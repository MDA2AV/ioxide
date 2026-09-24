/*
 * ioxide.ngtcp2 native shim: a thin, C#-friendly facade over ngtcp2 + its picotls crypto backend.
 *
 * Why it exists: ngtcp2's conn API takes large versioned structs (settings, transport params,
 * ~36-entry callback tables) and picotls' context is full of C bitfields - marshaling those from
 * C# would be fragile against upstream layout drift. The shim owns every struct layout in C
 * (compiled against the exact bundled headers) and exposes a small stable ABI:
 *
 *   engine  = iq_engine_new_mtls(cert, key, cidlen, alpn, ca, cbs)  one per factory; owns the
 *                                                        certificates every connection is served
 *   conn    = iq_accept(engine, addrs, first_pkt, ...)   validates + creates the server conn
 *             iq_conn_read(...)                          feed one UDP datagram
 *             iq_conn_write(...)                         produce one UDP datagram (loop until 0)
 *             iq_conn_open_uni / iq_conn_get_alpn        H3 plumbing (uni streams, negotiated proto)
 *             iq_conn_expiry / iq_conn_handle_expiry     ns-precision engine deadlines
 *             iq_conn_free / iq_engine_free
 *
 * Events flow back to C# through the iq_callbacks function pointers; every call into and out of
 * the shim happens on the owning reactor thread.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_picotls.h>

#include <picotls.h>
#include <picotls/openssl.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/pemerr.h>
#include <openssl/evp.h>
#include <openssl/err.h>

/* Exported-surface revision. Bump on any change to an exported signature or a struct crossing the
 * boundary; iq_abi() hands it to the managed side, which refuses to start on a mismatch.
 *   1 - iq_callbacks gained struct_size and on_path_change
 *   2 - iq_accept gained shard / shard_count for connection-id steering */
#define IQ_ABI 2

/* ---- callback table into C# ------------------------------------------------------------- */

typedef struct iq_callbacks {
    /* Bytes the CALLER compiled against. This struct is passed BY VALUE and is mirrored by hand in
     * several managed declarations, so a member added on one side and not the others makes the
     * callee read past what the caller wrote - silently, because nothing on either side can see the
     * mismatch. Checked at engine creation instead of being discovered as a garbage pointer. */
    size_t struct_size;

    void (*on_stream_data)(void *user, int64_t stream_id, const uint8_t *data, size_t datalen, int fin);
    void (*on_stream_close)(void *user, int64_t stream_id, uint64_t app_error_code);
    void (*on_handshake_completed)(void *user);
    void (*on_new_cid)(void *user, const uint8_t *cid, size_t cidlen);
    void (*on_retire_cid)(void *user, const uint8_t *cid, size_t cidlen);
    /* Peer aborted its sending side (RESET_STREAM) / asked us to stop ours (STOP_SENDING).
     * Either may be NULL (the test client ignores them). */
    void (*on_stream_reset)(void *user, int64_t stream_id, uint64_t app_error_code);
    void (*on_stream_stop_sending)(void *user, int64_t stream_id, uint64_t app_error_code);
    /* Bytes [offset, offset+datalen) of the stream are acknowledged: the app may free them.
     * ngtcp2 retains POINTERS into the app's buffers for retransmission until this fires - the
     * caller of iq_conn_write must keep stream bytes alive until then. May be NULL. */
    void (*on_acked_stream_data)(void *user, int64_t stream_id, uint64_t offset, uint64_t datalen);
    /* ngtcp2 moved this connection to a new peer address. What this does NOT mean is that the new
     * address was validated first: ngtcp2 adopts the current path on the first non-probing 1-RTT
     * packet from a new address (conn_recv_non_probing_pkt_on_new_path) and starts validating
     * afterwards. What makes that safe is not ordering but ngtcp2's own anti-amplification limit -
     * it will not send more than 3x what it has received on a path until that path validates - and
     * the fact that the packet had to decrypt under 1-RTT keys, which an off-path attacker cannot
     * forge. May be NULL. */
    void (*on_path_change)(void *user, const void *remote_sa, size_t remote_salen);
} iq_callbacks;

/* ---- objects ---------------------------------------------------------------------------- */

/* One SNI name and the context answering for it. Allocated individually rather than inside a
 * growable array: ptls_set_context hands the address to a live connection, so it has to stay put
 * however many more are registered afterwards. */
typedef struct iq_host {
    char                            *name;      /* lowercased, owned */
    ptls_context_t                   ptls_ctx;
    ptls_openssl_sign_certificate_t  sign_cert;
} iq_host;

/* Every certificate this engine serves, as one generation.
 *
 * Replaced whole rather than edited, because a certificate outlives the call that installs it:
 * ptls_new hands the default context to a connection and ptls_set_context hands a host's to one
 * mid-handshake, and picotls reads both for as long as that connection lives. Editing either in
 * place under a running server is a write beside those reads.
 *
 * So a renewal builds a new generation, publishes the pointer with one atomic store, and links the
 * old one here. Retired generations are NOT freed at that point - a handshake may be between
 * reading this and using what it found, and picotls does not refcount contexts - so they are kept
 * until the engine is freed. Renewal is an operational event a few times a year; the cost is a few
 * kilobytes per generation, and the alternative is a use-after-free. */
typedef struct iq_certs {
    ptls_context_t                  ptls_ctx;
    ptls_openssl_sign_certificate_t sign_cert;
    /* SNI. Empty unless hosts were registered, in which case on_client_hello picks the context
     * matching the name the client asked for and leaves the default in place otherwise. */
    iq_host                       **hosts;
    size_t                          host_count;
    size_t                          host_cap;
    struct iq_certs                *previous;   /* the generation this one replaced */
} iq_certs;

typedef struct iq_engine {
    /* The generation in force. Loaded once per connection and per client hello, never dereferenced
     * across a load, so a reader sees one whole generation or the other and never a mixture. */
    iq_certs                       *certs;
    ptls_on_client_hello_t          on_client_hello;
    /* mTLS. verify_cert does the actual path validation; peer_verify wraps it so the identity it
     * proved can be recorded on the connection - authenticating a client you cannot then name is
     * rarely what anyone wanted. Both are unused unless a client CA was configured. They live on
     * the ENGINE rather than the generation: every generation points at these, so renewing a
     * certificate cannot quietly change who is trusted to connect. */
    ptls_openssl_verify_certificate_t verify_cert;
    ptls_verify_certificate_t         peer_verify;
    /* Optional mTLS: a CertificateRequest always goes out once there are anchors, and this decides
     * what happens when the client answers with an empty certificate list. */
    ptls_openssl_override_verify_certificate_t allow_anonymous;
    int                             require_client_cert;
    /* Acceptable-issuer hint for the CertificateRequest, built once from the trust store. picotls
     * sends certificate_authorities ONLY from this field, and without it a client holding several
     * client certificates has nothing to choose by: it guesses, and a wrong guess is a refused
     * handshake. The TCP side has always sent the hint from both anchor sources, so a
     * configuration that worked there silently accepted a narrower set of clients here. Owned by
     * the engine and pointed at by every context, so it outlives any generation. */
    ptls_iovec_t                   *ca_names;
    size_t                          ca_name_count;
    /* Absolute bound on a handshake that never finishes, in nanoseconds; 0 leaves it unbounded.
     * ngtcp2's own default is UINT64_MAX and max_idle_timeout defaults to disabled, so before this
     * the only bound was the transport's sliding idle sweep - which any datagram refreshes, so a
     * peer trickling one packet under the interval held a half-open handshake, and its ngtcp2
     * conn, picotls session and CID routes, indefinitely. */
    ngtcp2_duration                 handshake_timeout;
    iq_callbacks                    cbs;
    size_t                          cidlen;
    uint8_t                         alpn[256];   /* allowlist, wire format (len-prefixed entries) */
    size_t                          alpn_len;    /* 0 = accept whatever the client offers */
} iq_engine;

typedef struct iq_conn {
    ngtcp2_conn                *conn;
    iq_callbacks                cbs;       /* copied from whichever engine created this conn */
    ngtcp2_crypto_conn_ref      conn_ref;
    ngtcp2_crypto_picotls_ctx   cptls;
    ngtcp2_sockaddr_union       local_addr;
    ngtcp2_sockaddr_union       remote_addr;
    /* The address last REPORTED to the caller. c->remote_addr is rewritten by ngtcp2 on every
     * write (the path argument to writev_stream is an OUT parameter), so it cannot double as the
     * record of what the caller believes - the two must be compared, not conflated. */
    ngtcp2_sockaddr_union       reported_addr;
    ngtcp2_socklen              reported_addrlen;
    ngtcp2_path                 path;
    ngtcp2_ccerr                last_error;
    void                       *user;
    /* Which reactor owns this connection, and how many there are. Stamped into every CID it
     * mints so the SO_REUSEPORT filter can route by connection id instead of by 4-tuple - the
     * difference between surviving a client's address change and dropping it. */
    uint32_t                    shard;
    uint32_t                    shard_count;
    ptls_raw_extension_t        exts[2];   /* [0] QUIC transport params (filled by ngtcp2), [1] terminator */
    char                        alpn[64];  /* client: the single protocol we offer */
    ptls_iovec_t                alpn_vec;  /* points into alpn[], handed to picotls for the CH */

    /* Streams whose receive window the APPLICATION paces: delivery skips the auto-credit below
     * and the app opens the window explicitly via iq_conn_consume as it consumes. Bounded set -
     * overflow degrades gracefully to auto-credit (no backpressure for the extra stream). */
    int64_t paced[32];
    int     paced_count;

    /* Set during the handshake when a client certificate was verified. The subject is captured
     * there because picotls does not retain the peer chain afterwards.
     *
     * peer_subject is for people to read. peer_cn is what an application compares, taken from the
     * DN structurally, because the rendered form escapes a literal '/' as "\/" - which still
     * contains '/', so an organisation named Acme\/CN=admin.internal renders as something a
     * Contains("/CN=admin.internal") check accepts while being a different principal entirely. */
    char peer_subject[1024];
    char peer_cn[256];
    int  peer_authenticated;
    /* Set instead of peer_authenticated when the subject was merely OBSERVED - the client-side
     * recorder, which does not verify anything. Kept apart deliberately: one flag meaning both
     * "we checked this" and "we saw this" would let an unverified name be read back as an
     * authenticated identity. */
    int  peer_recorded;
} iq_conn;

static int iq_paced_index(iq_conn *c, int64_t stream_id)
{
    for (int i = 0; i < c->paced_count; i++) {
        if (c->paced[i] == stream_id) {
            return i;
        }
    }
    return -1;
}

/* ---- helpers ---------------------------------------------------------------------------- */

static ngtcp2_conn *iq_get_conn(ngtcp2_crypto_conn_ref *ref)
{
    return ((iq_conn *)ref->user_data)->conn;
}

static void iq_rand(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx)
{
    (void)rand_ctx;
    ptls_openssl_random_bytes(dest, destlen);
}

/* Records the identity of a leaf certificate onto the connection.
 *
 * The buffer-taking form of X509_NAME_oneline is not used, because handed a buffer too small it
 * still reports success and writes as many whole attributes as fit: a subject longer than the
 * buffer comes back as a valid-looking prefix WITH THE CN MISSING, and two clients agreeing on
 * their leading attributes render identically - one string standing for two principals, which is
 * the one thing an identity must never do. Here the exact length is asked for first and a DN too
 * long for the field is recorded as no name at all rather than as a different one.
 *
 * The CN is read from the DN structurally for the escaping reason on peer_subject, and refused if
 * it is empty or contains a NUL - the latter being the old trick of a name that reads as
 * admin.example to whoever stops at the NUL and as admin.example\0.attacker.test to whoever does
 * not. */
static void iq_record_subject(iq_conn *c, X509 *leaf)
{
    X509_NAME *name = X509_get_subject_name(leaf);
    if (name == NULL) {
        return;
    }

    char *dn = X509_NAME_oneline(name, NULL, 0);
    if (dn != NULL) {
        if (strlen(dn) < sizeof(c->peer_subject)) {
            memcpy(c->peer_subject, dn, strlen(dn) + 1);
        } else {
            fprintf(stderr, "[ioxide.ngtcp2] peer subject is %zu bytes and does not fit; "
                            "reporting no name rather than a truncated one\n", strlen(dn));
        }
        OPENSSL_free(dn);
    }

    int index = -1, next = -1;
    while ((next = X509_NAME_get_index_by_NID(name, NID_commonName, next)) >= 0) {
        index = next;   /* the LAST CN, as every other X.509 consumer does */
    }
    if (index < 0) {
        return;
    }

    X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, index);
    ASN1_STRING *value = entry != NULL ? X509_NAME_ENTRY_get_data(entry) : NULL;
    if (value == NULL) {
        return;
    }

    /* Decoded rather than read raw: a CN is PrintableString, UTF8String or BMPString depending on
     * the issuer, and only this normalises all three. */
    unsigned char *cn = NULL;
    int cn_len = ASN1_STRING_to_UTF8(&cn, value);
    if (cn_len < 0) {
        return;
    }

    if (cn_len > 0 && (size_t)cn_len < sizeof(c->peer_cn) && memchr(cn, 0, (size_t)cn_len) == NULL) {
        memcpy(c->peer_cn, cn, (size_t)cn_len);
        c->peer_cn[cn_len] = '\0';
    }
    OPENSSL_free(cn);
}

/* Optional mTLS. The CertificateRequest is sent whenever trust anchors exist - otherwise a client
 * that HAS a certificate is never asked for one, and "optional" would quietly mean "never" - so
 * this is what separates optional from required: it forgives an empty certificate list and nothing
 * else. A client that offered a certificate which failed to validate is refused either way, which
 * is the distinction that matters; cert is non-NULL exactly when something was offered. */
static int iq_allow_anonymous(ptls_openssl_override_verify_certificate_t *self, ptls_t *tls, int ret,
                              int ossl_ret, X509 *cert, STACK_OF(X509) * chain)
{
    iq_engine *e = (iq_engine *)((char *)self - offsetof(iq_engine, allow_anonymous));

    (void)tls;
    (void)ossl_ret;
    (void)chain;

    if (ret == PTLS_ALERT_CERTIFICATE_REQUIRED && cert == NULL && !e->require_client_cert) {
        return 0;   /* no certificate offered, and none demanded: continue unauthenticated */
    }

    return ret;
}

/* Client certificate verification, wrapping picotls's OpenSSL verifier so the identity it just
 * proved can be recorded. picotls does not keep the peer chain after the handshake, so if the
 * subject is not taken here it is gone - and a server that authenticates a client without being
 * able to say WHICH client has a gate, not an identity. */
static int iq_verify_certificate(ptls_verify_certificate_t *self, ptls_t *tls, const char *server_name,
                                 int (**verify_sign)(void *verify_ctx, uint16_t algo, ptls_iovec_t data,
                                                     ptls_iovec_t signature),
                                 void **verify_data, ptls_iovec_t *certs, size_t num_certs)
{
    iq_engine *e = (iq_engine *)((char *)self - offsetof(iq_engine, peer_verify));

    int rv = e->verify_cert.super.cb(&e->verify_cert.super, tls, server_name, verify_sign, verify_data,
                                     certs, num_certs);
    if (rv != 0 || num_certs == 0) {
        return rv;   /* refused, or nothing offered - nothing to record either way */
    }

    /* ngtcp2 parks the connection ref here, and conn_ref lives inside iq_conn. */
    void **slot = ptls_get_data_ptr(tls);
    if (slot == NULL || *slot == NULL) {
        return rv;
    }
    iq_conn *c = (iq_conn *)((char *)*slot - offsetof(iq_conn, conn_ref));

    const uint8_t *der = certs[0].base;
    X509 *leaf = d2i_X509(NULL, &der, (long)certs[0].len);
    if (leaf != NULL) {
        iq_record_subject(c, leaf);
        c->peer_authenticated = 1;
        X509_free(leaf);
    }

    return rv;
}

/* ASCII lowercase, which is all a DNS name can contain that has a case at all. */
static char iq_lower(char c)
{
    return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
}

/* The certificates a context loaded from PEM. picotls allocates the list and each DER blob and
 * has no teardown of its own, so whoever built the context frees them. */
static void iq_free_certificates(ptls_context_t *ctx)
{
    for (size_t i = 0; i < ctx->certificates.count; i++) {
        free(ctx->certificates.list[i].base);
    }
    free(ctx->certificates.list);
    ctx->certificates.list  = NULL;
    ctx->certificates.count = 0;
}

/* Loads a certificate chain and its key into a context, and installs the signer. Returns 0, or -1
 * with the reason on stderr; on failure the context is left exactly as it was found.
 *
 * The pair is checked against each other. OpenSSL does it for the TCP side when the key is
 * installed, and picotls does not - so without this a certificate and a key that do not belong
 * together load happily here and fail every real handshake afterwards. That is exactly the state a
 * half-finished renewal leaves on disk, and catching it at load is what lets a failed renewal leave
 * the server serving what it had. */
static int iq_load_keypair(ptls_context_t *ctx, ptls_openssl_sign_certificate_t *sign,
                           const char *cert_pem_path, const char *key_pem_path, const char *who)
{
    if (ptls_load_certificates(ctx, (char *)cert_pem_path) != 0 || ctx->certificates.count == 0) {
        fprintf(stderr, "[ioxide.ngtcp2] %s: failed to load certificates from %s\n", who, cert_pem_path);
        goto fail;
    }

    BIO *bio = BIO_new_file(key_pem_path, "r");
    if (bio == NULL) {
        fprintf(stderr, "[ioxide.ngtcp2] %s: failed to open key %s\n", who, key_pem_path);
        goto fail;
    }

    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (pkey == NULL) {
        fprintf(stderr, "[ioxide.ngtcp2] %s: failed to parse key %s\n", who, key_pem_path);
        goto fail;
    }

    {
        /* Does this key belong to this certificate? The leaf is the one the key has to match. */
        const uint8_t *der = ctx->certificates.list[0].base;
        X509 *leaf = d2i_X509(NULL, &der, (long)ctx->certificates.list[0].len);
        int matched = leaf != NULL && X509_check_private_key(leaf, pkey) == 1;

        if (leaf != NULL) {
            X509_free(leaf);
        }

        if (!matched) {
            fprintf(stderr, "[ioxide.ngtcp2] %s: the key in %s does not match the certificate in %s\n",
                    who, key_pem_path, cert_pem_path);
            EVP_PKEY_free(pkey);
            goto fail;
        }
    }

    int rv = ptls_openssl_init_sign_certificate(sign, pkey);
    EVP_PKEY_free(pkey);

    if (rv != 0) {
        fprintf(stderr, "[ioxide.ngtcp2] %s: failed to init sign_certificate\n", who);
        goto fail;
    }

    ctx->sign_certificate = &sign->super;
    return 0;

fail:
    /* ptls_load_certificates mallocs the list before it so much as opens the file, and leaves
     * whatever it parsed behind on a partial failure - so there is something to free here even
     * when the load is what failed. */
    iq_free_certificates(ctx);
    return -1;
}

/* Releases what iq_load_keypair installed. Keyed off the signer, which is set last, so this is
 * safe on a context that never got that far. */
static void iq_dispose_keypair(ptls_context_t *ctx, ptls_openssl_sign_certificate_t *sign)
{
    if (ctx->sign_certificate != NULL) {
        ptls_openssl_dispose_sign_certificate(sign);
        ctx->sign_certificate = NULL;
    }

    iq_free_certificates(ctx);
}

/* One SNI host and everything it owns. The half-built case is the same shape as the fully-built
 * one, which is why the failure path and the teardown path are the same function. */
static void iq_host_free(iq_host *h)
{
    if (h == NULL) {
        return;
    }

    iq_dispose_keypair(&h->ptls_ctx, &h->sign_cert);
    free(h->name);
    free(h);
}

/* The context registered for this name, or NULL. Compared case-insensitively: SNI carries a DNS
 * name, and a client asking for EXAMPLE.COM means the host that answers for example.com. */
static ptls_context_t *iq_context_for(iq_certs *e, ptls_iovec_t name)
{
    if (name.base == NULL || name.len == 0) {
        return NULL;
    }

    for (size_t i = 0; i < e->host_count; i++) {
        const char *candidate = e->hosts[i]->name;

        if (strlen(candidate) != name.len) {
            continue;
        }

        size_t j = 0;
        while (j < name.len && candidate[j] == iq_lower((char)name.base[j])) {
            j++;
        }

        if (j == name.len) {
            return &e->hosts[i]->ptls_ctx;
        }
    }

    return NULL;
}

/* How many host_name entries the ClientHello's server_name extension carries, or -1 when the
 * message cannot be walked. 0 means the extension was absent, or held no host_name.
 *
 * Exists because the two stacks disagree about the same bytes. OpenSSL parses the ServerNameList
 * exact-fit and refuses anything that is not one host_name; picotls loops the list and lets the
 * LAST host_name win. So [allowed, evil] is a dead connection over TCP and serves evil's
 * certificate over QUIC - and anything in front that reads the first name, an SNI router or an
 * ACL, would have been looking at the other one.
 *
 * Only ever reports a violation it positively identified: anything it cannot walk is -1 and the
 * caller changes nothing. A mistake in here has to degrade to "no extra check", never to a refused
 * handshake. */
static int iq_count_host_names(const uint8_t *base, size_t len)
{
    const uint8_t *p = base, *end = base + len;

    /* Handshake header, then the ClientHello body: version and random are fixed width, the three
     * that follow are length-prefixed and only skipped over. */
    if ((size_t)(end - p) < 4u + 2u + 32u) {
        return -1;
    }
    p += 4 + 2 + 32;

    for (int i = 0; i < 3; i++) {
        /* legacy_session_id and legacy_compression_methods are 1-byte prefixed, cipher_suites 2. */
        size_t width = (i == 1) ? 2 : 1;
        size_t n;

        if ((size_t)(end - p) < width) {
            return -1;
        }
        n = (width == 1) ? p[0] : ((size_t)p[0] << 8 | p[1]);
        p += width;

        if ((size_t)(end - p) < n) {
            return -1;
        }
        p += n;
    }

    if ((size_t)(end - p) < 2u) {
        return 0;   /* no extensions block at all - no SNI, and nothing malformed about that */
    }

    size_t ext_total = (size_t)p[0] << 8 | p[1];
    p += 2;
    if ((size_t)(end - p) < ext_total) {
        return -1;
    }
    end = p + ext_total;   /* trailing bytes past the extensions are not ours to judge */

    while (p < end) {
        if ((size_t)(end - p) < 4u) {
            return -1;
        }
        unsigned type = (unsigned)p[0] << 8 | p[1];
        size_t ext_len = (size_t)p[2] << 8 | p[3];
        p += 4;

        if ((size_t)(end - p) < ext_len) {
            return -1;
        }

        if (type != 0) {
            p += ext_len;
            continue;
        }

        const uint8_t *q = p, *qend = p + ext_len;

        if ((size_t)(qend - q) < 2u) {
            return -1;
        }
        size_t list_len = (size_t)q[0] << 8 | q[1];
        q += 2;
        if ((size_t)(qend - q) != list_len) {
            return -1;   /* the list must fill the extension exactly */
        }

        int hosts = 0;
        while (q < qend) {
            if ((size_t)(qend - q) < 3u) {
                return -1;
            }
            unsigned name_type = q[0];
            size_t name_len = (size_t)q[1] << 8 | q[2];
            q += 3;

            if ((size_t)(qend - q) < name_len) {
                return -1;
            }
            if (name_type == 0) {
                hosts++;
            }
            q += name_len;
        }

        return hosts;
    }

    return 0;
}

static int iq_on_client_hello(ptls_on_client_hello_t *self, ptls_t *tls,
                              ptls_on_client_hello_parameters_t *params)
{
    iq_engine *e = (iq_engine *)((char *)self - offsetof(iq_engine, on_client_hello));

    /* RFC 6066 3.1: a ServerNameList carries at most one name of a given type. picotls does not
     * enforce it and would answer for the last one; refused here so this server cannot be talked
     * into serving a name that a device in front read as a different one. Same alert OpenSSL
     * sends for the same bytes, so both of this project's stacks now fail it identically. */
    if (iq_count_host_names(params->raw_message.base, params->raw_message.len) > 1) {
        return PTLS_ALERT_DECODE_ERROR;
    }

    /* Before ALPN, because a swapped context brings its own certificate and this is the only point
     * at which the choice is still open. An unknown name keeps the default: refusing here would
     * report "this server does not hold that name" as a dead connection, and would break every
     * client reaching the server by address. */
    {
        /* One load, and everything below reads through it: a renewal landing between here and the
         * swap would otherwise let a connection take its name from one generation and its
         * certificate from another. */
        iq_certs *certs = __atomic_load_n(&e->certs, __ATOMIC_ACQUIRE);

        if (certs->host_count > 0) {
            ptls_context_t *host = iq_context_for(certs, params->server_name);

            if (host != NULL) {
                ptls_set_context(tls, host);
            }
        }
    }

    if (params->negotiated_protocols.count == 0) {
        return e->alpn_len == 0 ? 0 : PTLS_ALERT_NO_APPLICATION_PROTOCOL;
    }

    if (e->alpn_len == 0) {
        return ptls_set_negotiated_protocol(
            tls,
            (const char *)params->negotiated_protocols.list[0].base,
            params->negotiated_protocols.list[0].len);
    }

    /* The SERVER's order decides, which is why this walks the allowlist on the outside: the first
     * protocol this engine lists that the client also offered is the one negotiated. The TCP side
     * has always worked that way and both are documented as preference-ordered; walking the
     * client's offers first would quietly let the client choose instead. */
    for (size_t off = 0; off < e->alpn_len;) {
        size_t len = e->alpn[off];

        for (size_t i = 0; i < params->negotiated_protocols.count; i++) {
            ptls_iovec_t offer = params->negotiated_protocols.list[i];

            if (len == offer.len && memcmp(e->alpn + off + 1, offer.base, len) == 0) {
                return ptls_set_negotiated_protocol(tls, (const char *)offer.base, offer.len);
            }
        }

        off += 1 + len;
    }
    return PTLS_ALERT_NO_APPLICATION_PROTOCOL;
}

/* The recorded subject, when the flag the caller is entitled to read is set. The flag is the whole
 * argument for the parameter: the two getters below differ in nothing else, and what separates
 * them is which claim the name carries rather than how it is copied. */
static size_t iq_copy_subject(iq_conn *c, char *out, size_t outlen, int allowed)
{
    if (c == NULL || out == NULL || outlen == 0 || !allowed) {
        return 0;
    }
    size_t n = strlen(c->peer_subject);
    if (n >= outlen) {
        /* No name beats a different one - the same rule iq_conn_peer_cn states below, and the rule
         * iq_record_subject already applies when the DN will not fit peer_subject at all. Handing
         * back a prefix is the one outcome an identity must never produce: a truncated DN is
         * plausible, comparable, and can equal a DIFFERENT principal's prefix. */
        return 0;
    }
    memcpy(out, c->peer_subject, n);
    out[n] = '\0';
    return n;
}

/* The verified client identity, or an empty string when the peer offered none. Returns the length
 * written, or 0. */
size_t iq_conn_peer_subject(iq_conn *c, char *out, size_t outlen)
{
    return iq_copy_subject(c, out, outlen, c != NULL && c->peer_authenticated);
}

/* The subject of the certificate the SERVER served, when the connection was asked to record one.
 * Deliberately a different entry point from iq_conn_peer_subject: this name was observed, not
 * authenticated, and the two must not be reachable through one call. Returns the length, or 0. */
size_t iq_conn_server_subject(iq_conn *c, char *out, size_t outlen)
{
    return iq_copy_subject(c, out, outlen, c != NULL && c->peer_recorded);
}

/* The common name of the VERIFIED client certificate - the value to authorize on, since it needs
 * no un-escaping and no substring search. Returns the length written, or 0. */
size_t iq_conn_peer_cn(iq_conn *c, char *out, size_t outlen)
{
    if (c == NULL || out == NULL || outlen == 0 || !c->peer_authenticated) {
        return 0;
    }
    size_t n = strlen(c->peer_cn);
    if (n >= outlen) {
        return 0;   /* the same rule as the subject: no name beats a different one */
    }
    memcpy(out, c->peer_cn, n);
    out[n] = '\0';
    return n;
}

/* ---- ngtcp2 callbacks ------------------------------------------------------------------- */

static int iq_cb_handshake_completed(ngtcp2_conn *conn, void *user_data)
{
    (void)conn;
    iq_conn *c = user_data;
    if (c->cbs.on_handshake_completed) c->cbs.on_handshake_completed(c->user);
    return 0;
}

static int iq_cb_recv_stream_data(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                                  uint64_t offset, const uint8_t *data, size_t datalen,
                                  void *user_data, void *stream_user_data)
{
    (void)offset; (void)stream_user_data;
    iq_conn *c = user_data;

    /* Consume connection + stream flow-control credit for what we just took - unless the
     * app paces this stream, in which case it credits via iq_conn_consume as it reads. */
    if (iq_paced_index(c, stream_id) < 0) {
        ngtcp2_conn_extend_max_offset(conn, datalen);
        ngtcp2_conn_extend_max_stream_offset(conn, stream_id, datalen);
    }

    if (c->cbs.on_stream_data) {
        c->cbs.on_stream_data(c->user, stream_id, data, datalen,
                              (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0);
    }
    return 0;
}

static int iq_cb_stream_close(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                              uint64_t app_error_code, void *user_data, void *stream_user_data)
{
    (void)stream_user_data;
    iq_conn *c = user_data;
    if (!(flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET)) {
        app_error_code = 0;
    }

    /* Replenish the peer's stream allowance: initial_max_streams_* is a WINDOW, not a lifetime
     * cap - without this a connection stalls for good after its first 100 requests. */
    if ((stream_id & 0x3) == 0x0) {
        ngtcp2_conn_extend_max_streams_bidi(conn, 1);
    } else if ((stream_id & 0x3) == 0x2) {
        ngtcp2_conn_extend_max_streams_uni(conn, 1);
    }

    int pi = iq_paced_index(c, stream_id);
    if (pi >= 0) {
        c->paced[pi] = c->paced[--c->paced_count];
    }

    if (c->cbs.on_stream_close) c->cbs.on_stream_close(c->user, stream_id, app_error_code);
    return 0;
}

static int iq_cb_stream_reset(ngtcp2_conn *conn, int64_t stream_id, uint64_t final_size,
                              uint64_t app_error_code, void *user_data, void *stream_user_data)
{
    (void)conn; (void)final_size; (void)stream_user_data;
    iq_conn *c = user_data;
    if (c->cbs.on_stream_reset) {
        c->cbs.on_stream_reset(c->user, stream_id, app_error_code);
    }
    return 0;
}

static int iq_cb_stream_stop_sending(ngtcp2_conn *conn, int64_t stream_id, uint64_t app_error_code,
                                     void *user_data, void *stream_user_data)
{
    (void)conn; (void)stream_user_data;
    iq_conn *c = user_data;
    if (c->cbs.on_stream_stop_sending) {
        c->cbs.on_stream_stop_sending(c->user, stream_id, app_error_code);
    }
    return 0;
}

static int iq_cb_acked_stream_data_offset(ngtcp2_conn *conn, int64_t stream_id, uint64_t offset,
                                          uint64_t datalen, void *user_data, void *stream_user_data)
{
    (void)conn; (void)stream_user_data;
    iq_conn *c = user_data;
    if (c->cbs.on_acked_stream_data) {
        c->cbs.on_acked_stream_data(c->user, stream_id, offset, datalen);
    }
    return 0;
}

/* Stamp the owning reactor into the first CID byte. The kernel filter routes on cid[0] %
 * shard_count, so the byte is picked to leave exactly `shard` as the remainder while staying
 * otherwise random - the CID keeps its unpredictability, it just stops being uniform.
 *
 * shard_count <= 1 is a single-reactor server: nothing to steer, so the CID is left fully random.
 * A count above 256 cannot be encoded in one byte, and the caller disables steering for it. */
static void iq_stamp_shard(uint8_t *cid, uint32_t shard, uint32_t shard_count)
{
    if (shard_count <= 1 || shard_count > 256 || shard >= shard_count) {
        return;
    }

    unsigned v = (unsigned)cid[0] - ((unsigned)cid[0] % shard_count) + shard;
    if (v > 255) {
        v -= shard_count;   /* still congruent to shard mod shard_count, and back inside a byte */
    }
    cid[0] = (uint8_t)v;
}

static int iq_cb_get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token,
                                       size_t cidlen, void *user_data)
{
    (void)conn;
    iq_conn *c = user_data;
    ptls_openssl_random_bytes(cid->data, cidlen);
    iq_stamp_shard(cid->data, c->shard, c->shard_count);
    cid->datalen = cidlen;
    ptls_openssl_random_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);
    if (c->cbs.on_new_cid) c->cbs.on_new_cid(c->user, cid->data, cid->datalen);
    return 0;
}

static int iq_cb_remove_connection_id(ngtcp2_conn *conn, const ngtcp2_cid *cid, void *user_data)
{
    (void)conn;
    iq_conn *c = user_data;
    if (c->cbs.on_retire_cid) c->cbs.on_retire_cid(c->user, cid->data, cid->datalen);
    return 0;
}

/* CID generator that doesn't report to a reactor (the test client has no engine->cbs). */
static int iq_cb_get_new_connection_id_noreport(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token,
                                                size_t cidlen, void *user_data)
{
    (void)conn; (void)user_data;
    ptls_openssl_random_bytes(cid->data, cidlen);
    cid->datalen = cidlen;
    ptls_openssl_random_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);
    return 0;
}

/* ---- engine ----------------------------------------------------------------------------- */

/* The subject DNs of every anchor in the store, DER-encoded, for the CertificateRequest's
 * certificate_authorities extension. Best effort by design: the hint helps a client PICK among the
 * certificates it holds, and a client with one certificate does not need it - so a failure here
 * costs selection help, never verification, and must not fail the engine. */
static void iq_build_ca_names(iq_engine *e, X509_STORE *store)
{
    STACK_OF(X509_OBJECT) *objects = X509_STORE_get0_objects(store);
    int count = objects != NULL ? sk_X509_OBJECT_num(objects) : 0;
    if (count <= 0) {
        return;
    }

    ptls_iovec_t *list = calloc((size_t)count, sizeof(*list));
    if (list == NULL) {
        return;
    }

    size_t filled = 0;
    for (int i = 0; i < count; i++) {
        X509 *cert = X509_OBJECT_get0_X509(sk_X509_OBJECT_value(objects, i));
        if (cert == NULL) {
            continue;   /* a CRL entry, not a certificate */
        }

        unsigned char *der = NULL;
        int len = i2d_X509_NAME(X509_get_subject_name(cert), &der);
        if (len <= 0 || der == NULL) {
            ERR_clear_error();
            continue;
        }

        list[filled].base = der;   /* OPENSSL_malloc'd; released in iq_engine_free */
        list[filled].len  = (size_t)len;
        filled++;
    }

    if (filled == 0) {
        free(list);
        return;
    }

    e->ca_names      = list;
    e->ca_name_count = filled;
}

iq_engine *iq_engine_new_mtls(const char *cert_pem_path, const char *key_pem_path,
                              size_t cidlen, const uint8_t *alpn, size_t alpn_len,
                              const char *client_ca_pem_path, const char *client_ca_pem,
                              int require_client_cert, iq_callbacks cbs);


/* Registers a certificate for one SNI name, to be served instead of the default when a client asks
 * for that host. Returns 0, or -1 with the reason on stderr.
 *
 * Call before the engine accepts anything: the contexts are read from the handshake with no lock,
 * on whichever thread the connection landed on. Client verification and the require flag are copied
 * from the default context, so swapping to a named certificate cannot quietly drop mutual TLS. */
static int iq_certs_add_host(iq_certs *certs, const char *host, const char *cert_pem_path,
                             const char *key_pem_path)
{
    if (certs == NULL || host == NULL || *host == '\0' || cert_pem_path == NULL || key_pem_path == NULL) {
        return -1;
    }

    /* Refused rather than shadowed: with a linear scan the first registration would win, so a
     * second certificate for the same name would sit in the table and never be served - and an
     * operator rotating a certificate by re-adding it would see the old one answer. */
    {
        ptls_iovec_t asked = {(uint8_t *)(uintptr_t)host, strlen(host)};

        if (iq_context_for(certs, asked) != NULL) {
            fprintf(stderr, "[ioxide.ngtcp2] host '%s' is already registered\n", host);
            return -1;
        }
    }

    if (certs->host_count == certs->host_cap) {
        size_t cap = certs->host_cap == 0 ? 4 : certs->host_cap * 2;
        iq_host **grown = realloc(certs->hosts, cap * sizeof(*grown));
        if (grown == NULL) {
            return -1;
        }
        certs->hosts   = grown;
        certs->host_cap = cap;
    }

    iq_host *h = calloc(1, sizeof(*h));
    if (h == NULL) {
        return -1;
    }

    size_t len = strlen(host);
    h->name = malloc(len + 1);
    if (h->name == NULL) {
        free(h);
        return -1;
    }
    for (size_t i = 0; i < len; i++) {
        h->name[i] = iq_lower(host[i]);
    }
    h->name[len] = '\0';

    h->ptls_ctx.random_bytes  = ptls_openssl_random_bytes;
    h->ptls_ctx.get_time      = &ptls_get_time;
    h->ptls_ctx.key_exchanges = ptls_openssl_key_exchanges_all;
    h->ptls_ctx.cipher_suites = ptls_openssl_cipher_suites;

    if (iq_load_keypair(&h->ptls_ctx, &h->sign_cert, cert_pem_path, key_pem_path, host) != 0) {
        goto fail;
    }

    if (ngtcp2_crypto_picotls_configure_server_context(&h->ptls_ctx) != 0) {
        fprintf(stderr, "[ioxide.ngtcp2] host '%s': configure_server_context failed\n", host);
        goto fail;
    }

    /* After configure_server_context, matching how the default context is built - and carried over
     * rather than re-derived, so a named host validates clients against the same anchors.
     *
     * These two are what picotls reads AFTER the swap to decide mutual TLS: whether to ask for a
     * certificate at all, and what to check the answer against. A host context that missed them
     * would serve without the mTLS the engine was configured for, so they are not optional.
     *
     * The copy is a SNAPSHOT. It is sound only because client verification is fixed in the
     * constructor - anything that configures anchors later would leave hosts registered before it
     * on the old verifier, which is the bypass this comment exists to prevent. */
    h->ptls_ctx.verify_certificate            = certs->ptls_ctx.verify_certificate;
    h->ptls_ctx.require_client_authentication = certs->ptls_ctx.require_client_authentication;
    h->ptls_ctx.client_ca_names               = certs->ptls_ctx.client_ca_names;

    /* Not read again for this handshake - picotls consults it only on a first flight, and the swap
     * happens inside that one call. Carried anyway so a host context is a faithful stand-in for the
     * default rather than one that merely happens not to be asked. */
    h->ptls_ctx.on_client_hello = certs->ptls_ctx.on_client_hello;

    certs->hosts[certs->host_count++] = h;
    return 0;

fail:
    iq_host_free(h);
    return -1;
}

/* Registers a certificate for one SNI name on the generation in force. Returns 0, or -1 with the
 * reason on stderr.
 *
 * For building the engine, before it serves anything: it edits the current generation rather than
 * publishing a new one. Renewing under load is iq_engine_replace_certificates. */
int iq_engine_add_host(iq_engine *e, const char *host, const char *cert_pem_path,
                       const char *key_pem_path)
{
    if (e == NULL) {
        return -1;
    }

    return iq_certs_add_host(e->certs, host, cert_pem_path, key_pem_path);
}

/* Frees one generation: every host it owns, and its own certificate material. */
static void iq_certs_free(iq_certs *certs)
{
    if (certs == NULL) {
        return;
    }

    iq_dispose_keypair(&certs->ptls_ctx, &certs->sign_cert);

    for (size_t i = 0; i < certs->host_count; i++) {
        iq_host_free(certs->hosts[i]);
    }

    free(certs->hosts);
    free(certs);
}

/* Builds one generation: the default certificate, configured the way the engine's first one was.
 * Hosts are added afterwards by the caller. Returns NULL with the reason on stderr. */
static iq_certs *iq_certs_new(iq_engine *e, const char *cert_pem_path, const char *key_pem_path)
{
    iq_certs *certs = calloc(1, sizeof(*certs));
    if (certs == NULL) {
        return NULL;
    }

    certs->ptls_ctx.random_bytes  = ptls_openssl_random_bytes;
    certs->ptls_ctx.get_time      = &ptls_get_time;
    /* _all rather than the default list, which is secp256r1 and nothing else. Every current client
     * puts x25519 first, so with the default the server matches none of the key shares offered and
     * answers HelloRetryRequest - a whole extra round trip on every single handshake, and a failure
     * outright against a client that offers x25519 alone. */
    certs->ptls_ctx.key_exchanges = ptls_openssl_key_exchanges_all;
    certs->ptls_ctx.cipher_suites = ptls_openssl_cipher_suites;
    certs->ptls_ctx.on_client_hello = &e->on_client_hello;

    if (iq_load_keypair(&certs->ptls_ctx, &certs->sign_cert, cert_pem_path, key_pem_path,
                        "default certificate") != 0) {
        goto fail;
    }

    if (ngtcp2_crypto_picotls_configure_server_context(&certs->ptls_ctx) != 0) {
        fprintf(stderr, "[ioxide.ngtcp2] configure_server_context failed\n");
        goto fail;
    }

    /* Who is trusted to connect belongs to the engine, not to the certificate being installed -
     * so a renewal carries it over rather than restating it, and cannot drop mutual TLS. */
    certs->ptls_ctx.verify_certificate            = e->peer_verify.cb != NULL ? &e->peer_verify : NULL;
    certs->ptls_ctx.require_client_authentication = e->certs != NULL
        ? e->certs->ptls_ctx.require_client_authentication
        : 0;
    certs->ptls_ctx.client_ca_names.list          = e->ca_names;
    certs->ptls_ctx.client_ca_names.count         = e->ca_name_count;

    return certs;

fail:
    iq_dispose_keypair(&certs->ptls_ctx, &certs->sign_cert);
    free(certs);
    return NULL;
}

/* Replaces every certificate this engine serves, on a running server.
 *
 * The default, then one host per entry of the three parallel arrays. Everything is built before
 * anything is published, so a bad path leaves the engine serving what it already had - a failed
 * renewal is a server that kept working. Returns 0, or -1 with the reason on stderr.
 *
 * Connections already established keep the certificate they were given; the next handshake gets the
 * new one. What is NOT replaced: the client trust anchors and whether a client certificate is
 * required, which are the engine's and stay as they were. */
int iq_engine_replace_certificates(iq_engine *e, const char *cert_pem_path, const char *key_pem_path,
                                   const char *const *hosts, const char *const *host_certs,
                                   const char *const *host_keys, size_t host_count)
{
    if (e == NULL || cert_pem_path == NULL || key_pem_path == NULL) {
        return -1;
    }

    iq_certs *next = iq_certs_new(e, cert_pem_path, key_pem_path);
    if (next == NULL) {
        return -1;
    }

    for (size_t i = 0; i < host_count; i++) {
        if (iq_certs_add_host(next, hosts[i], host_certs[i], host_keys[i]) != 0) {
            iq_certs_free(next);
            return -1;
        }
    }

    /* Published with one store, after everything above succeeded. A reader loading this pointer
     * either sees the whole new generation or the whole old one. */
    iq_certs *previous = e->certs;
    next->previous = previous;
    __atomic_store_n(&e->certs, next, __ATOMIC_RELEASE);

    return 0;
}

/* Trust anchors from PEM text rather than a file, for a host that carries its CA bundle as data.
 * Returns how many certificates were added, 0 if the text held none usable.
 *
 * X509_STORE_load_locations cannot read memory, so the blocks are parsed here and added one at a
 * time - the same anchors, reached the other way. A duplicate is not an error: add_cert refuses it
 * and the store already holds one, so it counts. */
static int iq_store_add_pem(X509_STORE *store, const char *pem)
{
    BIO *bio = BIO_new_mem_buf(pem, -1);
    if (bio == NULL) {
        return 0;
    }

    int added = 0;
    X509 *cert;

    for (;;) {
        ERR_clear_error();
        cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (cert == NULL) {
            /* Exhausted, or stopped on a malformed block - and only the first is an end of bundle.
             * Reading both as "done" trusted the anchors BEFORE the bad block and silently dropped
             * everything after it, so a client issued by a later anchor was refused with nothing
             * said. The TCP side tells the two apart (TlsService.AddTrustAnchorsPem); this did not,
             * and X509_STORE_load_locations - the path route right above the caller - refuses such
             * a bundle outright. */
            if (ERR_GET_REASON(ERR_peek_last_error()) != PEM_R_NO_START_LINE) {
                ERR_clear_error();
                BIO_free(bio);
                return -1;
            }
            break;
        }
        if (X509_STORE_add_cert(store, cert) == 1) {
            added++;
        } else if (ERR_GET_REASON(ERR_peek_last_error()) == X509_R_CERT_ALREADY_IN_HASH_TABLE) {
            added++;
        }
        X509_free(cert);
    }

    /* The loop ends by design on PEM_R_NO_START_LINE once the last block is consumed, and any
     * duplicate above left its own. Neither is a failure, so the queue must not outlive this. */
    ERR_clear_error();

    BIO_free(bio);
    return added;
}

/* With mTLS: the client certificates are validated against client_ca_pem_path, a bundle on disk, or
 * client_ca_pem, the same bundle as PEM text - at most one, and require_client_cert decides whether
 * a client that offers none is refused outright or merely arrives unauthenticated. Both NULL leaves
 * mTLS off and the handshake is byte-for-byte what it was. */
iq_engine *iq_engine_new_mtls(const char *cert_pem_path, const char *key_pem_path,
                              size_t cidlen, const uint8_t *alpn, size_t alpn_len,
                              const char *client_ca_pem_path, const char *client_ca_pem,
                              int require_client_cert, iq_callbacks cbs)
{
    if (cbs.struct_size != sizeof(iq_callbacks)) {
        fprintf(stderr, "[ioxide.ngtcp2] callback table is %zu bytes, this build expects %zu - "
                        "a managed mirror of iq_callbacks is out of date\n",
                cbs.struct_size, sizeof(iq_callbacks));
        return NULL;
    }

    /* Bounded here and not merely where the CID is minted: ngtcp2_cid.data is a fixed
     * NGTCP2_MAX_CIDLEN array, so accepting a longer length would store an overflow in the engine
     * and hand every accept a stack smash. A zero length leaves the caller nothing to route on. */
    if (cidlen < 1 || cidlen > NGTCP2_MAX_CIDLEN) {
        fprintf(stderr, "[ioxide.ngtcp2] connection ID length %zu is out of range (1..%d)\n",
                cidlen, NGTCP2_MAX_CIDLEN);
        return NULL;
    }

    iq_engine *e = calloc(1, sizeof(*e));
    if (e == NULL) {
        return NULL;
    }
    e->cbs    = cbs;
    e->cidlen = cidlen;

    if (alpn != NULL && alpn_len > 0) {
        if (alpn_len > sizeof(e->alpn)) {
            free(e);
            return NULL;
        }
        memcpy(e->alpn, alpn, alpn_len);
        e->alpn_len = alpn_len;
    }

    e->on_client_hello.cb = iq_on_client_hello;

    /* Who is trusted to connect is settled BEFORE the first certificate is built, because it
       belongs to the engine rather than to any one generation - every generation, including the
       ones a later renewal installs, points at the verifier set up here. */
    if (client_ca_pem_path != NULL || client_ca_pem != NULL) {
        X509_STORE *store = X509_STORE_new();
        if (store == NULL) {
            fprintf(stderr, "[ioxide.ngtcp2] failed to allocate the client CA store\n");
            goto fail;
        }
        if (client_ca_pem_path != NULL) {
            if (X509_STORE_load_locations(store, client_ca_pem_path, NULL) != 1) {
                fprintf(stderr, "[ioxide.ngtcp2] failed to load client CA bundle from %s\n", client_ca_pem_path);
                X509_STORE_free(store);
                goto fail;
            }
        } else {
            int added = iq_store_add_pem(store, client_ca_pem);
            if (added <= 0) {
                fprintf(stderr, added < 0
                    ? "[ioxide.ngtcp2] the client CA PEM text is malformed; the rest of the bundle "
                      "would have been ignored\n"
                    : "[ioxide.ngtcp2] the client CA PEM text held no usable certificate\n");
                X509_STORE_free(store);
                goto fail;
            }
        }
        /* Before the store changes owner: the hint is read out of it, not kept from it. */
        iq_build_ca_names(e, store);

        /* The store is owned by the verifier from here; freeing it separately would double-free. */
        if (ptls_openssl_init_verify_certificate(&e->verify_cert, store) != 0) {
            fprintf(stderr, "[ioxide.ngtcp2] failed to init client certificate verification\n");
            X509_STORE_free(store);
            goto fail;
        }
        X509_STORE_free(store);   /* init took its own reference */

        e->peer_verify.cb         = iq_verify_certificate;
        e->peer_verify.algos      = e->verify_cert.super.algos;

        e->allow_anonymous.cb            = iq_allow_anonymous;
        e->verify_cert.override_callback = &e->allow_anonymous;
    }

    /* The first generation. Every later one is built by the same function, so a renewed certificate
       is configured exactly the way this one was. */
    e->certs = iq_certs_new(e, cert_pem_path, key_pem_path);
    if (e->certs == NULL) {
        goto fail;
    }

    /* Ask every client for a certificate once there are anchors to judge one by. The flag is what
     * makes picotls send the CertificateRequest at all, so leaving it off for optional mTLS would
     * mean no client is ever asked and no client is ever identified - "optional" collapsing into
     * "never". Whether an empty answer is fatal is iq_allow_anonymous's decision instead.
     *
     * Only when a verifier exists, and that condition is the point: requiring a certificate with
     * nothing to validate it against asks every client for one, refuses the ones that have none,
     * and then accepts whatever the rest send - a port that looks authenticated and is not. */
    e->require_client_cert = require_client_cert != 0;
    if (e->peer_verify.cb != NULL) {
        e->certs->ptls_ctx.require_client_authentication = 1;
    }

    return e;

fail:
    /* The verifier is built before the first certificate now, so this path can be reached with it
     * holding a reference to the trust store - which nothing else would ever release. */
    if (e->peer_verify.cb != NULL) {
        ptls_openssl_dispose_verify_certificate(&e->verify_cert);
    }
    free(e);
    return NULL;
}

/* Nanoseconds; 0 disables. Separate from iq_engine_new_mtls on purpose: adding a parameter there
 * would change a signature the managed side already binds, and a mismatched .so would then be a
 * silent argument shift rather than a missing export. */
void iq_engine_set_handshake_timeout(iq_engine *e, uint64_t ns)
{
    if (e != NULL) {
        e->handshake_timeout = (ngtcp2_duration)ns;
    }
}

void iq_engine_free(iq_engine *e)
{
    if (e == NULL) {
        return;
    }
    /* Every generation, including the ones retired by a renewal - which is where they are freed,
       since a live connection could still have been reading one when it was replaced. */
    iq_certs *certs = e->certs;

    while (certs != NULL) {
        iq_certs *previous = certs->previous;
        iq_certs_free(certs);
        certs = previous;
    }

    /* The trust store the verifier took a reference to. */
    if (e->peer_verify.cb != NULL) {
        ptls_openssl_dispose_verify_certificate(&e->verify_cert);
    }

    /* Each DN was allocated by i2d_X509_NAME, the array by us. */
    for (size_t i = 0; i < e->ca_name_count; i++) {
        OPENSSL_free((void *)e->ca_names[i].base);
    }
    free(e->ca_names);

    free(e);
}

const char *iq_version(void)
{
    return ngtcp2_version(0)->version_str;
}

/* Bumped whenever an exported signature or struct layout changes. The managed binding checks this
 * when it builds an engine, so a stale libioxide_ngtcp2.so left in a build output fails at startup
 * with a clear message rather than silently passing garbage across the boundary. */
uint32_t iq_abi(void)
{
    return IQ_ABI;
}

/* ---- connection ------------------------------------------------------------------------- */

/* Validate the first datagram of a new connection and build the server conn for it.
 * scid_out receives the connection ID this server minted (engine->cidlen bytes) so the caller
 * can register the route. shard / shard_count identify the reactor calling this, and are stamped
 * into that CID and every later one this connection issues, so the kernel's SO_REUSEPORT filter
 * routes the connection's datagrams back here even after the client changes address. Pass
 * shard 0, count 1 for a single-reactor server: the CID is then left fully random.
 * Returns NULL if the packet is not an acceptable Initial. */
iq_conn *iq_accept(iq_engine *e,
                   const void *local_sa, size_t local_salen,
                   const void *remote_sa, size_t remote_salen,
                   const uint8_t *pkt, size_t pktlen,
                   uint64_t ts, void *user,
                   uint32_t shard, uint32_t shard_count, uint8_t *scid_out)
{
    ngtcp2_pkt_hd hd;
    if (ngtcp2_accept(&hd, pkt, pktlen) != 0) {
        return NULL;
    }

    iq_conn *c = calloc(1, sizeof(*c));
    if (c == NULL) {
        return NULL;
    }
    c->cbs = e->cbs;
    c->user   = user;
    /* Set before ngtcp2_conn_server_new, because the CID generator callback can fire during it. */
    c->shard       = shard;
    c->shard_count = shard_count;

    /* Clamped at the entry point, like every other caller-supplied length here. The destinations
     * are ngtcp2_sockaddr_union - 28 bytes, sa/in/in6 only, NOT sockaddr_storage - and the field
     * immediately after them is the ngtcp2_path whose members ngtcp2 dereferences. The kernel
     * bounds an AF_INET/AF_INET6 recvmsg to 28, so this is not reachable today; the managed side
     * hands over a 128-byte name buffer, which is the gap that makes it worth stating. */
    if (local_salen > sizeof(c->local_addr) || remote_salen > sizeof(c->remote_addr)) {
        fprintf(stderr, "[ioxide.ngtcp2] refusing a sockaddr longer than %zu bytes\n",
                sizeof(c->local_addr));
        free(c);
        return NULL;
    }

    memcpy(&c->local_addr, local_sa, local_salen);
    memcpy(&c->remote_addr, remote_sa, remote_salen);
    c->path.local.addr     = &c->local_addr.sa;
    c->path.local.addrlen  = (ngtcp2_socklen)local_salen;
    c->path.remote.addr    = &c->remote_addr.sa;
    c->path.remote.addrlen = (ngtcp2_socklen)remote_salen;

    /* What the caller already believes, so the first sync is a no-op. Left zeroed, every new
     * connection would report a path change it had not had. */
    memcpy(&c->reported_addr, remote_sa, remote_salen);
    c->reported_addrlen = (ngtcp2_socklen)remote_salen;

    ngtcp2_callbacks callbacks = {0};
    callbacks.recv_client_initial       = ngtcp2_crypto_recv_client_initial_cb;
    callbacks.recv_crypto_data          = ngtcp2_crypto_recv_crypto_data_cb;
    callbacks.encrypt                   = ngtcp2_crypto_encrypt_cb;
    callbacks.decrypt                   = ngtcp2_crypto_decrypt_cb;
    callbacks.hp_mask                   = ngtcp2_crypto_hp_mask_cb;
    callbacks.update_key                = ngtcp2_crypto_update_key_cb;
    callbacks.delete_crypto_aead_ctx    = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    callbacks.delete_crypto_cipher_ctx  = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    callbacks.get_path_challenge_data   = ngtcp2_crypto_get_path_challenge_data_cb;
    callbacks.version_negotiation       = ngtcp2_crypto_version_negotiation_cb;
    callbacks.rand                      = iq_rand;
    callbacks.get_new_connection_id     = iq_cb_get_new_connection_id;
    callbacks.remove_connection_id      = iq_cb_remove_connection_id;
    callbacks.handshake_completed       = iq_cb_handshake_completed;
    callbacks.recv_stream_data          = iq_cb_recv_stream_data;
    callbacks.stream_close              = iq_cb_stream_close;
    callbacks.stream_reset              = iq_cb_stream_reset;
    callbacks.stream_stop_sending       = iq_cb_stream_stop_sending;
    callbacks.acked_stream_data_offset  = iq_cb_acked_stream_data_offset;

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = ts;
    /* UINT64_MAX is how ngtcp2 spells "no bound"; 0 would mean initial_ts + 0, i.e. expired on
       arrival, so the disabled case has to be mapped explicitly rather than passed through. */
    settings.handshake_timeout = e->handshake_timeout != 0 ? e->handshake_timeout : UINT64_MAX;

    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    params.initial_max_stream_data_bidi_local  = 256 * 1024;
    params.initial_max_stream_data_bidi_remote = 256 * 1024;
    params.initial_max_stream_data_uni         = 256 * 1024;
    params.initial_max_data                    = 1024 * 1024;
    params.initial_max_streams_bidi            = 1024;
    params.initial_max_streams_uni             = 100;
    /* The budget for connection ids the CLIENT issues us, and a migration spends one: a client
     * that moves is required to use a fresh CID, and ngtcp2 pops one from this pool to do it.
     * ngtcp2's default is RFC 9000's minimum of 2, which during a validation window is current +
     * fallback + nothing spare - so a second migration inside that window finds the pool empty,
     * ngtcp2 swallows it ("DCID is not available. Just continue."), the path never moves and the
     * connection blackholes with no error anywhere. */
    params.active_connection_id_limit          = 8;
    params.original_dcid                       = hd.dcid;
    params.original_dcid_present               = 1;

    ngtcp2_cid scid;
    scid.datalen = e->cidlen;   /* bounded to 1..NGTCP2_MAX_CIDLEN when the engine was created */
    ptls_openssl_random_bytes(scid.data, scid.datalen);
    iq_stamp_shard(scid.data, shard, shard_count);

    if (ngtcp2_conn_server_new(&c->conn, &hd.scid, &scid, &c->path, hd.version,
                               &callbacks, &settings, &params, NULL, c) != 0) {
        free(c);
        return NULL;
    }

    c->conn_ref.get_conn  = iq_get_conn;
    c->conn_ref.user_data = c;

    ngtcp2_crypto_picotls_ctx_init(&c->cptls);
    /* Whichever generation is in force when this connection starts is the one it uses for its
       whole life - picotls keeps reading the context, and a renewal a moment later installs a new
       generation without touching this one. */
    c->cptls.ptls = ptls_new(&__atomic_load_n(&e->certs, __ATOMIC_ACQUIRE)->ptls_ctx, 1 /* server */);
    if (c->cptls.ptls == NULL) {
        ngtcp2_conn_del(c->conn);
        free(c);
        return NULL;
    }
    *ptls_get_data_ptr(c->cptls.ptls) = &c->conn_ref;

    c->exts[1].type = UINT16_MAX;   /* picotls terminator; [0] is filled during the handshake */
    c->cptls.handshake_properties.additional_extensions = c->exts;

    if (ngtcp2_crypto_picotls_configure_server_session(&c->cptls) != 0) {
        ptls_free(c->cptls.ptls);
        ngtcp2_conn_del(c->conn);
        free(c);
        return NULL;
    }

    ngtcp2_conn_set_tls_native_handle(c->conn, &c->cptls);
    ngtcp2_ccerr_default(&c->last_error);

    memcpy(scid_out, scid.data, scid.datalen);
    return c;
}

void iq_conn_free(iq_conn *c)
{
    if (c == NULL) {
        return;
    }
    if (c->cptls.ptls != NULL) {
        ngtcp2_crypto_picotls_deconfigure_session(&c->cptls);
        ptls_free(c->cptls.ptls);
    }
    ngtcp2_conn_del(c->conn);
    free(c);
}


/* ngtcp2's own sockaddr comparison lives in lib/ngtcp2_addr.h, which is INTERNAL - it is not
 * shipped under lib/includes, so calling it compiled only by implicit declaration and stops
 * building outright on GCC 14+, where that is an error rather than a warning. This mirrors it
 * using the public types.
 *
 * A plain memcmp is not a substitute: sockaddr_in carries sin_zero padding and sockaddr_in6
 * carries flowinfo and scope_id, so two spellings of the same peer can differ byte-wise and would
 * read as an address change - firing a migration callback on a connection that never moved. */
static int iq_sockaddr_eq(const ngtcp2_sockaddr *a, const ngtcp2_sockaddr *b)
{
    if (a->sa_family != b->sa_family) {
        return 0;
    }

    switch (a->sa_family) {
    case NGTCP2_AF_INET: {
        const ngtcp2_sockaddr_in *ai = (const ngtcp2_sockaddr_in *)(const void *)a;
        const ngtcp2_sockaddr_in *bi = (const ngtcp2_sockaddr_in *)(const void *)b;
        return ai->sin_port == bi->sin_port &&
               memcmp(&ai->sin_addr, &bi->sin_addr, sizeof(ai->sin_addr)) == 0;
    }
    case NGTCP2_AF_INET6: {
        const ngtcp2_sockaddr_in6 *ai = (const ngtcp2_sockaddr_in6 *)(const void *)a;
        const ngtcp2_sockaddr_in6 *bi = (const ngtcp2_sockaddr_in6 *)(const void *)b;
        return ai->sin6_port == bi->sin6_port &&
               memcmp(&ai->sin6_addr, &bi->sin6_addr, sizeof(ai->sin6_addr)) == 0;
    }
    default:
        return 0;   /* cannot arrive from a UDP recvmsg; re-reporting is harmless if it ever does */
    }
}

/* Tell the caller if the path in force has moved since we last said so.
 *
 * ngtcp2 changes conn->dcid.current in four places, and only three are inside read_pkt. The fourth
 * is conn_on_path_validation_failed, reached from conn_write_path_challenge - i.e. from INSIDE a
 * write - and it restores the previous, validated path when a probe times out. Watching only the
 * read path meant that recovery was invisible: the caller stayed pinned to an address that had
 * just failed validation, permanently, because ngtcp2 also rewrites our remote_addr on every write
 * so the next read compared equal and never fired again. A connection that would have survived
 * died at the idle sweep instead. */
static void iq_sync_path(iq_conn *c)
{
    if (c->path.remote.addrlen == 0) {
        return;
    }

    if (c->path.remote.addrlen == c->reported_addrlen &&
        iq_sockaddr_eq(&c->reported_addr.sa, c->path.remote.addr)) {
        return;
    }

    if (c->path.remote.addrlen > sizeof(c->reported_addr)) {
        return;
    }

    memcpy(&c->reported_addr, c->path.remote.addr, c->path.remote.addrlen);
    c->reported_addrlen = c->path.remote.addrlen;

    if (c->cbs.on_path_change) {
        c->cbs.on_path_change(c->user, &c->reported_addr, c->reported_addrlen);
    }
}

/* Feed one UDP datagram (the transport already split GRO trains). Returns 0, or a negative
 * ngtcp2 error - NGTCP2_ERR_DRAINING / NGTCP2_ERR_DROP_CONN mean "stop using this conn". */
int iq_conn_read(iq_conn *c, const void *remote_sa, size_t remote_salen,
                 const uint8_t *pkt, size_t pktlen, uint8_t ecn, uint64_t ts)
{
    ngtcp2_pkt_info pi = { .ecn = (uint8_t)(ecn & 0x3) };

    /* The path this datagram actually arrived on, not the one it arrived on at accept. Handing
     * ngtcp2 a stale path is what made migration impossible: it cannot validate a change it is
     * never told about, and it answers whatever address it was given. Everything below this line
     * is ngtcp2's decision, not ours - it issues PATH_CHALLENGE, waits for the PATH_RESPONSE, and
     * only then adopts. We are removing a lie, not implementing migration. */
    ngtcp2_path path = c->path;
    /* A lower bound as well as an upper one: below sizeof(ngtcp2_sockaddr) the family field is not
     * even fully present, and ngtcp2_sockaddr_eq would read past what the caller vouched for -
     * an unexpected family reaches ngtcp2_unreachable() and aborts the process. Unreachable
     * through a Linux recvmsg on an AF_INET/AF_INET6 socket, but this value is now on the wire
     * path rather than discarded. */
    if (remote_sa != NULL && remote_salen >= sizeof(ngtcp2_sockaddr) &&
        remote_salen <= sizeof(ngtcp2_sockaddr_union)) {
        path.remote.addr    = (ngtcp2_sockaddr *)remote_sa;
        path.remote.addrlen = (ngtcp2_socklen)remote_salen;
    }

    int rv = ngtcp2_conn_read_pkt(c->conn, &path, &pi, pkt, pktlen, ts);

    /* Before the error check on purpose: read_pkt can adopt a new path and then fail on a later
     * coalesced packet in the same datagram. Returning early there left the caller sending the
     * CONNECTION_CLOSE to the address the peer had just left, which is the silent death this whole
     * change exists to remove. */
    const ngtcp2_path *now = ngtcp2_conn_get_path2(c->conn);
    if (now != NULL && now->remote.addrlen > 0 &&
        now->remote.addrlen <= sizeof(c->remote_addr)) {
        memcpy(&c->remote_addr, now->remote.addr, now->remote.addrlen);
        c->path.remote.addr    = &c->remote_addr.sa;
        c->path.remote.addrlen = now->remote.addrlen;
    }
    iq_sync_path(c);

    return rv;
}

/* Produce at most one UDP datagram into dest. With stream_id >= 0, tries to include data from
 * (data, datalen) on that stream; *pconsumed reports how much was accepted (-1 = none).
 * Returns the datagram size, 0 when there is nothing (more) to send, or a negative ngtcp2
 * error. NGTCP2_ERR_STREAM_DATA_BLOCKED / STREAM_SHUT_WR simply mean "stop sending app data".  */
ngtcp2_ssize iq_conn_write(iq_conn *c, uint8_t *dest, size_t destlen,
                           int64_t stream_id, const uint8_t *data, size_t datalen, int fin,
                           int64_t *pconsumed, uint64_t ts)
{
    ngtcp2_vec vec = { .base = (uint8_t *)data, .len = datalen };
    ngtcp2_ssize consumed = -1;

    uint32_t flags = 0;
    if (fin) {
        flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
    }

    ngtcp2_ssize n = ngtcp2_conn_writev_stream(
        c->conn, &c->path, NULL, dest, destlen, &consumed, flags, stream_id,
        data != NULL ? &vec : NULL, data != NULL ? 1 : 0, ts);

    *pconsumed = consumed;

    /* writev_stream's path argument is an OUT parameter: ngtcp2 has just written the destination
     * it chose for THIS datagram into c->path. For ordinary traffic that is the current path; for
     * a PATH_RESPONSE it is the address the challenge arrived from, and for a probe it is the
     * address being validated. Reporting it here is what stops those going to the wrong peer -
     * RFC 9000 8.2.2 requires a PATH_RESPONSE on the path its challenge came in on. */
    iq_sync_path(c);
    return n;
}


/* App-initiated close: record an APPLICATION error (e.g. H3_NO_ERROR for graceful shutdown) and
 * build the CONNECTION_CLOSE datagram carrying it. The caller sends it and tears the conn down. */
ngtcp2_ssize iq_conn_close(iq_conn *c, uint64_t app_error_code,
                           uint8_t *dest, size_t destlen, uint64_t ts)
{
    ngtcp2_ccerr_set_application_error(&c->last_error, app_error_code, NULL, 0);
    return ngtcp2_conn_write_connection_close(c->conn, &c->path, NULL, dest, destlen,
                                              &c->last_error, ts);
}

/* Engine-initiated close: the peer is told which TRANSPORT error ended this, translated from the
 * ngtcp2 library error code, instead of the connection simply going quiet and the peer waiting out
 * its idle timeout. Returns <= 0 when there is nothing to send - notably in draining and closing
 * state, where a CONNECTION_CLOSE would be a reply to one the peer already sent. */
ngtcp2_ssize iq_conn_close_liberr(iq_conn *c, int liberr,
                                  uint8_t *dest, size_t destlen, uint64_t ts)
{
    ngtcp2_ccerr_set_liberr(&c->last_error, liberr, NULL, 0);
    return ngtcp2_conn_write_connection_close(c->conn, &c->path, NULL, dest, destlen,
                                              &c->last_error, ts);
}

uint64_t iq_conn_expiry(iq_conn *c)
{
    return ngtcp2_conn_get_expiry(c->conn);
}

int iq_conn_handle_expiry(iq_conn *c, uint64_t ts)
{
    int rv = ngtcp2_conn_handle_expiry(c->conn, ts);
    iq_sync_path(c);
    return rv;
}

int iq_conn_is_established(iq_conn *c)
{
    return ngtcp2_conn_get_handshake_completed(c->conn);
}

/* The tighter of two bounds where 0 means "none". */
static uint64_t iq_tighter_bound(uint64_t a, uint64_t b)
{
    if (a == 0) {
        return b;
    }
    if (b == 0) {
        return a;
    }
    return a < b ? a : b;
}

/* Keep-alive while this side owes a response: a PING at half the tightest of the transport's bound
 * (bound_ns, 0 = none) and both idle timeouts, so the peer's ACK lands inside all of them. */
void iq_conn_set_keep_alive(iq_conn *c, int on, uint64_t bound_ns)
{
    if (c == NULL || c->conn == NULL) {
        return;
    }

    ngtcp2_duration interval = UINT64_MAX;
    if (on) {
        const ngtcp2_transport_params *local = ngtcp2_conn_get_local_transport_params2(c->conn);
        const ngtcp2_transport_params *remote = ngtcp2_conn_get_remote_transport_params2(c->conn);

        uint64_t bound = bound_ns;
        bound = iq_tighter_bound(bound, local != NULL ? local->max_idle_timeout : 0);
        bound = iq_tighter_bound(bound, remote != NULL ? remote->max_idle_timeout : 0);
        if (bound != 0) {
            interval = bound / 2;
        }
    }

    ngtcp2_conn_set_keep_alive_timeout(c->conn, interval);
}


/* Open a server-initiated unidirectional stream (H3 control / QPACK). Returns the stream id, or
 * a negative ngtcp2 error (e.g. STREAM_ID_BLOCKED when the peer's uni allowance is exhausted). */
int64_t iq_conn_open_uni(iq_conn *c)
{
    int64_t sid;
    int rv = ngtcp2_conn_open_uni_stream(c->conn, &sid, NULL);
    return rv != 0 ? (int64_t)rv : sid;
}

/* Negotiated ALPN token into buf; returns its length, 0 if none (or buf too small). */
size_t iq_conn_get_alpn(iq_conn *c, uint8_t *buf, size_t buflen)
{
    if (c->cptls.ptls == NULL) {
        return 0;
    }
    const char *proto = ptls_get_negotiated_protocol(c->cptls.ptls);
    if (proto == NULL) {
        return 0;
    }
    size_t len = strlen(proto);
    if (len == 0 || len > buflen) {
        return 0;
    }
    memcpy(buf, proto, len);
    return len;
}

const char *iq_strerror(int liberr)
{
    return ngtcp2_strerror(liberr);
}

/* ---- minimal client (test harness only) -------------------------------------------------- *
 * A bare ngtcp2 client with a picotls session, enough to complete a real handshake against the
 * server side above and echo one bidi stream. Not part of the public C# API - it exists so the
 * e2e suite can prove the whole engine hermetically, with no external QUIC client.             */

typedef struct iq_client_engine {
    ptls_context_t ptls_ctx;
    ptls_openssl_sign_certificate_t sign_cert;   /* mTLS: signs with the client's own key */
    iq_callbacks   cbs;
    char           alpn[64];   /* the protocol every connection from this engine offers */
    /* Unused unless iq_client_engine_record_server_certificate was called. */
    ptls_verify_certificate_t record_cert;
} iq_client_engine;

/* Records the subject of the certificate the SERVER served, and accepts it whatever it is.
 *
 * Leaving *verify_sign NULL is how picotls is told to skip the CertificateVerify check, which is
 * precisely what this client did before with no callback registered at all. Paired with the
 * signature algorithms picotls itself offers in that case (below), installing this changes what is
 * REMEMBERED about a handshake and not one byte of what goes on the wire or what is accepted. */
static int iq_record_server_certificate(ptls_verify_certificate_t *self, ptls_t *tls,
                                        const char *server_name,
                                        int (**verify_sign)(void *verify_ctx, uint16_t algo,
                                                            ptls_iovec_t data, ptls_iovec_t signature),
                                        void **verify_data, ptls_iovec_t *certs, size_t num_certs)
{
    (void)self;
    (void)server_name;
    *verify_sign = NULL;
    *verify_data = NULL;

    if (num_certs == 0) {
        return 0;
    }

    void **slot = ptls_get_data_ptr(tls);
    if (slot == NULL || *slot == NULL) {
        return 0;
    }
    iq_conn *c = (iq_conn *)((char *)*slot - offsetof(iq_conn, conn_ref));

    const uint8_t *der = certs[0].base;
    X509 *leaf = d2i_X509(NULL, &der, (long)certs[0].len);
    if (leaf != NULL) {
        iq_record_subject(c, leaf);
        /* NOT peer_authenticated: nothing here checked a chain, a name, or a signature. */
        c->peer_recorded = 1;
        X509_free(leaf);
    }

    return 0;
}

/* Makes connections from this engine remember which certificate the server served, readable
 * afterwards with iq_conn_server_subject. Verification stays off: the client accepts any
 * certificate, exactly as it did without this.
 *
 * It exists so the suite can prove SNI selection, whose only externally visible effect is WHICH
 * certificate comes back for a given name. Call before connecting.
 *
 * Refuses when a verifier is already installed. A function that only observes must never be able
 * to switch off a check someone else put there - the day this client learns to authenticate
 * servers, asking it to record one would otherwise silently disable that. */
void iq_client_engine_record_server_certificate(iq_client_engine *e)
{
    /* picotls's own list for a client with no verifier registered (push_signature_algorithms),
     * repeated here so the ClientHello is byte-for-byte what it was. */
    static const uint16_t algos[] = {PTLS_SIGNATURE_RSA_PSS_RSAE_SHA384, PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
                                     PTLS_SIGNATURE_ECDSA_SECP384R1_SHA384, PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256,
                                     PTLS_SIGNATURE_RSA_PKCS1_SHA256, PTLS_SIGNATURE_RSA_PKCS1_SHA1, UINT16_MAX};

    if (e == NULL) {
        return;
    }

    if (e->ptls_ctx.verify_certificate != NULL) {
        /* Said out loud: the caller asked to observe the server's certificate and will now read
         * nothing back, and silence would leave that looking like a server that sent none. */
        fprintf(stderr, "[ioxide.ngtcp2] client: a verifier is already installed; "
                        "not replacing it to record the server certificate\n");
        return;
    }

    e->record_cert.cb    = iq_record_server_certificate;
    e->record_cert.algos = algos;
    e->ptls_ctx.verify_certificate = &e->record_cert;
}


/* A client that can prove who it is: cert_pem_path and key_pem_path are the certificate it presents
 * when a server asks for one. Both NULL leaves the client exactly as it was, offering nothing. */
iq_client_engine *iq_client_engine_new_mtls(const char *alpn, const char *cert_pem_path,
                                            const char *key_pem_path, iq_callbacks cbs)
{
    if (cbs.struct_size != sizeof(iq_callbacks)) {
        fprintf(stderr, "[ioxide.ngtcp2] callback table is %zu bytes, this build expects %zu - "
                        "a managed mirror of iq_callbacks is out of date\n",
                cbs.struct_size, sizeof(iq_callbacks));
        return NULL;
    }


    iq_client_engine *e = calloc(1, sizeof(*e));
    if (e == NULL) {
        return NULL;
    }
    e->cbs = cbs;
    if (alpn != NULL) {
        snprintf(e->alpn, sizeof(e->alpn), "%s", alpn);
    }
    e->ptls_ctx.random_bytes  = ptls_openssl_random_bytes;
    e->ptls_ctx.get_time      = &ptls_get_time;
    e->ptls_ctx.key_exchanges = ptls_openssl_key_exchanges_all;
    e->ptls_ctx.cipher_suites = ptls_openssl_cipher_suites;
    /* Accepts the server's certificate unconditionally (verify_certificate NULL) - this client
     * exists to drive our own servers, not to authenticate them. */

    if (cert_pem_path != NULL && key_pem_path != NULL) {
        if (iq_load_keypair(&e->ptls_ctx, &e->sign_cert, cert_pem_path, key_pem_path, "client") != 0) {
            free(e);
            return NULL;
        }
    }

    if (ngtcp2_crypto_picotls_configure_client_context(&e->ptls_ctx) != 0) {
        iq_dispose_keypair(&e->ptls_ctx, &e->sign_cert);
        free(e);
        return NULL;
    }
    return e;
}

void iq_client_engine_free(iq_client_engine *e)
{
    if (e == NULL) {
        return;
    }

    iq_dispose_keypair(&e->ptls_ctx, &e->sign_cert);
    free(e);
}

/* Open a client connection. scid_len is the length of the connection ID we ask the peer to send
 * back to us: it MUST match the demux slice of whoever routes our inbound datagrams (the reactor
 * uses QuicOptions.LocalCidLength), because short-header packets carry no CID length on the wire.
 * scid_out receives that CID so the caller can register the route. */
iq_conn *iq_client_connect(iq_client_engine *e,
                           const void *local_sa, size_t local_salen,
                           const void *remote_sa, size_t remote_salen,
                           const char *server_name, const char *alpn,
                           size_t scid_len, uint64_t ts, void *user,
                           uint8_t *scid_out)
{
    /* Refused rather than substituted: the caller demultiplexes inbound datagrams by exactly the
     * length it asked for, so quietly minting a different one would produce a connection whose
     * replies never route back. Out of range is a caller bug and is reported as one. */
    if (scid_len < 1 || scid_len > NGTCP2_MAX_CIDLEN) {
        fprintf(stderr, "[ioxide.ngtcp2] client connection ID length %zu is out of range (1..%d)\n",
                scid_len, NGTCP2_MAX_CIDLEN);
        return NULL;
    }

    iq_conn *c = calloc(1, sizeof(*c));
    if (c == NULL) {
        return NULL;
    }
    c->user = user;
    c->cbs = e->cbs;

    /* Clamped at the entry point, like every other caller-supplied length here. The destinations
     * are ngtcp2_sockaddr_union - 28 bytes, sa/in/in6 only, NOT sockaddr_storage - and the field
     * immediately after them is the ngtcp2_path whose members ngtcp2 dereferences. The kernel
     * bounds an AF_INET/AF_INET6 recvmsg to 28, so this is not reachable today; the managed side
     * hands over a 128-byte name buffer, which is the gap that makes it worth stating. */
    if (local_salen > sizeof(c->local_addr) || remote_salen > sizeof(c->remote_addr)) {
        fprintf(stderr, "[ioxide.ngtcp2] refusing a sockaddr longer than %zu bytes\n",
                sizeof(c->local_addr));
        free(c);
        return NULL;
    }

    memcpy(&c->local_addr, local_sa, local_salen);
    memcpy(&c->remote_addr, remote_sa, remote_salen);
    c->path.local.addr     = &c->local_addr.sa;
    c->path.local.addrlen  = (ngtcp2_socklen)local_salen;
    c->path.remote.addr    = &c->remote_addr.sa;
    c->path.remote.addrlen = (ngtcp2_socklen)remote_salen;

    /* What the caller already believes, so the first sync is a no-op. Left zeroed, every new
     * connection would report a path change it had not had. */
    memcpy(&c->reported_addr, remote_sa, remote_salen);
    c->reported_addrlen = (ngtcp2_socklen)remote_salen;

    ngtcp2_callbacks callbacks = {0};
    callbacks.client_initial            = ngtcp2_crypto_client_initial_cb;
    callbacks.recv_crypto_data          = ngtcp2_crypto_recv_crypto_data_cb;
    callbacks.encrypt                   = ngtcp2_crypto_encrypt_cb;
    callbacks.decrypt                   = ngtcp2_crypto_decrypt_cb;
    callbacks.hp_mask                   = ngtcp2_crypto_hp_mask_cb;
    callbacks.recv_retry                = ngtcp2_crypto_recv_retry_cb;
    callbacks.update_key                = ngtcp2_crypto_update_key_cb;
    callbacks.delete_crypto_aead_ctx    = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    callbacks.delete_crypto_cipher_ctx  = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    callbacks.get_path_challenge_data   = ngtcp2_crypto_get_path_challenge_data_cb;
    callbacks.version_negotiation       = ngtcp2_crypto_version_negotiation_cb;
    callbacks.rand                      = iq_rand;
    callbacks.get_new_connection_id     = iq_cb_get_new_connection_id_noreport;
    callbacks.handshake_completed       = iq_cb_handshake_completed;
    callbacks.recv_stream_data          = iq_cb_recv_stream_data;
    callbacks.stream_close              = iq_cb_stream_close;
    callbacks.stream_reset              = iq_cb_stream_reset;
    callbacks.stream_stop_sending       = iq_cb_stream_stop_sending;
    callbacks.acked_stream_data_offset  = iq_cb_acked_stream_data_offset;

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = ts;

    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    params.initial_max_stream_data_bidi_local  = 256 * 1024;
    params.initial_max_stream_data_bidi_remote = 256 * 1024;
    params.initial_max_stream_data_uni         = 256 * 1024;
    params.initial_max_data                    = 1024 * 1024;
    params.initial_max_streams_bidi            = 1024;
    params.initial_max_streams_uni             = 100;

    ngtcp2_cid dcid, scid;
    dcid.datalen = 16; ptls_openssl_random_bytes(dcid.data, dcid.datalen);
    scid.datalen = scid_len;
    ptls_openssl_random_bytes(scid.data, scid.datalen);

    if (ngtcp2_conn_client_new(&c->conn, &dcid, &scid, &c->path, NGTCP2_PROTO_VER_V1,
                               &callbacks, &settings, &params, NULL, c) != 0) {
        free(c);
        return NULL;
    }

    c->conn_ref.get_conn  = iq_get_conn;
    c->conn_ref.user_data = c;

    ngtcp2_crypto_picotls_ctx_init(&c->cptls);
    c->cptls.ptls = ptls_new(&e->ptls_ctx, 0 /* client */);
    if (c->cptls.ptls == NULL) {
        ngtcp2_conn_del(c->conn);
        free(c);
        return NULL;
    }
    *ptls_get_data_ptr(c->cptls.ptls) = &c->conn_ref;
    ptls_set_server_name(c->cptls.ptls, server_name, strlen(server_name));

    c->exts[1].type = UINT16_MAX;
    c->cptls.handshake_properties.additional_extensions = c->exts;

    if (ngtcp2_crypto_picotls_configure_client_session(&c->cptls, c->conn) != 0) {
        ptls_free(c->cptls.ptls);
        ngtcp2_conn_del(c->conn);
        free(c);
        return NULL;
    }

    /* ALPN: RFC 9001 requires QUIC clients to offer one, and a server pinned to "h3" fails the
     * handshake (no_application_protocol -> ERR_CRYPTO) against a client that offers none. The
     * iovec must outlive the handshake, so it points into the connection's own buffer. */
    const char *offer = (alpn != NULL && alpn[0] != '\0') ? alpn : e->alpn;
    if (offer != NULL && offer[0] != '\0') {
        snprintf(c->alpn, sizeof(c->alpn), "%s", offer);
        c->alpn_vec.base = (uint8_t *)c->alpn;
        c->alpn_vec.len  = strlen(c->alpn);
        c->cptls.handshake_properties.client.negotiated_protocols.list  = &c->alpn_vec;
        c->cptls.handshake_properties.client.negotiated_protocols.count = 1;
    }


    ngtcp2_conn_set_tls_native_handle(c->conn, &c->cptls);
    ngtcp2_ccerr_default(&c->last_error);

    if (scid_out != NULL) {
        memcpy(scid_out, scid.data, scid.datalen);
    }
    return c;
}

/* Open a client bidi stream; returns the stream id or a negative error. */
int64_t iq_client_open_bidi(iq_conn *c)
{
    int64_t sid;
    if (ngtcp2_conn_open_bidi_stream(c->conn, &sid, NULL) != 0) {
        return -1;
    }
    return sid;
}

/* ---- app-paced receive windows ----------------------------------------------------------- */

/* Mark/unmark a stream as app-paced (see iq_conn.paced). Reactor thread only. */
void iq_conn_set_stream_paced(iq_conn *c, int64_t stream_id, int on)
{
    int pi = iq_paced_index(c, stream_id);
    if (on) {
        if (pi < 0 && c->paced_count < (int)(sizeof(c->paced) / sizeof(c->paced[0]))) {
            c->paced[c->paced_count++] = stream_id;
        }
    } else if (pi >= 0) {
        c->paced[pi] = c->paced[--c->paced_count];
    }
}

/* Open the peer's flow-control window (stream + connection) for bytes the app consumed on a
 * paced stream. Extending is permission, never obligation - over-crediting is harmless. */
void iq_conn_consume(iq_conn *c, int64_t stream_id, uint64_t n)
{
    ngtcp2_conn_extend_max_offset(c->conn, n);
    ngtcp2_conn_extend_max_stream_offset(c->conn, stream_id, n);
}
