/*
 * ioxide.nghttp3 native shim: a thin, C#-friendly facade over nghttp3 (sans-I/O HTTP/3 + QPACK).
 *
 * Why it exists: nghttp3's conn API takes a ~15-entry callback table, rcbuf-typed header values
 * and vectored reads - marshaling those from C# would be fragile against upstream layout drift.
 * The shim owns every struct layout in C (compiled against the exact bundled headers) and exposes
 * a small stable ABI. It does no I/O and holds no transport state: bytes in via ih3_read_stream
 * (from any QuicConnection's recv queue), bytes out via ih3_writev (into SendStream).
 *
 *   conn = ih3_server_new(cbs, user)              one per QUIC connection
 *          ih3_bind_streams(ctrl, qenc, qdec)     the server-opened uni streams (SETTINGS ride out
 *                                                 on the next ih3_writev drain)
 *          ih3_read_stream(sid, data, len, fin)   feed one recv item; request events fire back
 *          ih3_submit_response(sid, hdrs, body)   headers packed [u16 nlen][name][u16 vlen][value]*
 *          ih3_writev(&sid, &fin, buf, len)       drain one egress chunk per call until 0
 *          ih3_close_stream(sid, app_error)       QUIC reported the stream closed
 *          ih3_free
 *
 * Every call happens on the owning reactor thread. Response bodies are copied in and freed on
 * stream close, so the C# side keeps nothing alive.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>

#include <nghttp3/nghttp3.h>

/* ---- callback table into C# ------------------------------------------------------------- */

typedef struct ih3_callbacks {
    void (*on_begin_headers)(void *user, int64_t stream_id);
    void (*on_header)(void *user, int64_t stream_id,
                      const uint8_t *name, size_t namelen,
                      const uint8_t *value, size_t valuelen);
    void (*on_end_headers)(void *user, int64_t stream_id, int fin);
    void (*on_data)(void *user, int64_t stream_id, const uint8_t *data, size_t datalen);
    void (*on_end_stream)(void *user, int64_t stream_id);
    /* nghttp3 consumed bytes internally for a stream (sync-blocked case): the app must credit
     * them to QUIC flow control when it paces that stream. Optional (may be NULL). */
    void (*on_deferred_consume)(void *user, int64_t stream_id, size_t consumed);
    /* Pull the next body chunk for a STREAMED response. Sets *buf/*len to memory that must stay
     * valid until the stream closes (nghttp3 does not copy), and *fin when that chunk is the last.
     * Leaving *len 0 with *fin 0 means "nothing yet" - the stream is deferred until the app calls
     * ih3_resume_stream. Optional (may be NULL); without it no stream can be submitted streamed. */
    void (*on_read_body)(void *user, int64_t stream_id, const uint8_t **buf, size_t *len, int *fin);
} ih3_callbacks;

/* ---- objects ---------------------------------------------------------------------------- */

/* Per-request-stream send state: the response body, copied at submit, freed at close. */
typedef struct ih3_stream {
    int64_t             id;
    uint8_t            *body;      /* buffered responses only: copied at submit, freed at close */
    size_t              body_len;
    int                 streamed;  /* 1 = body is pulled from the app through on_read_body */
    struct ih3_stream  *next;
} ih3_stream;

typedef struct ih3_conn {
    nghttp3_conn   *conn;
    ih3_callbacks   cbs;
    void           *user;
    ih3_stream     *streams;
} ih3_conn;

static ih3_stream *ih3_stream_find(ih3_conn *c, int64_t id)
{
    for (ih3_stream *s = c->streams; s != NULL; s = s->next) {
        if (s->id == id) {
            return s;
        }
    }
    return NULL;
}

static void ih3_stream_drop(ih3_conn *c, int64_t id)
{
    ih3_stream **p = &c->streams;
    while (*p != NULL) {
        if ((*p)->id == id) {
            ih3_stream *dead = *p;
            *p = dead->next;
            free(dead->body);
            free(dead);
            return;
        }
        p = &(*p)->next;
    }
}

/* ---- nghttp3 callbacks ------------------------------------------------------------------ */

static int ih3_cb_begin_headers(nghttp3_conn *conn, int64_t stream_id, void *conn_user_data,
                                void *stream_user_data)
{
    (void)conn; (void)stream_user_data;
    ih3_conn *c = conn_user_data;
    c->cbs.on_begin_headers(c->user, stream_id);
    return 0;
}

static int ih3_cb_recv_header(nghttp3_conn *conn, int64_t stream_id, int32_t token,
                              nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags,
                              void *conn_user_data, void *stream_user_data)
{
    (void)conn; (void)token; (void)flags; (void)stream_user_data;
    ih3_conn *c = conn_user_data;
    nghttp3_vec n = nghttp3_rcbuf_get_buf(name);
    nghttp3_vec v = nghttp3_rcbuf_get_buf(value);
    c->cbs.on_header(c->user, stream_id, n.base, n.len, v.base, v.len);
    return 0;
}

static int ih3_cb_end_headers(nghttp3_conn *conn, int64_t stream_id, int fin,
                              void *conn_user_data, void *stream_user_data)
{
    (void)conn; (void)stream_user_data;
    ih3_conn *c = conn_user_data;
    c->cbs.on_end_headers(c->user, stream_id, fin);
    return 0;
}

static int ih3_cb_recv_data(nghttp3_conn *conn, int64_t stream_id, const uint8_t *data,
                            size_t datalen, void *conn_user_data, void *stream_user_data)
{
    (void)conn; (void)stream_user_data;
    ih3_conn *c = conn_user_data;
    c->cbs.on_data(c->user, stream_id, data, datalen);
    return 0;
}

static int ih3_cb_end_stream(nghttp3_conn *conn, int64_t stream_id, void *conn_user_data,
                             void *stream_user_data)
{
    (void)conn; (void)stream_user_data;
    ih3_conn *c = conn_user_data;
    c->cbs.on_end_stream(c->user, stream_id);
    return 0;
}

static int ih3_cb_stream_close(nghttp3_conn *conn, int64_t stream_id, uint64_t app_error_code,
                               void *conn_user_data, void *stream_user_data)
{
    (void)conn; (void)app_error_code; (void)stream_user_data;
    ih3_conn *c = conn_user_data;
    ih3_stream_drop(c, stream_id);
    return 0;
}

static int ih3_cb_deferred_consume(nghttp3_conn *conn, int64_t stream_id, size_t nconsumed,
                                   void *conn_user_data, void *stream_user_data)
{
    (void)conn; (void)stream_user_data;
    ih3_conn *c = conn_user_data;
    if (c->cbs.on_deferred_consume) {
        c->cbs.on_deferred_consume(c->user, stream_id, nconsumed);
    }
    return 0;
}

static int ih3_cb_acked_stream_data(nghttp3_conn *conn, int64_t stream_id, uint64_t datalen,
                                    void *conn_user_data, void *stream_user_data)
{
    (void)conn; (void)stream_id; (void)datalen; (void)conn_user_data; (void)stream_user_data;
    return 0;
}

/* ---- body provider ---------------------------------------------------------------------- */

/* Hand nghttp3 the whole remaining body in one vec with EOF; it slices as the window allows.
 * The buffer stays valid until stream close (ih3_stream_drop), so no ack tracking is needed. */
static nghttp3_ssize ih3_read_body(nghttp3_conn *conn, int64_t stream_id, nghttp3_vec *vec,
                                   size_t veccnt, uint32_t *pflags, void *conn_user_data,
                                   void *stream_user_data)
{
    (void)conn; (void)veccnt; (void)stream_user_data;
    ih3_conn *c = conn_user_data;
    ih3_stream *s = ih3_stream_find(c, stream_id);

    *pflags |= NGHTTP3_DATA_FLAG_EOF;
    if (s == NULL || s->body_len == 0) {
        return 0;
    }
    vec[0].base = s->body;
    vec[0].len  = s->body_len;
    return 1;
}

/* The STREAMED counterpart of ih3_read_body: the body is not here, it is in the application, so
 * ask for it. Returning WOULDBLOCK is how nghttp3 is told "not yet" - it then defers the stream
 * and stops asking until ih3_resume_stream says otherwise, which is what keeps a slow producer
 * from spinning the egress pump. */
static nghttp3_ssize ih3_read_body_streamed(nghttp3_conn *conn, int64_t stream_id, nghttp3_vec *vec,
                                            size_t veccnt, uint32_t *pflags, void *conn_user_data,
                                            void *stream_user_data)
{
    (void)conn; (void)veccnt; (void)stream_user_data;
    ih3_conn *c = conn_user_data;

    if (c->cbs.on_read_body == NULL) {
        *pflags |= NGHTTP3_DATA_FLAG_EOF;
        return 0;
    }

    const uint8_t *buf = NULL;
    size_t len = 0;
    int fin = 0;
    c->cbs.on_read_body(c->user, stream_id, &buf, &len, &fin);

    if (len == 0 && !fin) {
        return NGHTTP3_ERR_WOULDBLOCK;
    }

    if (fin) {
        *pflags |= NGHTTP3_DATA_FLAG_EOF;
    }

    if (len == 0) {
        return 0;   /* end of body with nothing left to send */
    }

    vec[0].base = (uint8_t *)buf;
    vec[0].len  = len;
    return 1;
}

/* ---- API -------------------------------------------------------------------------------- */

static ih3_conn *ih3_new(ih3_callbacks cbs, void *user, int server,
                         uint64_t qpack_max_dtable_capacity, uint64_t qpack_blocked_streams)
{
    ih3_conn *c = calloc(1, sizeof(*c));
    if (c == NULL) {
        return NULL;
    }
    c->cbs  = cbs;
    c->user = user;

    nghttp3_callbacks callbacks = {0};
    callbacks.begin_headers     = ih3_cb_begin_headers;
    callbacks.recv_header       = ih3_cb_recv_header;
    callbacks.end_headers       = ih3_cb_end_headers;
    callbacks.recv_data         = ih3_cb_recv_data;
    callbacks.end_stream        = ih3_cb_end_stream;
    callbacks.stream_close      = ih3_cb_stream_close;
    callbacks.deferred_consume  = ih3_cb_deferred_consume;
    callbacks.acked_stream_data = ih3_cb_acked_stream_data;

    nghttp3_settings settings;
    nghttp3_settings_default(&settings);
    /* QPACK dynamic table: 0 (the default) pins peers to static refs + literals; a nonzero
     * capacity advertises a decode-side table and lets peers compress repeated headers
     * (cookies!) to ~2-byte references. blocked_streams bounds how many header blocks may wait
     * on an unacknowledged insertion. */
    settings.qpack_max_dtable_capacity = (size_t)qpack_max_dtable_capacity;
    settings.qpack_blocked_streams     = (size_t)qpack_blocked_streams;

    int rv = server
        ? nghttp3_conn_server_new(&c->conn, &callbacks, &settings, nghttp3_mem_default(), c)
        : nghttp3_conn_client_new(&c->conn, &callbacks, &settings, nghttp3_mem_default(), c);
    if (rv != 0) {
        free(c);
        return NULL;
    }
    return c;
}

ih3_conn *ih3_server_new(ih3_callbacks cbs, void *user,
                         uint64_t qpack_max_dtable_capacity, uint64_t qpack_blocked_streams)
{
    return ih3_new(cbs, user, 1, qpack_max_dtable_capacity, qpack_blocked_streams);
}

/* Client conn (test drivers): same event surface, requests out instead of responses. */
ih3_conn *ih3_client_new(ih3_callbacks cbs, void *user)
{
    return ih3_new(cbs, user, 0, 0, 0);   /* test drivers: no decode-side dynamic table */
}

void ih3_free(ih3_conn *c)
{
    if (c == NULL) {
        return;
    }
    while (c->streams != NULL) {
        ih3_stream_drop(c, c->streams->id);
    }
    nghttp3_conn_del(c->conn);
    free(c);
}

/* Register the server-opened uni streams. nghttp3 queues its SETTINGS/QPACK prefaces; the next
 * ih3_writev drain carries them out. */
int ih3_bind_streams(ih3_conn *c, int64_t ctrl, int64_t qenc, int64_t qdec)
{
    int rv = nghttp3_conn_bind_control_stream(c->conn, ctrl);
    if (rv != 0) {
        return rv;
    }
    return nghttp3_conn_bind_qpack_streams(c->conn, qenc, qdec);
}

/* Feed one recv item (any stream - nghttp3 demuxes uni stream types itself). Negative = fatal. */
int64_t ih3_read_stream(ih3_conn *c, int64_t stream_id, const uint8_t *data, size_t datalen, int fin)
{
    nghttp3_ssize rv = nghttp3_conn_read_stream(c->conn, stream_id, data, datalen, fin);
    return (int64_t)rv;
}

#define IH3_MAX_NV 64

/* headers: [u16 namelen][name][u16 valuelen][value] repeated, little-endian u16 (written and read
 * on the same host). Returns the entry count, or -1 on a malformed buffer. */
static int ih3_unpack_headers(const uint8_t *headers, size_t headers_len, nghttp3_nv *nva)
{
    size_t nvlen = 0;
    for (size_t off = 0; off + 2 <= headers_len && nvlen < IH3_MAX_NV; nvlen++) {
        uint16_t namelen;
        memcpy(&namelen, headers + off, 2);
        off += 2;
        const uint8_t *name = headers + off;
        off += namelen;

        if (off + 2 > headers_len) {
            return -1;
        }
        uint16_t valuelen;
        memcpy(&valuelen, headers + off, 2);
        off += 2;
        const uint8_t *value = headers + off;
        off += valuelen;

        if (off > headers_len) {
            return -1;
        }

        nva[nvlen].name     = (uint8_t *)name;
        nva[nvlen].namelen  = namelen;
        nva[nvlen].value    = (uint8_t *)value;
        nva[nvlen].valuelen = valuelen;
        nva[nvlen].flags    = NGHTTP3_NV_FLAG_NONE;

        if (off == headers_len) {
            return (int)(nvlen + 1);
        }
    }
    return (int)nvlen;
}

/* body copied; freed at stream close. */
int ih3_submit_response(ih3_conn *c, int64_t stream_id,
                        const uint8_t *headers, size_t headers_len,
                        const uint8_t *body, size_t body_len)
{
    nghttp3_nv nva[IH3_MAX_NV];
    int nvlen = ih3_unpack_headers(headers, headers_len, nva);
    if (nvlen < 0) {
        return NGHTTP3_ERR_INVALID_ARGUMENT;
    }

    ih3_stream *s = NULL;
    if (body_len > 0) {
        s = calloc(1, sizeof(*s));
        if (s == NULL) {
            return NGHTTP3_ERR_NOMEM;
        }
        s->body = malloc(body_len);
        if (s->body == NULL) {
            free(s);
            return NGHTTP3_ERR_NOMEM;
        }
        memcpy(s->body, body, body_len);
        s->body_len = body_len;
        s->id       = stream_id;
        s->next     = c->streams;
        c->streams  = s;
    }

    nghttp3_data_reader dr = { .read_data = ih3_read_body };
    int rv = nghttp3_conn_submit_response(c->conn, stream_id, nva, (size_t)nvlen,
                                          body_len > 0 ? &dr : NULL);
    if (rv != 0 && s != NULL) {
        ih3_stream_drop(c, stream_id);
    }
    return rv;
}

/* Submit a response whose body the application produces over time. Same headers path as the
 * buffered form; the difference is which reader nghttp3 gets and that nothing is copied here -
 * every chunk arrives later through on_read_body and must stay valid until the stream closes. */
int ih3_submit_response_stream(ih3_conn *c, int64_t stream_id,
                               const uint8_t *headers, size_t headers_len)
{
    nghttp3_nv nva[IH3_MAX_NV];
    int nvlen = ih3_unpack_headers(headers, headers_len, nva);
    if (nvlen < 0) {
        return NGHTTP3_ERR_INVALID_ARGUMENT;
    }

    ih3_stream *s = calloc(1, sizeof(*s));
    if (s == NULL) {
        return NGHTTP3_ERR_NOMEM;
    }
    s->id       = stream_id;
    s->streamed = 1;
    s->next     = c->streams;
    c->streams  = s;

    nghttp3_data_reader dr = { .read_data = ih3_read_body_streamed };
    int rv = nghttp3_conn_submit_response(c->conn, stream_id, nva, (size_t)nvlen, &dr);
    if (rv != 0) {
        ih3_stream_drop(c, stream_id);
    }
    return rv;
}

/* The app has more body for a stream nghttp3 deferred after a WOULDBLOCK. Undeferring is all this
 * does - the next egress pump calls on_read_body again. */
int ih3_resume_stream(ih3_conn *c, int64_t stream_id)
{
    return nghttp3_conn_resume_stream(c->conn, stream_id);
}

/* Client conn only (test drivers): a request, with an optional body served through the same
 * per-stream body machinery the server response path uses (copied, freed at stream close). */
int ih3_submit_request(ih3_conn *c, int64_t stream_id,
                       const uint8_t *headers, size_t headers_len,
                       const uint8_t *body, size_t body_len)
{
    nghttp3_nv nva[IH3_MAX_NV];
    int nvlen = ih3_unpack_headers(headers, headers_len, nva);
    if (nvlen < 0) {
        return NGHTTP3_ERR_INVALID_ARGUMENT;
    }

    ih3_stream *s = NULL;
    if (body_len > 0) {
        s = calloc(1, sizeof(*s));
        if (s == NULL) {
            return NGHTTP3_ERR_NOMEM;
        }
        s->body = malloc(body_len);
        if (s->body == NULL) {
            free(s);
            return NGHTTP3_ERR_NOMEM;
        }
        memcpy(s->body, body, body_len);
        s->body_len = body_len;
        s->id       = stream_id;
        s->next     = c->streams;
        c->streams  = s;
    }

    nghttp3_data_reader dr = { .read_data = ih3_read_body };
    int rv = nghttp3_conn_submit_request(c->conn, stream_id, nva, (size_t)nvlen,
                                         body_len > 0 ? &dr : NULL, NULL);
    if (rv != 0 && s != NULL) {
        ih3_stream_drop(c, stream_id);
    }
    return rv;
}

/* Drain one egress chunk: fills buf, returns byte count (0 = drained), sets *stream_id and *fin.
 * fin only survives when the chunk fit whole - a truncated chunk clears it and the next call
 * carries the rest. */
int64_t ih3_writev(ih3_conn *c, int64_t *stream_id, int *fin, uint8_t *buf, size_t buflen)
{
    enum { MAX_VEC = 16 };
    nghttp3_vec vec[MAX_VEC];

    int lfin = 0;
    nghttp3_ssize cnt = nghttp3_conn_writev_stream(c->conn, stream_id, &lfin, vec, MAX_VEC);
    if (cnt < 0) {
        return (int64_t)cnt;
    }
    if (cnt == 0 && *stream_id == -1) {
        return 0;
    }

    size_t total = 0;
    int truncated = 0;
    for (nghttp3_ssize i = 0; i < cnt; i++) {
        size_t take = vec[i].len;
        if (total + take > buflen) {
            take = buflen - total;
            truncated = 1;
        }
        memcpy(buf + total, vec[i].base, take);
        total += take;
        if (truncated) {
            break;
        }
    }

    nghttp3_conn_add_write_offset(c->conn, *stream_id, total);
    *fin = (lfin && !truncated) ? 1 : 0;
    return (int64_t)total;
}

/* Peer aborted its sending side (RESET_STREAM): stop expecting request bytes, release QPACK state. */
int ih3_shutdown_stream_read(ih3_conn *c, int64_t stream_id)
{
    return nghttp3_conn_shutdown_stream_read(c->conn, stream_id);
}

/* Peer refused our response (STOP_SENDING): stop generating output for the stream. The body
 * buffer is NOT dropped here - nghttp3 may still hold references into it for output it already
 * accepted; stream_close (which always follows) is the single free point. */
int ih3_shutdown_stream_write(ih3_conn *c, int64_t stream_id)
{
    nghttp3_conn_shutdown_stream_write(c->conn, stream_id);
    return 0;
}

/* The h3 application error code a library error means, straight from nghttp3 rather than from a
 * table of our own: it owns the NGHTTP3_ERR_* -> RFC 9114 mapping and knows which of its errors are
 * H3_FRAME_ERROR, H3_MESSAGE_ERROR, QPACK_DECOMPRESSION_FAILED and so on. Anything it does not
 * recognise becomes H3_INTERNAL_ERROR, which is the right answer for "we failed and cannot say
 * why". */
uint64_t ih3_app_error_code(int liberr)
{
    return nghttp3_err_infer_quic_app_error_code(liberr);
}

int ih3_close_stream(ih3_conn *c, int64_t stream_id, uint64_t app_error)
{
    int rv = nghttp3_conn_close_stream(c->conn, stream_id, app_error);
    if (rv == NGHTTP3_ERR_STREAM_NOT_FOUND) {
        return 0;   /* uni streams and already-closed streams are not an error */
    }
    return rv;
}

/* Graceful shutdown: queue the GOAWAY pair (shutdown notice + final bound) on the control
 * stream - the next writev drain carries it out - and start rejecting NEW request streams.
 * Streams already in flight are processed normally. */
int ih3_shutdown(ih3_conn *c)
{
    int rv = nghttp3_conn_submit_shutdown_notice(c->conn);
    if (rv != 0) {
        return rv;
    }
    return nghttp3_conn_shutdown(c->conn);
}

/* Nonzero once a shutdown finished draining: every accepted stream has completed. */
int ih3_is_drained(ih3_conn *c)
{
    return nghttp3_conn_is_drained(c->conn);
}

const char *ih3_strerror(int liberr)
{
    return nghttp3_strerror(liberr);
}

const char *ih3_version(void)
{
    const nghttp3_info *info = nghttp3_version(0);
    return info != NULL ? info->version_str : "unknown";
}
