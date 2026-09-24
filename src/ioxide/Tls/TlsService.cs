using System.Runtime.InteropServices;
using System.Security.Cryptography;
using ioxide.utils;

namespace ioxide.tls;

/// <summary>
/// Per-reactor TLS termination. <see cref="AcceptAsync"/> drives the TLS 1.3 handshake through
/// OpenSSL memory BIOs - handshake bytes ride the same ring recv/send as everything else - and
/// hands back the <see cref="TlsSession"/> that carries the connection from there. By default
/// OpenSSL owns both directions: the handler writes through <see cref="TlsSession.Write"/> and
/// passes each ciphertext slice through <see cref="TlsSession.Decrypt"/>. Kernel TLS is opt-in
/// per direction (<see cref="TlsOptions.KernelTx"/> / <see cref="TlsOptions.KernelRx"/>), and the
/// handoff happens here, right after the handshake.
/// </summary>
public sealed class TlsService
{
    private readonly GCHandle _alpnHandle;   // roots the ALPN wire bytes the select callback reads via its arg

    // Everything about the certificates lives behind this one slot, and a rotation replaces it
    // whole. The handle roots the slot so the servername callback can reach it through its arg.
    private readonly CertificateSlot _slot;
    private readonly GCHandle _slotHandle;

    // What a rotation is NOT allowed to change, kept from the options the service started with.
    private readonly TlsOptions _options;

    // Serialises rotations against each other. Readers never take it - they read one reference.
    private readonly Lock _rotation = new();

    /// <summary>
    /// Handshakes still running, oldest first. A queue rather than a set because every entry gets
    /// the same timeout, so insertion order IS deadline order and the sweep can stop at the first
    /// entry that has not expired instead of walking all of them.
    /// </summary>
    private readonly Queue<PendingHandshake> _handshakes = new();

    private sealed class PendingHandshake
    {
        public TcpConnection Conn = null!;
        public long DeadlineMs;
        public bool Done;
    }

    /// <summary>
    /// Closes connections that have been handshaking too long. Runs on the reactor thread from the
    /// reactor's ticker, so it needs no lock and can touch the connection directly.
    /// </summary>
    private void SweepHandshakes()
    {
        long now = Environment.TickCount64;

        while (_handshakes.Count > 0)
        {
            PendingHandshake head = _handshakes.Peek();

            if (head.Done)
            {
                _handshakes.Dequeue();
                continue;
            }

            if (now < head.DeadlineMs)
            {
                return;   // deadlines are in insertion order, so nothing behind this has expired
            }

            _handshakes.Dequeue();
            head.Done = true;

            // Both halves are needed, and neither is redundant.
            //
            // shutdown() is what the PEER sees, and it is also what releases the connection. A
            // TcpConnection is held by two refs, the handler's and the reactor's, and the
            // reactor's is only given up when its multishot recv completes - which for a peer
            // that simply says nothing never happens, so marking the connection closed on its own
            // leaves the socket open for as long as that peer likes, which is the thing being
            // defended against. Shutting the socket down completes that recv with EOF and the
            // ordinary teardown runs.
            //
            // MarkClosed is what wakes the handshake NOW, rather than one io_uring round trip
            // later, with the closed snapshot its loop already knows how to handle.
            Sockets.Shutdown(head.Conn.ClientFd);
            head.Conn.MarkClosed();
        }
    }

    // Identifies this server to OpenSSL's session cache. Any stable value works - what matters is
    // that it is set at all, and that it does not change between the contexts of one service.
    private static readonly byte[] SessionIdContext = "ioxide"u8.ToArray();

    /// <summary>The one suite kTLS can derive kernel keys from; see <see cref="TlsOptions.KernelTx"/>.</summary>
    private const string KernelTlsSuite = "TLS_AES_128_GCM_SHA256";

    private static readonly int SslSessionIndex =
        OpenSsl.CRYPTO_get_ex_new_index(OpenSsl.CRYPTO_EX_INDEX_SSL, 0, 0, 0, 0, 0);

    private TlsService(CertificateSlot slot, GCHandle slotHandle, GCHandle alpnHandle, TlsOptions options)
    {
        _slot = slot;
        _slotHandle = slotHandle;
        _alpnHandle = alpnHandle;
        _options = options;
    }

    /// <summary>The SNI names this service answers for, beside its default certificate.</summary>
    public IReadOnlyCollection<string> ServerNames => _slot.Current.ByHost?.Names ?? [];

    /// <summary>
    /// The certificates in force. Replaced whole rather than edited, so a handshake reads one
    /// coherent set: the default it will answer with, and the alternatives it may pick from.
    /// </summary>
    private sealed class Certificates
    {
        public required nint Default { get; init; }
        public required HostTable? ByHost { get; init; }
    }

    /// <summary>
    /// The one thing both the accept path and the servername callback read, so a rotation has a
    /// single place to publish to and neither can see half of one.
    /// </summary>
    /// <remarks>
    /// The handle rooting this never changes, which is what lets the callback keep the same arg for
    /// the life of the service while the certificates behind it are replaced.
    /// </remarks>
    private sealed class CertificateSlot
    {
        private Certificates _current = null!;

        public Certificates Current
        {
            get => Volatile.Read(ref _current);
            set => Volatile.Write(ref _current, value);
        }
    }

    /// <summary>
    /// The SNI table in the form the handshake reads it: names as the UTF-8 bytes they arrive as,
    /// so choosing one costs a comparison and no allocation on the reactor thread.
    /// </summary>
    /// <remarks>
    /// Scanned linearly. A host serves a handful of names, and walking a few short byte strings
    /// beats hashing one that would have to be decoded into a managed string first - which is the
    /// allocation this shape exists to avoid.
    /// </remarks>
    private sealed class HostTable
    {
        public required byte[][] NamesUtf8 { get; init; }
        public required nint[] Contexts { get; init; }
        public required string[] Names { get; init; }

        /// <summary>The context registered for this name, or 0. Case-insensitive, as DNS is.</summary>
        public nint Find(ReadOnlySpan<byte> name)
        {
            for (int i = 0; i < NamesUtf8.Length; i++)
            {
                ReadOnlySpan<byte> candidate = NamesUtf8[i];

                if (candidate.Length != name.Length)
                {
                    continue;
                }

                int j = 0;
                while (j < name.Length && candidate[j] == Lower(name[j]))
                {
                    j++;
                }

                if (j == name.Length)
                {
                    return Contexts[i];
                }
            }

            return 0;
        }

        // ASCII, which is all a DNS name can hold that has a case at all - the names were folded
        // the same way when the table was built.
        internal static byte Lower(byte c) => (byte)(c is >= (byte)'A' and <= (byte)'Z' ? c - 'A' + 'a' : c);
    }

    /// <summary>A configured name in the form the matcher compares: UTF-8, ASCII-lowercased.</summary>
    private static byte[] Fold(string host)
    {
        byte[] bytes = System.Text.Encoding.UTF8.GetBytes(host);

        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = HostTable.Lower(bytes[i]);
        }

        return bytes;
    }

    /// <summary>Create the per-reactor service and register it. Call from <c>Reactor.OnStart</c>.</summary>
    /// <param name="register">
    /// When false the service is not registered on the reactor - for hosts that run SEVERAL TLS
    /// contexts on one reactor (one per listen port, say) and hold the instances themselves.
    /// <see cref="Reactor.GetService{T}"/> only ever returns the last registered one.
    /// </param>
    public static TlsService Start(Reactor reactor, TlsOptions options, bool register = true)
    {
        // Scalars first, because the checks below reason about COMBINATIONS and a value outside its
        // own domain makes that reasoning meaningless. Both of these resolve to something plausible
        // rather than failing, which is the shape worth refusing: an undefined version maps to the
        // TLS 1.2 floor through a not-Tls13 ternary, and a negative timeout disables the handshake
        // sweep entirely because both readers guard on "> 0" - so the one bound on a peer that
        // connects and then says nothing is silently off. No config binder validates an enum
        // (Enum.Parse<TlsProtocolVersion>("3") succeeds), so neither value needs a cast to arrive.
        if (!Enum.IsDefined(options.MinProtocolVersion))
        {
            throw new ArgumentException(
                $"MinProtocolVersion is {(int)options.MinProtocolVersion}, which is not one of "
                + "Default, Tls12 or Tls13. Name the floor you want rather than leaving it to be "
                + "resolved.", nameof(options));
        }

        if (options.HandshakeTimeoutMs < 0)
        {
            throw new ArgumentException(
                $"HandshakeTimeoutMs is {options.HandshakeTimeoutMs}. Zero disables the handshake "
                + "sweep; a negative value would disable it too, which is worth saying rather than "
                + "arriving at by accident.", nameof(options));
        }

        // Each connection's read pump builds a Pipe from these, and a Pipe refuses them - inside
        // the handler, on every accept. Refused once here instead.
        if (options.InboundPauseBytes < 0 || options.InboundResumeBytes < 0
            || (options.InboundPauseBytes > 0 && options.InboundResumeBytes > options.InboundPauseBytes))
        {
            throw new ArgumentException(
                $"InboundPauseBytes is {options.InboundPauseBytes} and InboundResumeBytes is "
                + $"{options.InboundResumeBytes}. Neither may be negative, and the pump cannot start "
                + "again above the level it stops at.", nameof(options));
        }

        // RX alone cannot be programmed: the handoff shares the TCP_ULP that EnableTx installs.
        // Refuse loudly rather than silently serving the userspace path the caller opted out of.
        if (options.KernelRx && !options.KernelTx)
        {
            throw new ArgumentException(
                "KernelRx requires KernelTx: kTLS RX is programmed at the same handoff as TX. " +
                "Set KernelTx = true as well, or drop KernelRx.", nameof(options));
        }

        // kTLS derives its keys from one specific suite over TLS 1.3, so it PINS both. A caller
        // who also states a floor of 1.2, or a suite list of their own, has asked for two
        // incompatible things - named here rather than resolved by whichever line runs last.
        if (options.KernelTx && options.MinProtocolVersion == TlsProtocolVersion.Tls12)
        {
            throw new ArgumentException(
                "KernelTx negotiates TLS 1.3 only, so MinProtocolVersion = Tls12 cannot hold. " +
                "Drop one of the two.", nameof(options));
        }

        // kTLS derives its keys from exactly one suite, so a list that STATES that suite agrees
        // with the mode rather than contradicting it - and stating the posture out loud is the
        // thing this option exists for. Only a list that asks for something else is refused.
        if (options.KernelTx && options.CipherSuites is not null
            && options.CipherSuites.Trim() != KernelTlsSuite)
        {
            throw new ArgumentException(
                $"KernelTx requires exactly {KernelTlsSuite} to derive kernel keys, so CipherSuites "
                + $"cannot ask for anything else. Set it to \"{KernelTlsSuite}\", or drop one of the two.",
                nameof(options));
        }

        // The certificate and key each come from exactly one place - a path or in-memory PEM.
        // Neither set (possible now that the path is not `required`) and both set are refused.
        TlsCertificate defaultCertificate = new()
        {
            CertificatePath = options.CertificatePath,
            CertificatePem = options.CertificatePem,
            KeyPath = options.KeyPath,
            KeyPem = options.KeyPem,
        };

        // Client anchors are optional, but two sources for them is a mistake worth naming rather
        // than resolving by precedence.
        if (options.ClientCaPath is not null && options.ClientCaPem is not null)
        {
            throw new ArgumentException(
                "At most one client CA source: set ClientCaPath or ClientCaPem, not both.", nameof(options));
        }

        // Requiring a certificate with nothing to validate it against would refuse every client
        // that sends none and accept any that sends anything - the opposite of what it reads as.
        if (options.RequireClientCertificate && options.ClientCaPath is null && options.ClientCaPem is null)
        {
            throw new ArgumentException(
                "RequireClientCertificate needs trust anchors: set ClientCaPath or ClientCaPem.", nameof(options));
        }

        byte[] alpnWire = BuildAlpnWire(options.Alpn);
        GCHandle alpnHandle = GCHandle.Alloc(alpnWire);

        var slot = new CertificateSlot();
        GCHandle slotHandle = GCHandle.Alloc(slot);

        try
        {
            slot.Current = BuildCertificates(options, defaultCertificate, options.CertificatesByHost, alpnHandle, slotHandle);
        }
        catch
        {
            // Start fails on ordinary operational input - a PEM caught half-written by a renewal,
            // a path that is not readable yet - and a supervisor retries it. Leaking two handles
            // per attempt is the same shape as the rotation leak already fixed one layer down.
            alpnHandle.Free();
            slotHandle.Free();
            throw;
        }

        var service = new TlsService(slot, slotHandle, alpnHandle, options);
        if (options.HandshakeTimeoutMs > 0)
        {
            reactor.AddTicker(service.SweepHandshakes);
        }
        if (register)
        {
            reactor.AddService(service);
        }
        return service;
    }

    /// <summary>
    /// Replaces the certificates this service serves, on a running server. New connections are
    /// answered with them from the next handshake; connections already established keep the
    /// certificate they were given, which is what they authenticated.
    /// </summary>
    /// <param name="defaultCertificate">
    /// The certificate for a client that sends no name, or asks for one not in
    /// <paramref name="certificatesByHost"/>.
    /// </param>
    /// <param name="certificatesByHost">The certificates chosen by name, or null for none.</param>
    /// <remarks>
    /// What renewal needs: an ACME client rewrites its PEM every couple of months, and without this
    /// the only way to serve the new one is to restart. The protocol floor, ALPN and kTLS are what
    /// the service started with and cannot be changed here, since those decide how a connection
    /// behaves rather than which certificate it is shown.
    ///
    /// One thing DOES follow the disk, and it is worth knowing before automating this. Client trust
    /// anchors given as <see cref="TlsOptions.ClientCaPath"/> are re-read from that path on every
    /// rotation, so an edit to the CA bundle takes effect at the next renewal rather than at the
    /// next restart - revoking an issuer that way is possible, and so is widening who may connect
    /// without meaning to. It reads from the path deliberately: the alternative is holding the
    /// bundle from startup, which would also drop the issuer list sent in the CertificateRequest
    /// and so break clients that hold several certificates and pick by it. Anchors given as
    /// <see cref="TlsOptions.ClientCaPem"/> are data, and do not move.
    ///
    /// This service belongs to ONE reactor. A server with several rotates each of them, and a
    /// reactor that is missed keeps serving the old certificate on its share of the connections -
    /// they all listen on the same port through SO_REUSEPORT, so which one a client reaches is not
    /// something the client chooses.
    ///
    /// Everything is built before anything is published, so a bad path or an unreadable key throws
    /// and LEAVES THE SERVICE SERVING WHAT IT WAS. A failed rotation is a server that kept working.
    ///
    /// Call it from anywhere; it takes a lock against other rotations, and the handshake path never
    /// does. Each read of the certificates is one reference load, so no handshake sees half a set.
    /// A connection that is already running when a rotation lands can still take its default from
    /// the old set and a named certificate from the new one, since it reads them at two different
    /// moments - harmless, because every set is built from the same options and differs only in
    /// certificate material, which is exactly why this method is not allowed to change anything else.
    ///
    /// The contexts it replaces are kept, not freed. A handshake may be between reading the table
    /// and using what it found, and OpenSSL gives no way to wait that out - so they are retained
    /// for the life of the service, as its contexts already were. A rotation is an operational
    /// event, not a hot path; rotating a handful of names a few times a year costs kilobytes.
    /// </remarks>
    public void ReplaceCertificates(TlsCertificate defaultCertificate,
        IReadOnlyDictionary<string, TlsCertificate>? certificatesByHost = null)
    {
        ArgumentNullException.ThrowIfNull(defaultCertificate);

        lock (_rotation)
        {
            _slot.Current = BuildCertificates(_options, defaultCertificate, certificatesByHost, _alpnHandle, _slotHandle);
        }
    }

    /// <summary>
    /// One coherent set of contexts: the default, the alternatives by name, and the servername
    /// callback wired to the slot when there are any.
    /// </summary>
    /// <remarks>
    /// Used to start the service and to rotate it, so a rotated context is built exactly the way
    /// the first one was - the parity between the two paths is not something to maintain twice.
    /// </remarks>
    private static Certificates BuildCertificates(TlsOptions options, TlsCertificate defaultCertificate,
        IReadOnlyDictionary<string, TlsCertificate>? certificatesByHost, GCHandle alpnHandle, GCHandle slotHandle)
    {
        RequireOneSourceEach(defaultCertificate, "");

        nint ctx = 0;
        HostTable? byHost = null;

        try
        {
            ctx = NewContext(options, defaultCertificate, "", alpnHandle);

            byHost = BuildHostContexts(options, certificatesByHost, alpnHandle);

            if (byHost is not null)
            {
                unsafe
                {
                    // Checked, because the failure is silent otherwise: an unregistered callback means
                    // every name is answered with the default certificate, which looks like a working
                    // server serving the wrong certificate rather than one that failed to start.
                    delegate* unmanaged<nint, nint, nint, int> servername = &ServerNameCallback;

                    if (OpenSsl.SSL_CTX_callback_ctrl(ctx, OpenSsl.SSL_CTRL_SET_TLSEXT_SERVERNAME_CB, (nint)servername) != 1 ||
                        OpenSsl.SSL_CTX_ctrl(ctx, OpenSsl.SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG, 0, GCHandle.ToIntPtr(slotHandle)) != 1)
                    {
                        throw new IOException($"could not install the SNI callback: {OpenSsl.LastError()}");
                    }
                }
            }
        }
        catch
        {
            // Nothing here was ever published, so nothing can hold a reference to it and freeing is
            // safe - unlike the contexts a rotation REPLACES, which are deliberately kept. Without
            // this a renewal retried against a half-written PEM leaks a certificate and key per
            // attempt, for as long as it keeps retrying.
            Release(ctx, byHost);
            throw;
        }

        return new Certificates { Default = ctx, ByHost = byHost };
    }

    /// <summary>Drops contexts that were built and never published.</summary>
    private static void Release(nint ctx, HostTable? byHost)
    {
        if (ctx != 0)
        {
            OpenSsl.SSL_CTX_free(ctx);
        }

        foreach (nint hostCtx in byHost?.Contexts ?? [])
        {
            OpenSsl.SSL_CTX_free(hostCtx);
        }
    }

    /// <summary>
    /// One OpenSSL context per SNI name, built here so that selecting one at handshake time is a
    /// lookup and nothing more. Null when no alternatives were configured.
    /// </summary>
    /// <remarks>
    /// Swapping to one of these changes the certificate and nothing else, but NOT because every
    /// setting is repeated here - the two halves are worth telling apart, because only one of them
    /// is load-bearing:
    ///
    /// Settings OpenSSL copies into the SSL when it is created, from the DEFAULT context, and never
    /// re-reads: the verify mode, SSL_OP_* options, min/max protocol version, and the ticket count.
    /// A swap cannot touch these, so a host context cannot weaken them - it is why SNI cannot be
    /// used to escape mutual TLS or the kTLS protocol floor. Setting them below is inert.
    ///
    /// Settings a host context therefore has to carry itself, because OpenSSL takes them from it:
    /// the client trust anchors and CA list, and the ALPN and keylog callbacks, each read back off
    /// the context after the swap - and EVERYTHING IN ITS CERT, which the swap duplicates wholesale
    /// over the connection's own. That is the certificate and key, and with them the security
    /// level, the signature-algorithm lists, and the certificate callback. Omitting any of these
    /// changes how the connection behaves: dropping the anchors would fail every mutual-TLS client
    /// of a named host, and a security level or sigalg list configured only on the default would be
    /// silently reset to OpenSSL's own for every named one.
    ///
    /// That split is the invariant to preserve: anything added to the default context in future
    /// belongs in the second group unless it is known to be in the first.
    ///
    /// One thing neither group covers, because the swap cannot reach it: the session cache and the
    /// ticket keys, which come from the context the connection was CREATED from. Every host shares
    /// the default's, so a resumption ticket is not bound to the name it was issued under. Harmless
    /// while every host is verified alike - no certificate is sent on a resumption at all, and
    /// clients key their own caches by name - but it is the thing to close before any per-host
    /// policy is added here, and per-host session id contexts are NOT the way to close it: the
    /// ticket is accepted while parsing extensions, before this callback runs at all.
    ///
    /// A name is stored lowercase: SNI is a DNS name and DNS is case-insensitive, and a client
    /// asking for EXAMPLE.COM means the same host as one asking for example.com.
    /// </remarks>
    private static HostTable? BuildHostContexts(TlsOptions options,
        IReadOnlyDictionary<string, TlsCertificate>? certificatesByHost, GCHandle alpnHandle)
    {
        if (certificatesByHost is not { Count: > 0 } certificates)
        {
            return null;
        }

        var names = new string[certificates.Count];
        var namesUtf8 = new byte[certificates.Count][];
        var contexts = new nint[certificates.Count];
        int next = 0;

        try
        {
        foreach ((string host, TlsCertificate certificate) in certificates)
        {
            if (string.IsNullOrWhiteSpace(host))
            {
                throw new ArgumentException("A blank host cannot be asked for by SNI.");
            }

            RequireOneSourceEach(certificate, $" for '{host}'");

            // Folded the SAME way the handshake folds the name it receives - ASCII only. Using
            // ToLowerInvariant here instead would fold letters the matcher does not (a Unicode
            // uppercase, the Kelvin sign), and the entry would sit in the table unreachable.
            //
            // Checked before a context is built rather than after, so a rejected entry has not
            // already allocated one that nothing will ever free.
            byte[] folded = Fold(host);

            for (int i = 0; i < next; i++)
            {
                if (namesUtf8[i].AsSpan().SequenceEqual(folded))
                {
                    throw new ArgumentException(
                        $"Two certificates for the same host '{names[i]}': names are matched " +
                        "case-insensitively, so only the first would ever be served.");
                }
            }

            nint hostCtx = NewContext(options, certificate, $" for '{host}'", alpnHandle);

            names[next] = System.Text.Encoding.UTF8.GetString(folded);
            namesUtf8[next] = folded;
            contexts[next] = hostCtx;
            next++;
        }

        }
        catch
        {
            // The entries built before the bad one. Unpublished, so nothing holds them - and a
            // rotation that throws half way through a table would otherwise leak every context it
            // had already built.
            for (int i = 0; i < next; i++)
            {
                OpenSsl.SSL_CTX_free(contexts[i]);
            }

            throw;
        }

        return new HostTable { Names = names, NamesUtf8 = namesUtf8, Contexts = contexts };
    }

    /// <summary>
    /// One configured OpenSSL context. The default certificate and every SNI alternative are built
    /// HERE and nowhere else.
    /// </summary>
    /// <remarks>
    /// That is the point of the method rather than a tidiness argument. A per-host context has to
    /// carry everything OpenSSL reads back off the context after a handshake swaps to it, and the
    /// two were previously configured by two pieces of code that had to be kept in step by hand -
    /// so a setting added to one and forgotten on the other would apply to clients that sent no
    /// name and silently not to clients that did. Built from one body, they cannot drift.
    ///
    /// <paramref name="what"/> names the offender in any error - empty for the default certificate,
    /// " for 'host'" for an alternative.
    /// </remarks>
    private static nint NewContext(TlsOptions options, TlsCertificate certificate, string what, GCHandle alpnHandle)
    {
        nint ctx = OpenSsl.SSL_CTX_new(OpenSsl.TLS_server_method());
        if (ctx == 0)
        {
            throw new IOException($"SSL_CTX_new{what}: {OpenSsl.LastError()}");
        }

        try
        {
            Configure(ctx, options, certificate, what, alpnHandle);
        }
        catch
        {
            // The context is this method's to release until it returns one. A caller cannot do it:
            // the assignment it would free through never happened, which is exactly how a renewal
            // retried against a half-written PEM leaked a certificate and key per attempt.
            OpenSsl.SSL_CTX_free(ctx);
            throw;
        }

        return ctx;
    }

    /// <summary>Everything a context needs beyond existing. Separate so the allocation above has
    /// exactly one owner and one release path.</summary>
    private static void Configure(nint ctx, TlsOptions options, TlsCertificate certificate, string what, GCHandle alpnHandle)
    {
        // Before any key is read. OpenSSL's default passphrase callback is PEM_def_callback, which
        // reads the TERMINAL - so an encrypted key makes Start, or ReplaceCertificates on a
        // rotation thread while the server is still answering, block on a prompt rather than fail.
        // TlsOptions has no passphrase, so the only correct answer is that none is available, which
        // turns a hang into the ordinary refusal every other unusable key already gets.
        unsafe
        {
            delegate* unmanaged<nint, int, int, nint, int> refuse = &NoPassphrase;
            OpenSsl.SSL_CTX_set_default_passwd_cb(ctx, (nint)refuse);
        }


        // OpenSSL copies a context's options onto each SSL as it is created and never re-reads
        // them, so this holds for every connection whether or not it asked for a name. TLS 1.3 has
        // no renegotiation to refuse; over TLS 1.2 refusing it costs nothing anyone uses and takes
        // away a second ClientHello - which, with SNI, would be a second go at the certificate.
        OpenSsl.SSL_CTX_set_options(ctx, OpenSsl.SSL_OP_NO_RENEGOTIATION);

        // Caller-stated posture first; the kTLS block below then pins what it must, and Start has
        // already refused the combinations where the two would disagree.
        if (options.MinProtocolVersion != TlsProtocolVersion.Default)
        {
            long floor = options.MinProtocolVersion == TlsProtocolVersion.Tls13
                ? OpenSsl.TLS1_3_VERSION
                : OpenSsl.TLS1_2_VERSION;

            if (OpenSsl.SSL_CTX_ctrl(ctx, OpenSsl.SSL_CTRL_SET_MIN_PROTO_VERSION, floor, 0) != 1)
            {
                throw new IOException($"set_min_proto_version{what}: {OpenSsl.LastError()}");
            }
        }

        if (options.CipherSuites is { } suites)
        {
            // OpenSSL is no help here on its own. It accepts an EMPTY 1.3 list and returns success,
            // which leaves no TLS 1.3 suite enabled at all - so with a 1.3 floor the server starts
            // clean and fails every handshake. And it ignores names it does not know as long as one
            // in the list is valid, so a single typo silently drops the suite the operator meant to
            // pin. Neither shows up until a client cannot connect, and neither is a mistake the
            // caller can see. Note CipherList (1.2) behaves the opposite way and refuses both.
            //
            // Each name is offered on its own first, because a one-name list that OpenSSL does not
            // recognise IS an all-unknown list, which it does refuse. The full list is applied
            // afterwards so ordering is the caller's.
            string[] names = suites.Split(':', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (names.Length == 0)
            {
                throw new IOException(
                    $"CipherSuites{what} is empty, which disables every TLS 1.3 suite. Leave it null for the default.");
            }

            foreach (string name in names)
            {
                if (OpenSsl.SSL_CTX_set_ciphersuites(ctx, name) != 1)
                {
                    OpenSsl.ERR_clear_error();
                    throw new IOException($"set_ciphersuites{what}: OpenSSL does not know the suite '{name}'.");
                }
            }

            if (OpenSsl.SSL_CTX_set_ciphersuites(ctx, suites) != 1)
            {
                throw new IOException($"set_ciphersuites{what}: {OpenSsl.LastError()}");
            }
        }

        // Empty is not "no restriction" - it is a list nothing matches, which would fail every
        // TLS 1.2 handshake at the point of use rather than here.
        if (options.CipherList is { } ciphers && OpenSsl.SSL_CTX_set_cipher_list(ctx, ciphers) != 1)
        {
            throw new IOException($"set_cipher_list{what}: {OpenSsl.LastError()}");
        }

        // A stated list is documented as being in preference order, and OpenSSL's default is to let
        // the CLIENT's order win - so without this the operator's order was decoration. Set only
        // when they actually stated one: with no list configured the default order is OpenSSL's to
        // choose, and forcing server preference there would change which suite existing clients
        // negotiate for no one's benefit.
        if (options.CipherSuites is not null || options.CipherList is not null)
        {
            OpenSsl.SSL_CTX_set_options(ctx, OpenSsl.SSL_OP_CIPHER_SERVER_PREFERENCE);
        }

        // The kTLS constraints are the kernel path's, not TLS's - so they apply only when the
        // kernel path was asked for. The default keeps OpenSSL's own defaults: TLS 1.2 and 1.3,
        // any ciphersuite, session tickets on. This is the table in TlsOptions.KernelTx made true.
        if (options.KernelTx)
        {
            // TLS 1.3 only, one suite: kTLS needs AES-128-GCM keys and a known layout.
            OpenSsl.SSL_CTX_ctrl(ctx, OpenSsl.SSL_CTRL_SET_MIN_PROTO_VERSION, OpenSsl.TLS1_3_VERSION, 0);
            OpenSsl.SSL_CTX_ctrl(ctx, OpenSsl.SSL_CTRL_SET_MAX_PROTO_VERSION, OpenSsl.TLS1_3_VERSION, 0);
            if (OpenSsl.SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256") != 1)
            {
                throw new IOException($"set_ciphersuites{what}: {OpenSsl.LastError()}");
            }

            // No session tickets: they would consume record sequence numbers after the
            // handshake and break the kTLS handoff (which programs the record sequence).
            OpenSsl.SSL_CTX_set_num_tickets(ctx, 0);
        }

        LoadCertificate(ctx, certificate, what);
        ConfigureClientVerification(ctx, options);

        // Scope sessions to this server. Required rather than tidy: with SSL_VERIFY_PEER set and no
        // id context, OpenSSL treats a resumption attempt as fatal to the whole HANDSHAKE, not just
        // to the resumption - so an mTLS port issues tickets and then refuses every client that
        // comes back with one, which is roughly every second connection from anything that caches.
        // Constant per process: every context of this service must accept the others' tickets, or a
        // rotation would invalidate every outstanding session.
        unsafe
        {
            fixed (byte* id = SessionIdContext)
            {
                if (OpenSsl.SSL_CTX_set_session_id_context(ctx, id, (uint)SessionIdContext.Length) != 1)
                {
                    throw new IOException($"could not set the session id context{what}: {OpenSsl.LastError()}");
                }
            }
        }

        unsafe
        {
            // Only the kernel path consumes these, and the callback necessarily materialises each
            // traffic secret as an immutable managed string that nothing can scrub afterwards - it
            // outlives the byte[] this code is careful to zero, and lands in any core dump. So it
            // is registered where it is used rather than on every context. (KernelRx is refused
            // without KernelTx, so this covers both.)
            if (options.KernelTx)
            {
                delegate* unmanaged<nint, nint, void> keylog = &KeylogCallback;
                OpenSsl.SSL_CTX_set_keylog_callback(ctx, (nint)keylog);
            }

            // ALPN is settled against whichever context the handshake ends on, so every context
            // needs the callback - reading the same wire bytes through the same handle.
            delegate* unmanaged<nint, nint, nint, nint, uint, nint, int> alpn = &AlpnSelectCallback;
            OpenSsl.SSL_CTX_set_alpn_select_cb(ctx, (nint)alpn, GCHandle.ToIntPtr(alpnHandle));
        }
    }

    /// <summary>
    /// Exactly one source for the certificate and exactly one for the key. Neither set is as wrong
    /// as both: one is an entry nobody finished, the other two answers to one question.
    /// </summary>
    private static void RequireOneSourceEach(TlsCertificate certificate, string what)
    {
        if ((certificate.CertificatePath is null) == (certificate.CertificatePem is null))
        {
            throw new ArgumentException(
                $"Exactly one certificate source{what}: set CertificatePath or CertificatePem.");
        }

        if ((certificate.KeyPath is null) == (certificate.KeyPem is null))
        {
            throw new ArgumentException(
                $"Exactly one key source{what}: set KeyPath or KeyPem.");
        }
    }

    /// <summary>
    /// Picks the certificate for the name the client asked for, mid-handshake.
    /// </summary>
    /// <remarks>
    /// An unknown name, or none at all, leaves the default context in place and the handshake
    /// continues - the client then decides whether the certificate it got will do. Aborting here
    /// instead would break every client reaching this server by address or by an alias nobody
    /// listed, and would report it as a dead connection rather than a certificate mismatch.
    ///
    /// A name that WAS matched returns OK, and any other outcome returns NOACK. The difference is
    /// what the server says about it: OK acknowledges the extension, so OpenSSL echoes the name
    /// back and records it on the session. Acknowledging a name this server does not hold would be
    /// claiming one it cannot serve (RFC 6066 3), and would file the client's own string against
    /// the session. NOACK declines the extension WITHOUT failing the handshake, which is exactly
    /// the "answer with the default" behaviour above.
    ///
    /// Runs on the reactor thread. The lookup allocates nothing: the name is compared as UTF-8
    /// bytes already in native memory, against a table built when the service started.
    /// </remarks>
    /// <summary>
    /// "There is no passphrase." Zero written bytes makes OpenSSL fail the key load with an
    /// ordinary error rather than prompting on the terminal, which is what it does when no
    /// callback is installed at all.
    /// </summary>
    [UnmanagedCallersOnly]
    private static int NoPassphrase(nint buf, int size, int rwflag, nint userdata) => 0;

    [UnmanagedCallersOnly]
    private static unsafe int ServerNameCallback(nint ssl, nint alert, nint arg)
    {
        try
        {
            // Read once, through the slot, so a rotation replacing the table mid-handshake is
            // either wholly before this read or wholly after it.
            if (arg == 0 || GCHandle.FromIntPtr(arg).Target is not CertificateSlot slot
                || slot.Current.ByHost is not { } byHost)
            {
                return OpenSsl.SSL_TLSEXT_ERR_NOACK;
            }

            nint namePtr = OpenSsl.SSL_get_servername(ssl, OpenSsl.TLSEXT_NAMETYPE_host_name);
            if (namePtr == 0)
            {
                // No SNI extension. The default certificate is the answer, which is what it is for.
                return OpenSsl.SSL_TLSEXT_ERR_NOACK;
            }

            // OpenSSL's own copy of the name, NUL-terminated and valid for this handshake - read
            // where it lies rather than decoded into a string only to be thrown away. OpenSSL has
            // already refused an over-long name and one carrying a NUL, so the span is bounded.
            nint hostCtx = byHost.Find(MemoryMarshal.CreateReadOnlySpanFromNullTerminated((byte*)namePtr));

            if (hostCtx == 0)
            {
                return OpenSsl.SSL_TLSEXT_ERR_NOACK;
            }

            // Fails only when the certificate cannot be duplicated, and the default context is
            // still a working answer - but then this name was NOT the one being served, so it must
            // not be acknowledged as though it were.
            if (OpenSsl.SSL_set_SSL_CTX(ssl, hostCtx) == 0)
            {
                return OpenSsl.SSL_TLSEXT_ERR_NOACK;
            }
        }
        catch
        {
            // A throw here would cross native frames. The default certificate is a working answer,
            // so failing to select a better one is not a reason to lose the connection.
            return OpenSsl.SSL_TLSEXT_ERR_NOACK;
        }

        return OpenSsl.SSL_TLSEXT_ERR_OK;
    }

    /// <summary>
    /// Client-certificate verification. Does nothing unless anchors are configured, so the
    /// handshake for everyone else is byte-for-byte what it was.
    /// </summary>
    /// <remarks>
    /// This is a property of the SSL_CTX and therefore of the port: TLS settles client
    /// authentication during the handshake, and while TLS 1.3 has post-handshake authentication,
    /// nothing here uses it. A route that wants to authenticate reads
    /// <see cref="TlsSession.PeerSubject"/> from a handshake that already happened.
    ///
    /// Orthogonal to kTLS. The certificate is exchanged and validated during the handshake, which
    /// OpenSSL performs either way - the kernel only takes over record crypto afterwards - so this
    /// composes with <see cref="TlsOptions.KernelTx"/> and <see cref="TlsOptions.KernelRx"/>
    /// unchanged.
    /// </remarks>
    private static unsafe void ConfigureClientVerification(nint ctx, TlsOptions options)
    {
        if (options.ClientCaPath is null && options.ClientCaPem is null)
        {
            return;
        }

        if (options.ClientCaPath is not null)
        {
            if (OpenSsl.SSL_CTX_load_verify_locations(ctx, options.ClientCaPath, null) != 1)
            {
                throw new IOException(
                    $"could not load client CA '{options.ClientCaPath}': {OpenSsl.LastError()}");
            }

            // Tell the client which issuers we accept. Failure here is not fatal - it costs the
            // hint, not the verification - so a CA file OpenSSL can trust but not enumerate still
            // works for a client with a single certificate.
            nint names = OpenSsl.SSL_load_client_CA_file(options.ClientCaPath);
            if (names != 0)
            {
                OpenSsl.SSL_CTX_set_client_CA_list(ctx, names);
            }
            else
            {
                OpenSsl.ERR_clear_error();
            }
        }
        else
        {
            AddTrustAnchorsPem(ctx, options.ClientCaPem!);
        }

        int mode = OpenSsl.SSL_VERIFY_PEER;
        if (options.RequireClientCertificate)
        {
            mode |= OpenSsl.SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        }

        // No callback: a chain that does not validate fails the handshake. There is no prompt to
        // fall back to and no partial trust worth inventing.
        OpenSsl.SSL_CTX_set_verify(ctx, mode, 0);
    }

    // Trust anchors from PEM text, added straight to the context's store - the in-memory mirror of
    // load_verify_locations, for hosts that carry a CA bundle as data rather than as a file.
    private static unsafe void AddTrustAnchorsPem(nint ctx, string pem)
    {
        nint store = OpenSsl.SSL_CTX_get_cert_store(ctx);
        if (store == 0)
        {
            throw new IOException($"SSL_CTX_get_cert_store: {OpenSsl.LastError()}");
        }

        byte[] bytes = System.Text.Encoding.ASCII.GetBytes(pem);
        int added = 0;

        fixed (byte* p = bytes)
        {
            nint bio = OpenSsl.BIO_new_mem_buf(p, bytes.Length);
            if (bio == 0)
            {
                throw new IOException($"BIO_new_mem_buf: {OpenSsl.LastError()}");
            }

            try
            {
                while (true)
                {
                    nint cert = OpenSsl.PEM_read_bio_X509(bio, 0, 0, 0);
                    if (cert == 0)
                    {
                        // Exhausted, or stopped on a malformed block. Only the first is an end of
                        // bundle: stopping early on the second would trust the anchors BEFORE the
                        // bad block and silently drop everything after it, so clients issued by a
                        // later anchor are refused with nothing said server-side. The file route
                        // refuses such a bundle outright, and TlsOptions documents the two sources
                        // as equivalent.
                        if (!OpenSsl.ErrorIsEndOfPem())
                        {
                            throw new IOException(
                                $"ClientCaPem is malformed after {added} usable certificate(s); "
                                + "the rest of the bundle would have been ignored.");
                        }

                        break;
                    }

                    int ok = OpenSsl.X509_STORE_add_cert(store, cert);

                    // Same issuer hint the file route sends. Without it a client holding several
                    // certificates has nothing to choose by and offers whichever comes first, so
                    // the two anchor sources would accept different populations of client - which
                    // is not something the choice between a path and PEM text should decide.
                    // Not fatal on failure: it costs the hint, not the verification.
                    if (ok == 1 && OpenSsl.SSL_CTX_add_client_CA(ctx, cert) != 1)
                    {
                        OpenSsl.ERR_clear_error();
                    }

                    OpenSsl.X509_free(cert);   // the store and the CA list took their own references

                    if (ok != 1)
                    {
                        throw new IOException($"X509_STORE_add_cert: {OpenSsl.LastError()}");
                    }
                    added++;
                }
            }
            finally
            {
                OpenSsl.BIO_free(bio);
            }
        }

        // Running off the end of the last certificate leaves a "no start line" error behind.
        OpenSsl.ERR_clear_error();

        if (added == 0)
        {
            throw new IOException("ClientCaPem contained no certificates.");
        }
    }

    // Certificate and key, from whichever source the caller carries. The file route is OpenSSL's
    // own loaders; the in-memory route reads the same PEM through a memory BIO. Which of the two
    // is set was settled by RequireOneSourceEach before any context existed.
    private static void LoadCertificate(nint ctx, TlsCertificate certificate, string what)
    {
        if (certificate.CertificatePath is not null)
        {
            if (OpenSsl.SSL_CTX_use_certificate_chain_file(ctx, certificate.CertificatePath) != 1)
            {
                throw new IOException($"certificate{what} '{certificate.CertificatePath}': {OpenSsl.LastError()}");
            }
        }
        else
        {
            LoadCertificatePem(ctx, certificate.CertificatePem!);
        }

        if (certificate.KeyPath is not null)
        {
            if (OpenSsl.SSL_CTX_use_PrivateKey_file(ctx, certificate.KeyPath, OpenSsl.SSL_FILETYPE_PEM) != 1)
            {
                throw new IOException($"private key{what} '{certificate.KeyPath}': {OpenSsl.LastError()}");
            }
        }
        else
        {
            LoadKeyPem(ctx, certificate.KeyPem!);
        }

        // The pair has to be checked explicitly, because OpenSSL only checks it for us when the two
        // land in the SAME algorithm slot. A certificate and key that are both RSA and unrelated
        // are refused by use_PrivateKey itself - but an RSA certificate with an EC key is not: the
        // key goes into the EC slot, which has no certificate, and the RSA slot keeps a certificate
        // with no key. Nothing complains, the server starts, and every handshake afterwards fails
        // with no shared cipher. That is the shape of an operator moving a server from RSA to EC
        // and updating one of the two files.
        if (OpenSsl.SSL_CTX_check_private_key(ctx) != 1)
        {
            OpenSsl.ERR_clear_error();
            throw new IOException(
                $"the certificate and private key{what} do not go together - a certificate of one "
                + "algorithm with a key of another leaves the context with neither a usable pair.");
        }
    }

    private static unsafe void LoadCertificatePem(nint ctx, string pem)
    {
        byte[] bytes = System.Text.Encoding.ASCII.GetBytes(pem);
        fixed (byte* p = bytes)
        {
            // The memory BIO reads the pinned buffer in place, so the fixed block spans every read.
            nint bio = OpenSsl.BIO_new_mem_buf(p, bytes.Length);
            if (bio == 0)
            {
                throw new IOException($"CertificatePem: {OpenSsl.LastError()}");
            }

            try
            {
                // First PEM block is the leaf; use_certificate takes its own reference.
                nint leaf = OpenSsl.PEM_read_bio_X509(bio, 0, 0, 0);
                if (leaf == 0)
                {
                    throw new IOException($"CertificatePem carries no certificate: {OpenSsl.LastError()}");
                }
                int ok = OpenSsl.SSL_CTX_use_certificate(ctx, leaf);
                OpenSsl.X509_free(leaf);
                if (ok != 1)
                {
                    throw new IOException($"CertificatePem: {OpenSsl.LastError()}");
                }

                // Any further blocks are the chain, closest-to-leaf first, exactly as in a chain
                // file. add_extra_chain_cert takes ownership on success, so no free there.
                while (true)
                {
                    nint extra = OpenSsl.PEM_read_bio_X509(bio, 0, 0, 0);
                    if (extra == 0)
                    {
                        // Exhausted, or stopped on a malformed block - the same distinction
                        // AddTrustAnchorsPem makes, and for a worse reason here. Reading both as
                        // end-of-data publishes the leaf with the chain silently cut at the tear,
                        // ReplaceCertificates returns normally, SSL_CTX_check_private_key passes
                        // (the leaf does match the key), and every client that needs the missing
                        // intermediate fails path-building while the operator's only signal - did
                        // the rotation throw - says it went fine. A renewal read mid-write is the
                        // ordinary way to produce exactly this file. SSL_CTX_use_certificate_chain_file,
                        // which the path route uses and this mirrors, refuses it outright.
                        if (!OpenSsl.ErrorIsEndOfPem())
                        {
                            throw new IOException(
                                "CertificatePem is malformed after the leaf; the rest of the chain "
                                + "would have been ignored and the certificate served without it.");
                        }

                        OpenSsl.ERR_clear_error();   // end-of-data queues PEM_R_NO_START_LINE
                        break;
                    }
                    if (OpenSsl.SSL_CTX_ctrl(ctx, OpenSsl.SSL_CTRL_EXTRA_CHAIN_CERT, 0, extra) != 1)
                    {
                        OpenSsl.X509_free(extra);
                        throw new IOException($"CertificatePem chain: {OpenSsl.LastError()}");
                    }
                }
            }
            finally
            {
                OpenSsl.BIO_free(bio);
            }
        }
    }

    private static unsafe void LoadKeyPem(nint ctx, string pem)
    {
        byte[] bytes = System.Text.Encoding.ASCII.GetBytes(pem);
        fixed (byte* p = bytes)
        {
            nint bio = OpenSsl.BIO_new_mem_buf(p, bytes.Length);
            if (bio == 0)
            {
                throw new IOException($"KeyPem: {OpenSsl.LastError()}");
            }

            try
            {
                nint key = OpenSsl.PEM_read_bio_PrivateKey(bio, 0, 0, 0);
                if (key == 0)
                {
                    throw new IOException($"KeyPem carries no private key: {OpenSsl.LastError()}");
                }
                int ok = OpenSsl.SSL_CTX_use_PrivateKey(ctx, key);
                OpenSsl.EVP_PKEY_free(key);
                if (ok != 1)
                {
                    throw new IOException($"KeyPem: {OpenSsl.LastError()}");
                }
            }
            finally
            {
                OpenSsl.BIO_free(bio);
            }
        }
    }

    /// <summary>
    /// Run the server handshake on an accepted connection. Resumes inline on the reactor like
    /// every other await. Returns the session used to decrypt inbound records; any application
    /// data that arrived alongside the final handshake flight is already in
    /// <see cref="TlsSession.DrainPlaintext"/>.
    /// </summary>
    public async ValueTask<TlsSession> AcceptAsync(TcpConnection conn)
    {
        // Read once, here: whichever certificates are in force when this connection starts are the
        // ones it uses. SSL_new takes its own reference, so a rotation a moment later cannot pull
        // the context out from under a handshake already running on it.
        nint ssl = OpenSsl.SSL_new(_slot.Current.Default);
        if (ssl == 0)
        {
            throw new IOException($"SSL_new: {OpenSsl.LastError()}");
        }

        nint rbio = OpenSsl.BIO_new(OpenSsl.BIO_s_mem());
        nint wbio = OpenSsl.BIO_new(OpenSsl.BIO_s_mem());
        OpenSsl.SSL_set_bio(ssl, rbio, wbio);   // ssl owns both BIOs now
        OpenSsl.SSL_set_accept_state(ssl);

        var session = new TlsSession(ssl, rbio, wbio, _options.InboundPauseBytes, _options.InboundResumeBytes);

        // Associate the session with this SSL so the keylog callback writes the secret onto it
        // directly (no global map). The handle is freed in TlsSession.Dispose.
        GCHandle handle = GCHandle.Alloc(session);
        OpenSsl.SSL_set_ex_data(ssl, SslSessionIndex, GCHandle.ToIntPtr(handle));
        session.AttachHandle(handle);
        session.AttachFd(conn.ClientFd);   // the teardown close_notify goes out on it, both modes

        // Under the sweep from here until the handshake settles, either way.
        PendingHandshake? pending = null;
        if (_options.HandshakeTimeoutMs > 0)
        {
            pending = new PendingHandshake
            {
                Conn = conn,
                DeadlineMs = Environment.TickCount64 + _options.HandshakeTimeoutMs,
            };
            _handshakes.Enqueue(pending);
        }

        try
        {
            while (true)
            {
                int ret = OpenSsl.Accept(ssl, out int err);

                await FlushOutbound(conn, wbio);   // server flights stage into the slab

                if (ret == 1)
                {
                    break;
                }
                if (err != OpenSsl.SSL_ERROR_WANT_READ)
                {
                    throw new IOException($"TLS handshake failed: {OpenSsl.LastError()}");
                }

                RecvSnapshot snapshot = await conn.ReadAsync();
                bool fed = FeedInbound(conn, rbio, snapshot);
                conn.ResetRead();

                if (snapshot.IsClosed && !fed)
                {
                    throw new IOException("connection closed during TLS handshake");
                }
            }

            // Available only once the handshake is complete, and the handler needs it before it
            // decides which protocol loop to run.
            session.CaptureAlpn();

            session.CapturePeerCertificate();

            // Count BEFORE draining: these are the records the handshake pulled off the socket, so
            // they are invisible to the kernel and the RX sequence number has to skip past them.
            int consumedRecords = session.CountPendingRecords(out bool partialRecord);

            // App data that rode in with the client's Finished is sitting in the
            // rbio - decrypt it now so the handler starts with a clean slate.
            session.DrainPending();

            // Everything the handshake needed to send is flushed; from the next write on, the kernel
            // produces the records. kTLS rejects MSG_WAITALL, so switch this connection's sends to
            // plain (the reactor still loops on short sends). EnableTx zeros 'secret' once programmed.
            if (_options.KernelTx)
            {
                // The keylog secret exists only on TLS 1.3, which the kTLS branch pins above - so
                // here its absence is a real failure, not a version artifact.
                byte[] secret = session.ServerSecret
                    ?? throw new IOException("TLS handshake completed but no server traffic secret was captured");
                Ktls.EnableTx(conn.ClientFd, secret);
                conn.SendOpFlags = 0;
                session.MarkTxEnabled(conn.ClientFd);
            }
            else
            {
                // No TLS ULP on this socket at all: OpenSSL encrypts, the reactor sends ordinary
                // bytes, and MSG_WAITALL stays on because there is no kTLS to reject it. The raw
                // secrets have no further use - and a TLS 1.2 handshake never produced them.
                session.ZeroSecrets();
            }

            // RX is opt-in and per connection. A partial record left in the BIO means bytes the
            // kernel will never see, and no sequence number recovers those - that connection stays
            // on the userspace path rather than corrupting itself.
            if (_options.KernelTx && _options.KernelRx && !partialRecord && session.ClientSecret is not null)
            {
                Ktls.EnableRx(conn.ClientFd, session.ClientSecret, (ulong)consumedRecords);
                session.ClientSecret = null;   // EnableRx zeroed it
                session.MarkKernelRx();
            }
            else if (session.ClientSecret is not null)
            {
                // The client secret exists only for that handoff. OpenSSL keeps its own key
                // schedule, so on every path that did not program the kernel the raw secret is
                // just key material sitting on the heap - scrub it now, not at GC's leisure.
                CryptographicOperations.ZeroMemory(session.ClientSecret);
                session.ClientSecret = null;
            }

            return session;
        }
        catch
        {
            session.Dispose();   // frees the ex_data GCHandle and the SSL (+ BIOs)
            throw;
        }
        finally
        {
            // However this ended - handshake done, peer gone, the sweep itself - the entry stops
            // being a candidate. Flagged rather than removed: it may be anywhere in the queue, and
            // the sweep drops flagged entries when they reach the front, which costs nothing.
            if (pending is not null)
            {
                pending.Done = true;
            }
        }
    }

    private static async ValueTask FlushOutbound(TcpConnection conn, nint wbio)
    {
        int pending = (int)OpenSsl.BIO_ctrl_pending(wbio);
        while (pending > 0)
        {
            int n = StageOutbound(conn, wbio, Math.Min(pending, 8 * 1024));
            if (n <= 0)
            {
                break;
            }
            await conn.FlushAsync();
            pending -= n;
        }
    }

    private static unsafe int StageOutbound(TcpConnection conn, nint wbio, int chunk)
    {
        Span<byte> dst = conn.GetSpan(chunk);
        int n;
        fixed (byte* p = dst)
        {
            n = OpenSsl.BIO_read(wbio, p, chunk);
        }
        if (n > 0)
        {
            conn.Advance(n);
        }
        return n;
    }

    private static unsafe bool FeedInbound(TcpConnection conn, nint rbio, in RecvSnapshot snapshot)
    {
        bool any = false;
        while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
        {
            if (item.HasBuffer)
            {
                OpenSsl.BIO_write(rbio, item.Ptr, item.Len);
                conn.ReturnBuffer(in item);
                any = true;
            }
        }
        return any;
    }

    [UnmanagedCallersOnly]
    private static void KeylogCallback(nint ssl, nint line)
    {
        // Guarded for the same reason ServerNameCallback is: OpenSSL's C frame sits between here
        // and any managed caller, so an escaping exception aborts the PROCESS rather than faulting
        // one connection - uncatchably, and with no stack to read. The body parses a string and
        // allocates, so it is not throw-free by inspection.
        try
        {
            KeylogCore(ssl, line);
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"[tls] keylog callback faulted: {e}");
        }
    }

    private static void KeylogCore(nint ssl, nint line)
    {
        string? text = Marshal.PtrToStringUTF8(line);
        if (text == null)
        {
            return;
        }

        bool server = text.StartsWith("SERVER_TRAFFIC_SECRET_0 ", StringComparison.Ordinal);
        bool client = text.StartsWith("CLIENT_TRAFFIC_SECRET_0 ", StringComparison.Ordinal);
        if (!server && !client)
        {
            return;
        }

        // Resolve the session from the SSL's ex_data (set in AcceptAsync) - no global pointer map.
        nint data = OpenSsl.SSL_get_ex_data(ssl, SslSessionIndex);
        if (data == 0 || GCHandle.FromIntPtr(data).Target is not TlsSession session)
        {
            return;
        }

        // "<SIDE>_TRAFFIC_SECRET_0 <client_random_hex> <secret_hex>"
        int lastSpace = text.LastIndexOf(' ');
        if (lastSpace <= 0)
        {
            return;
        }

        byte[] secret = Convert.FromHexString(text.AsSpan(lastSpace + 1).TrimEnd());
        if (server)
        {
            session.ServerSecret = secret;
        }
        else
        {
            session.ClientSecret = secret;   // the RX half; only used when TlsOptions.KernelRx is on
        }
    }

    [UnmanagedCallersOnly]
    private static unsafe int AlpnSelectCallback(nint ssl, nint outPtr, nint outLen, nint inPtr, uint inLen, nint arg)
    {
        // Same reason as the other two: an exception crossing OpenSSL's frame aborts the process.
        // NOACK on failure is the safe answer - it declines ALPN and lets the handshake continue,
        // which is what this returns for "nothing in common" anyway.
        try
        {
            return AlpnSelectCore(outPtr, outLen, inPtr, inLen, arg);
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"[tls] alpn callback faulted: {e}");
            return OpenSsl.SSL_TLSEXT_ERR_NOACK;
        }
    }

    private static unsafe int AlpnSelectCore(nint outPtr, nint outLen, nint inPtr, uint inLen, nint arg)
    {
        if (arg == 0 || GCHandle.FromIntPtr(arg).Target is not byte[] wire)
        {
            return OpenSsl.SSL_TLSEXT_ERR_NOACK;
        }

        // SERVER preference: walk OUR list in order and take the first the client also offered, so
        // the order in TlsOptions.Alpn is what decides. Walking the client's list instead would
        // hand it the choice, which is not what an operator listing ["h2", "http/1.1"] means.
        //
        // *out points into the CLIENT's buffer rather than ours - standard practice, since that
        // buffer outlives the callback and ours would have to be pinned to match.
        var offered = new ReadOnlySpan<byte>((void*)inPtr, (int)inLen);

        int ours = 0;
        while (ours < wire.Length)
        {
            int wantLength = wire[ours];
            ReadOnlySpan<byte> want = wire.AsSpan(ours + 1, wantLength);

            int theirs = 0;
            while (theirs < offered.Length)
            {
                int haveLength = offered[theirs];
                if (theirs + 1 + haveLength > offered.Length)
                {
                    break;   // malformed offer list; stop rather than read past it
                }

                if (haveLength == wantLength && offered.Slice(theirs + 1, haveLength).SequenceEqual(want))
                {
                    *(nint*)outPtr = inPtr + theirs + 1;
                    *(byte*)outLen = (byte)haveLength;
                    return OpenSsl.SSL_TLSEXT_ERR_OK;
                }
                theirs += 1 + haveLength;
            }

            ours += 1 + wantLength;
        }

        // Nothing in common. NOACK continues without the extension rather than failing the
        // handshake - the client may still speak HTTP/1.1 quite happily.
        return OpenSsl.SSL_TLSEXT_ERR_NOACK;
    }

    /// <summary>
    /// Protocols as ALPN wants them: each one a length byte then its ASCII name, in our preference
    /// order. The select callback walks this, so position here is what decides the negotiation.
    /// </summary>
    private static byte[] BuildAlpnWire(string[] protocols)
    {
        if (protocols.Length == 0)
        {
            throw new ArgumentException("At least one ALPN protocol is required.", nameof(protocols));
        }

        int total = 0;
        foreach (string protocol in protocols)
        {
            if (protocol.Length is 0 or > 255)
            {
                throw new ArgumentException($"ALPN protocol '{protocol}' must be 1..255 bytes.", nameof(protocols));
            }
            total += 1 + protocol.Length;
        }

        var wire = new byte[total];
        int cursor = 0;
        foreach (string protocol in protocols)
        {
            wire[cursor++] = (byte)protocol.Length;
            for (int i = 0; i < protocol.Length; i++)
            {
                wire[cursor++] = (byte)protocol[i];
            }
        }
        return wire;
    }
}
