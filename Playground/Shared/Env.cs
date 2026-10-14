namespace Playground.Shared;

/// <summary>
/// Typed reads for the PLAYGROUND_* environment knobs. Every sample configures itself this way, so
/// the "parse it or fall back" shape is written once instead of at each call site.
/// </summary>
public static class Env
{
    public static string Str(string name, string fallback)
        => Environment.GetEnvironmentVariable(name) is { Length: > 0 } value ? value : fallback;

    public static string? StrOrNull(string name)
        => Environment.GetEnvironmentVariable(name) is { Length: > 0 } value ? value : null;

    public static int Int(string name, int fallback)
        => int.TryParse(Environment.GetEnvironmentVariable(name), out int value) ? value : fallback;

    public static long Long(string name, long fallback)
        => long.TryParse(Environment.GetEnvironmentVariable(name), out long value) ? value : fallback;

    public static ushort Port(string name, ushort fallback)
        => ushort.TryParse(Environment.GetEnvironmentVariable(name), out ushort value) ? value : fallback;

    public static bool Flag(string name)
        => Environment.GetEnvironmentVariable(name) == "1";

    /// <summary>
    /// Tri-state, unlike <see cref="Flag"/>: unset keeps the sample's own literal, so a harness can
    /// force a knob OFF as well as on. "1" and "0" are the only values that mean anything.
    /// </summary>
    public static bool Bool(string name, bool fallback)
        => Environment.GetEnvironmentVariable(name) switch
        {
            "1" => true,
            "0" => false,
            _ => fallback,
        };

    /// <summary>
    /// Apply the harness overrides to a sample's knobs, in one call, so the sample itself can
    /// declare them as plain literals you edit.
    ///
    /// The knobs are the sample's real configuration; this exists only because bench/run.sh and
    /// the Dockerfile drive every sample from the outside. Delete the call when you copy a sample
    /// out - the literals above it are the whole configuration and nothing else reads these.
    /// </summary>
    public static void Override(ref ushort port, ref int reactors)
    {
        port = Port("PLAYGROUND_PORT", port);
        reactors = Int("PLAYGROUND_REACTORS", reactors);
    }

    /// <inheritdoc cref="Override(ref ushort, ref int)"/>
    public static void Override(ref ushort port, ref int reactors, ref int bodyBytes)
    {
        Override(ref port, ref reactors);
        bodyBytes = Int("PLAYGROUND_BODY", bodyBytes);
    }

    /// <summary>
    /// The QUIC form of <see cref="Override(ref ushort, ref int)"/>. A QUIC port is a UDP port, so
    /// it reads PLAYGROUND_QUIC_PORT and not PLAYGROUND_PORT - a sample that listens on both binds
    /// two different ports and would otherwise collide with itself.
    /// </summary>
    public static void OverrideQuic(ref ushort quicPort, ref int reactors)
    {
        quicPort = Port("PLAYGROUND_QUIC_PORT", quicPort);
        reactors = Int("PLAYGROUND_REACTORS", reactors);
    }

    /// <summary>
    /// PLAYGROUND_TLS_CERT and PLAYGROUND_TLS_KEY: a real PEM pair in place of the self-signed
    /// localhost one a sample generates when its own literals are null.
    /// </summary>
    public static void OverrideTlsCert(ref string? certOverride, ref string? keyOverride)
    {
        certOverride = StrOrNull("PLAYGROUND_TLS_CERT") ?? certOverride;
        keyOverride = StrOrNull("PLAYGROUND_TLS_KEY") ?? keyOverride;
    }

    /// <summary>
    /// The kTLS knobs, same escape hatch. These exist so bench/tls-matrix.sh can measure one build
    /// in every backend combination instead of rebuilding per cell - a sample that only ever runs
    /// one way does not need them.
    /// </summary>
    public static void OverrideKtls(ref bool kernelTx, ref bool kernelRx)
    {
        kernelTx = Bool("PLAYGROUND_KTLS_TX", kernelTx);
        kernelRx = Bool("PLAYGROUND_KTLS_RX", kernelRx);
    }

    /// <summary>
    /// Per-connection recv buffer rings instead of the shared ring - an A/B knob, so it has to be
    /// drivable from outside even though no committed script sets it today.
    /// </summary>
    public static void OverrideIncremental(ref bool incrementalBuffers)
        => incrementalBuffers = Bool("PLAYGROUND_INCREMENTAL", incrementalBuffers);

    /// <summary>
    /// The general form: the literal in the sample is the configuration, and the named environment
    /// variable overrides it when set. Naming the variable at the call site is deliberate - these
    /// samples are the benchmark regression fixtures, so what a harness can drive has to be
    /// readable from the sample itself.
    /// </summary>
    public static void Override(ref string value, string name) => value = Str(name, value);

    /// <summary>
    /// The nullable-string form. It cannot be an <c>Override</c> overload: nullability is not part
    /// of the signature, so <c>ref string?</c> and <c>ref string</c> collide.
    /// </summary>
    public static void OverrideOptional(ref string? value, string name) => value = StrOrNull(name) ?? value;

    /// <inheritdoc cref="Override(ref string, string)"/>
    public static void Override(ref int value, string name) => value = Int(name, value);

    /// <inheritdoc cref="Override(ref string, string)"/>
    public static void Override(ref long value, string name) => value = Long(name, value);

    /// <inheritdoc cref="Override(ref string, string)"/>
    public static void Override(ref ushort value, string name) => value = Port(name, value);

    /// <inheritdoc cref="Override(ref string, string)"/>
    public static void Override(ref bool value, string name) => value = Bool(name, value);

    /// <summary>The incremental sample's ring geometry.</summary>
    public static void OverrideIncrementalRing(ref int maxConnections, ref int recvSlots, ref int recvBufferSize)
    {
        maxConnections = Int("PLAYGROUND_INC_CONNS", maxConnections);
        recvSlots = Int("PLAYGROUND_INC_SLOTS", recvSlots);
        recvBufferSize = Int("PLAYGROUND_INC_BUFSIZE", recvBufferSize);
    }

    /// <summary>UDP and QPACK tuning for the QUIC and HTTP/3 samples.</summary>
    public static void OverrideH3(ref int udpRecvSlots, ref long qpackCapacity)
    {
        udpRecvSlots = Int("PLAYGROUND_UDP_SLOTS", udpRecvSlots);
        qpackCapacity = Long("PLAYGROUND_QPACK_CAP", qpackCapacity);
    }

    /// <summary>A PEM pair supplied from outside instead of the generated self-signed one.</summary>
    public static void OverrideCert(ref string? certPath, ref string? keyPath)
    {
        certPath = StrOrNull("PLAYGROUND_QUIC_CERT") ?? certPath;
        keyPath = StrOrNull("PLAYGROUND_QUIC_KEY") ?? keyPath;
    }

    /// <summary>The Postgres sample's connection settings.</summary>
    public static void OverridePg(ref string host, ref ushort pgPort, ref string user,
        ref string? password, ref string database, ref int poolSize, ref int commandTimeoutMs)
    {
        host = Str("PLAYGROUND_PG_HOST", host);
        pgPort = Port("PLAYGROUND_PG_PORT", pgPort);
        user = Str("PLAYGROUND_PG_USER", user);
        password = StrOrNull("PLAYGROUND_PG_PASSWORD") ?? password;
        database = Str("PLAYGROUND_PG_DB", database);
        poolSize = Int("PLAYGROUND_PG_POOL", poolSize);
        commandTimeoutMs = Int("PLAYGROUND_PG_TIMEOUT", commandTimeoutMs);
    }

    /// <summary>Where a proxy sample forwards to, and how it trusts the origin.</summary>
    public static void OverrideUpstream(ref string host, ref ushort upstreamPort, ref string serverName,
        ref int poolSize, ref string? caFile, ref bool insecure)
    {
        host = Str("PLAYGROUND_UPSTREAM_HOST", host);
        upstreamPort = Port("PLAYGROUND_UPSTREAM_PORT", upstreamPort);
        serverName = Str("PLAYGROUND_UPSTREAM_SNI", serverName);
        poolSize = Int("PLAYGROUND_UPSTREAM_POOL", poolSize);
        caFile = StrOrNull("PLAYGROUND_UPSTREAM_CA") ?? caFile;
        insecure = Bool("PLAYGROUND_UPSTREAM_INSECURE", insecure);
    }

    /// <summary>
    /// The static-file sample's own knobs, so bench/file-matrix.sh can drive every arm of the
    /// slab-vs-buffer matrix from a single build instead of rebuilding per cell.
    /// </summary>
    public static void OverrideFile(ref string dir, ref bool buffered, ref string tlsMode)
    {
        dir = Str("PLAYGROUND_DIR", dir);
        buffered = Bool("PLAYGROUND_FILE_BUFFERED", buffered);
        tlsMode = Str("PLAYGROUND_FILE_TLS", tlsMode);
    }
}
