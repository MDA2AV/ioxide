namespace ioxide.pg;

/// <summary>
/// How to reach Postgres and how much capacity to provision per reactor.
/// </summary>
public sealed record PgOptions
{
    /// <summary>IPv4 literal. Resolve hostnames up front - DNS would block the reactor.</summary>
    public string Host { get; init; } = "127.0.0.1";

    public ushort Port { get; init; } = 5432;

    public required string User { get; init; }

    public required string Database { get; init; }

    /// <summary>Password for SCRAM-SHA-256; empty/null means trust auth.</summary>
    public string? Password { get; init; }

    /// <summary>
    /// Connections opened per reactor. One connection carries one query at a time, so this is the
    /// reactor's query concurrency; total server-side connections = PoolSize × ReactorCount.
    /// </summary>
    public int PoolSize { get; init; } = 8;

    /// <summary>
    /// Hard ceiling on a single backend message; the receive buffer grows up to this (from 64 KB).
    /// A single row or value larger than this breaks the connection. Default 64 MB - raise it for
    /// large bytea/text workloads.
    /// </summary>
    public int MaxReceiveBytes { get; init; } = 64 * 1024 * 1024;

    /// <summary>
    /// Per-command timeout in milliseconds: a connection whose oldest in-flight command exceeds this
    /// is torn down and its waiters fail with a diagnostic error, so a silent backend can't park a
    /// query forever. It bounds a connect and its startup the same way. 0 disables. Default 30000.
    /// </summary>
    public int CommandTimeoutMs { get; init; } = 30_000;
}
