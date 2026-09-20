namespace ioxide;

/// <summary>
/// ioxide - a thread-per-core io_uring runtime for .NET. One ring per core; HTTP, Postgres, and
/// file I/O submit on that ring and resume inline on the reactor thread. See the repo README and
/// website for the full picture.
/// </summary>
public static class IoxideRuntime
{
    /// <summary>
    /// The version of the NuGet package this assembly shipped in.
    /// </summary>
    /// <remarks>
    /// Generated from the Version property in ioxide.csproj by the GenerateVersionSource target
    /// there, not written here. As a hand-kept literal it had to be remembered on every release and
    /// was not: it still read "0.0.17" - untouched since the 0.0.x days - against packages on
    /// 0.13.233, one of four statements of the same number with all four disagreeing (#224).
    ///
    /// Generated rather than read off the assembly at run time: AssemblyInformationalVersionAttribute
    /// would be the obvious source, but reflecting over assembly attributes is what Native AOT
    /// trims. A const costs nothing and survives trimming.
    /// </remarks>
    public const string Version = IoxideVersion.Value;

    // Wiring (a builder API will eventually wrap this):
    //   var reactor = new Reactor(id, config);               // implements IRingHost
    //   reactor.TcpHandle  = HandleConnection;
    //   reactor.OnStart = r => PgPool.Start(r, pgOptions);   // clients open on the reactor thread
    //   reactor.Run();
    //
    // Roadmap: per-command timeouts · fixed files / send-zc · builder API. (SCRAM, the
    // extended/prepared protocol, Redis, TLS, and the BCL bridge (per-reactor SyncContext) have shipped.)
}
