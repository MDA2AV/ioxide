namespace ioxide;

/// <summary>
/// ioxide - a thread-per-core io_uring runtime for .NET. One ring per core; HTTP, Postgres, and
/// file I/O submit on that ring and resume inline on the reactor thread. See the repo README and
/// website for the full picture.
/// </summary>
public static class IoxideRuntime
{
    public const string Version = "0.14.236";

    // Wiring (a builder API will eventually wrap this):
    //   var reactor = new Reactor(id, config);               // implements IRingHost
    //   reactor.TcpHandle  = HandleConnection;
    //   reactor.OnStart = r => PgPool.Start(r, pgOptions);   // clients open on the reactor thread
    //   reactor.Run();
    //
    // Roadmap: per-command timeouts · fixed files / send-zc · builder API. (SCRAM, the
    // extended/prepared protocol, Redis, TLS, and the BCL bridge (per-reactor SyncContext) have shipped.)
}
