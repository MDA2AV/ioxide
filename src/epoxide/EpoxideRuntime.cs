namespace epoxide;

/// <summary>
/// epoxide - ioxide's thread-per-core runtime on epoll. One epoll set per reactor thread, handlers
/// resume inline on it, and because every operation is an ordinary non-blocking syscall a
/// connection can be read and written from any thread: a handler that moves to the thread pool
/// keeps working there, with no hop back to its reactor.
/// </summary>
public static class EpoxideRuntime
{
    /// <summary>The version of the NuGet package this assembly shipped in (epoxide.csproj's Version).</summary>
    public const string Version = EpoxideVersion.Value;

    // Wiring, the same as ioxide's:
    //   var reactor = new Reactor(id, config);
    //   reactor.TcpHandle = HandleConnection;
    //   reactor.OnStart = r => TlsService.Start(r, tlsOptions);
    //   reactor.Run();
}
