namespace epoxide;

/// <summary>The reactor's hooks and its per-reactor services, as in ioxide.</summary>
public sealed partial class Reactor
{
    // Typed per-reactor services (opened in OnStart; handlers fetch them).
    private readonly Dictionary<Type, object> _services = new();

    public void AddService<T>(T service) where T : class
    {
        _services[typeof(T)] = service;
    }

    /// <summary>Get a service registered with <see cref="AddService{T}"/>; throws if absent.</summary>
    public T GetService<T>() where T : class
    {
        return _services.TryGetValue(typeof(T), out object? service)
            ? (T)service
            : throw new InvalidOperationException(
                $"No {typeof(T).Name} registered on reactor {_id}. Register it from OnStart with AddService.");
    }

    /// <summary>Runs on the reactor thread before the loop starts - register services here.</summary>
    public Action<Reactor>? OnStart;

    /// <summary>
    /// The per-connection TCP handler, invoked once per accepted connection, on the reactor thread.
    /// It may move to the thread pool at any point and keep using the connection there.
    /// </summary>
    public Func<Reactor, TcpConnection, Task> TcpHandle = null!;

    /// <summary>
    /// Raised on the reactor's own thread when it is ending because of a fault rather than a
    /// <see cref="Stop"/>. It runs before the teardown: the listeners and connections are closed only
    /// once it returns. Handle it to log, restart, or bring the process down deliberately.
    /// </summary>
    /// <remarks>
    /// Without a handler the exception propagates out of <see cref="Run"/>, which on a bare
    /// <c>new Thread(reactor.Run)</c> terminates the process.
    /// </remarks>
    public Action<Reactor, Exception>? OnFault;
}
