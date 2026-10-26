namespace epoxide;

// Not unsafe: it awaits the connection handler, and await isn't allowed in an unsafe context.
public sealed partial class Reactor
{
    // Invoke the per-connection handler, observing faults so a thrown handler doesn't silently vanish
    // (the reactor starts it fire-and-forget from the accept path). Runs once per connection.
    private async Task RunHandlerAsync(TcpConnection conn)
    {
        int gen = conn.Generation;
        try
        {
            await TcpHandle(this, conn);
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"[r{_id}] connection handler faulted: {e}");

            // A handler that faulted before its DecRef would otherwise leak the connection. Released on
            // the reactor, the one thread that recycles it, so it cannot be reused between the
            // generation check and the release, which would let go of its next life.
            if (OnReactorThread)
            {
                conn.ReleaseHandlerRefOnFault(gen);
            }
            else
            {
                ScheduleOnReactor(static s =>
                {
                    var (c, g) = ((TcpConnection, int))s!;
                    c.ReleaseHandlerRefOnFault(g);
                }, (conn, gen));
            }
        }
    }
}
