namespace ioxide;

// This part is intentionally NOT unsafe: it awaits the connection handler, and await isn't allowed
// in an unsafe context. The rest of the reactor (pointer-heavy ring work) stays unsafe.
public sealed partial class Reactor
{
    // Invoke the per-connection handler, observing faults so a thrown handler doesn't silently
    // vanish (the reactor starts it fire-and-forget from the accept path). Runs once per connection.
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

            // A handler that faulted before its DecRef would otherwise leak the connection (#94).
            conn.ReleaseHandlerRefOnFault(gen);
        }
    }
}
