using ioxide;

namespace ioxide.ngtcp2;

/// <summary>Transport dropped the connection (idle sweep or shutdown).</summary>
public unsafe partial class QuicEngineConnection
{
    public override void OnEvicted(QuicEvictReason reason)
    {
        // A shutdown is an immediate close the peer is told of (RFC 9000 10.2); idle and faulted ones end silently.
        if (reason == QuicEvictReason.ReactorShutdown)
        {
            Teardown(WriteTransportFarewell(0));   // liberr 0: transport NO_ERROR; Close(code) sends an application code
            return;
        }

        Destroy();
    }
}
