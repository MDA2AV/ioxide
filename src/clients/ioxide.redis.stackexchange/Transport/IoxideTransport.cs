using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using RESPite.Transports;

namespace ioxide.redis.stackexchange;

/// <summary>
/// One StackExchange.Redis connection as a socket on a reactor's ring. Receives are ring operations
/// whose completions push the bytes into StackExchange.Redis on the reactor's thread, where it parses
/// them and completes the commands; each loop turn that delivered anything ends with one
/// <see cref="TransportReceiver.OnBatchEnd"/>, posted to run after the turn's completions. Writers
/// stage from any thread (StackExchange.Redis keeps to one at a time) and <see cref="Flush"/> hands
/// the batch to the ring as one send.
/// </summary>
internal sealed partial class IoxideTransport : DuplexTransport
{
    private readonly Reactor _reactor;
    private readonly RingSocket _socket;

    private IoxideTransport(Reactor reactor, RingSocket socket, int receiveBufferSize)
    {
        _reactor = reactor;
        _socket = socket;
        _received = GC.AllocateUninitializedArray<byte>(receiveBufferSize, pinned: true);
    }

    private static unsafe nint Address(byte[] pinned) => (nint)Unsafe.AsPointer(ref MemoryMarshal.GetArrayDataReference(pinned));
}
