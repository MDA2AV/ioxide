using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using ioxide.utils;
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
    private readonly RingSocket _ringSocket;

    // Wraps a connected socket and allocates the native buffer its receives land in.
    private unsafe IoxideTransport(Reactor reactor, RingSocket ringSocket, int receiveBufferSize)
    {
        _reactor = reactor;
        _ringSocket = ringSocket;
        _received = (nint)NativeMemory.Alloc((nuint)receiveBufferSize);
        _receivedView = new UnmanagedMemoryManager((byte*)_received, receiveBufferSize);
    }

    // A pinned array's raw address, which is what the ring's operations take.
    private static unsafe nint Address(byte[] pinned) => (nint)Unsafe.AsPointer(ref MemoryMarshal.GetArrayDataReference(pinned));
}
