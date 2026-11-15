using System.Runtime.InteropServices;

namespace ioxide.file;

/// <summary>
/// One unit of file-serving capacity: an op source plus a native read buffer, reading any
/// descriptor (typically <see cref="AssetCache"/> fds) at an offset, resumed inline. Pooled per
/// reactor via <see cref="CreatePool"/> so concurrent requests don't serialize.
/// </summary>
public sealed unsafe class AssetReader : IDisposable
{
    private readonly IRingHost _host;
    private readonly RingOpSource _read = new();
    private int _disposed;

    /// <summary>The reader's native buffer; valid until the reader is returned to its pool.</summary>
    public nint Buffer { get; }

    public int Capacity { get; }

    public AssetReader(IRingHost host, int bufferBytes)
    {
        _host = host;
        Buffer = (nint)NativeMemory.Alloc((nuint)bufferBytes);
        Capacity = bufferBytes;
    }

    /// <summary>
    /// Read up to <see cref="Capacity"/> bytes of <paramref name="fd"/> from
    /// <paramref name="offset"/> into <see cref="Buffer"/>; returns bytes read or a negative errno.
    /// One call never returns more than <see cref="Capacity"/> bytes - to serve a file larger than
    /// the buffer, call repeatedly at advancing offsets (<c>offset += bytesRead</c>) until done.
    /// </summary>
    public ValueTask<int> ReadAsync(int fd, long offset)
    {
        ValueTask<int> pending = _read.Prepare();
        _host.SubmitRead(fd, Buffer, Capacity, offset, _read);
        return pending;
    }

    /// <summary>
    /// Build a per-reactor reader pool and register it as a service
    /// (<c>GetService&lt;RingPool&lt;AssetReader&gt;&gt;()</c>). <paramref name="readers"/> bounds
    /// concurrent reads; size <paramref name="bufferBytes"/> for the largest asset. The reactor's stop
    /// disposes the pool, and with it each reader once it is back.
    /// </summary>
    public static RingPool<AssetReader> CreatePool(Reactor reactor, int readers, int bufferBytes)
    {
        var pool = new RingPool<AssetReader>();
        for (int i = 0; i < readers; i++)
        {
            pool.Return(new AssetReader(reactor, bufferBytes));
        }

        reactor.AddService(pool);
        reactor.AddStopper(pool.Dispose);
        return pool;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            NativeMemory.Free((void*)Buffer);
        }
    }
}
