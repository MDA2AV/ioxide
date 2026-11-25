using System.Buffers;

namespace ioxide.utils;

public sealed unsafe class UnmanagedMemoryManager : MemoryManager<byte>
{
    private byte* _ptr;
    private int _length;

    internal byte* Pointer => _ptr;

    public ushort BufferId { get; private set; }

    // TcpConnection generation at enqueue time; lets returns route safely after pool reuse.
    public ushort Gen { get; private set; }

    public UnmanagedMemoryManager(byte* ptr, int length)
    {
        _ptr = ptr;
        _length = length;
    }

    public UnmanagedMemoryManager(byte* ptr, int length, ushort bufferId, ushort gen = 0)
    {
        _ptr = ptr;
        _length = length;
        BufferId = bufferId;
        Gen = gen;
    }

    // Re-point a pooled manager at a new slice (TcpConnectionPipeReader reuses
    // one manager per held segment instead of allocating per recv).
    internal void Reset(byte* ptr, int length, ushort bufferId, ushort gen)
    {
        _ptr = ptr;
        _length = length;
        BufferId = bufferId;
        Gen = gen;
    }

    // Re-point at a new buffer after the write slab grows; the write-side manager doesn't use
    // BufferId/Gen, so leave them untouched.
    internal void Reset(byte* ptr, int length)
    {
        _ptr = ptr;
        _length = length;
    }

    public override Span<byte> GetSpan() => new(_ptr, _length);

    public override MemoryHandle Pin(int elementIndex = 0) => new(_ptr + elementIndex);

    public override void Unpin() { }

    protected override void Dispose(bool disposing) { }
}
