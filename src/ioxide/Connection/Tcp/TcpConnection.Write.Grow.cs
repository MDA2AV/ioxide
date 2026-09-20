using System.Runtime.InteropServices;

// ReSharper disable SuggestVarOrType_BuiltInTypes

namespace ioxide;

/// <summary>
/// Grow write overflow (<see cref="WriteOverflowStrategy.Grow"/>): when a response outgrows the primary
/// write slab (see TcpConnection.Write.cs), reallocate it larger and copy the bytes written so far, so the
/// whole response stays in one contiguous buffer flushed with a single SEND.
/// </summary>
public sealed unsafe partial class TcpConnection
{
    // Grows the per-connection write slab so a response larger than the current capacity can be
    // buffered before the single contiguous flush. Runs on the reactor thread while building a
    // response (never during a flush), so WriteBuffer is never in flight when it moves.
    private void GrowWriteSlab(int required)
    {
        int newSize = _writeSlabSize;
        do
        {
            newSize *= 2;
        }
        while (newSize < required);

        byte* newBuffer = (byte*)NativeMemory.AlignedAlloc((nuint)newSize, 64);

        if (WriteTail > 0)
        {
            Buffer.MemoryCopy(WriteBuffer, newBuffer, newSize, WriteTail);
        }

        NativeMemory.AlignedFree(WriteBuffer);

        WriteBuffer = newBuffer;
        _writeSlabSize = newSize;
        _manager.Reset(newBuffer, newSize);
    }
}
