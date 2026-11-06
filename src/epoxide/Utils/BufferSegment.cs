using System.Buffers;

namespace epoxide.utils;

/// <summary>
/// One segment of a multi-buffer ReadOnlySequence&lt;byte&gt; stitched from a snapshot's recv
/// buffers (<see cref="BufferMemoryExtensions.ToReadOnlySequence"/>).
/// </summary>
public sealed class BufferSegment : ReadOnlySequenceSegment<byte>
{
    public int BufferId { get; }

    public BufferSegment(ReadOnlyMemory<byte> memory, int bufferId)
    {
        Memory = memory;
        BufferId = bufferId;
    }

    public BufferSegment Append(ReadOnlyMemory<byte> memory, int bufferId)
    {
        var next = new BufferSegment(memory, bufferId)
        {
            RunningIndex = RunningIndex + Memory.Length
        };

        Next = next;
        return next;
    }
}

public static class BufferMemoryExtensions
{
    /// <summary>
    /// Stitch the snapshot's buffers into one logical byte sequence, so a parser sees the request
    /// whole no matter how many recv slices it arrived in. Zero-copy: segments point straight at the
    /// recv buffers, so parse before returning them.
    /// </summary>
    public static ReadOnlySequence<byte> ToReadOnlySequence(this UnmanagedMemoryManager[] memories)
    {
        if (memories.Length == 0)
        {
            return ReadOnlySequence<byte>.Empty;
        }

        if (memories.Length == 1)
        {
            return new ReadOnlySequence<byte>(memories[0].Memory);
        }

        var head = new BufferSegment(memories[0].Memory, memories[0].BufferId);
        BufferSegment tail = head;
        for (int i = 1; i < memories.Length; i++)
        {
            tail = tail.Append(memories[i].Memory, memories[i].BufferId);
        }

        return new ReadOnlySequence<byte>(head, 0, tail, tail.Memory.Length);
    }
}
