using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace ioxide;

/// <summary>
/// The connection's file-read facet: read a file descriptor straight into the write buffer, so a static
/// file needs no intermediate buffer and no copy - the bytes land exactly where the next send picks
/// them up. IORING_OP_READ on this connection's reactor, resumed inline. One read in flight per
/// connection at a time (reuses a single <see cref="RingOpSource"/>, like the flush facet).
/// </summary>
public sealed unsafe partial class TcpConnection
{
    // What a read on a connection that has closed returns. Never a read's own error - a file has no
    // peer to lose - so a caller can tell a client that left from a file that failed or ended early.
    private const int EPIPE = 32;

    private readonly RingOpSource _fileRead = new();

    /// <summary>
    /// Read up to <paramref name="len"/> bytes of <paramref name="fileFd"/> from
    /// <paramref name="fileOffset"/> straight into the write buffer, where the next write would go, via
    /// IORING_OP_READ on this connection's reactor. That is where <see cref="GetSpan"/> would hand out
    /// <paramref name="len"/> bytes: the slab, grown to hold them under <see cref="WriteOverflowStrategy.Grow"/>;
    /// under <see cref="WriteOverflowStrategy.Segmented"/> an overflow segment once the slab can't hold
    /// them, or once the response has spilled, so the file's bytes go out behind everything written
    /// before them.
    ///
    /// The bytes are placed but NOT yet part of the pending write - call <see cref="AdvanceWrite"/>
    /// with the result to commit them before <c>FlushAsync</c>, and write nothing in between. Framing a
    /// header first (with a known Content-Length) then reading the body after it sends header + body in
    /// one flush. Like every write, refused while a flush is in flight.
    ///
    /// <b>Cleartext only.</b> The bytes go on the wire as read, so this is for a plain connection. A
    /// TLS connection must read into a buffer and encrypt (<c>TlsSession.Write</c>) - the wire carries
    /// ciphertext, not the file's plaintext.
    /// </summary>
    /// <returns>
    /// The bytes read; 0 at end of file; or a negative errno - the read's own, or -EPIPE (-32) once the
    /// connection has closed, since nothing would ever send what it read. A loop that stops at a result
    /// of 0 or less stops for both; one that has to tell a client that left from a file that ended early
    /// looks for -EPIPE.
    /// </returns>
    /// <exception cref="InvalidOperationException">A flush is in flight, or another file read is.</exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="len"/> is negative, or more than the write buffer can hand out in one piece.
    /// </exception>
    public ValueTask<int> ReadFileAsync(int fileFd, int len, long fileOffset)
    {
        if (Volatile.Read(ref _closed) == 1)
        {
            return new ValueTask<int>(-EPIPE);
        }

        // A send may still be reading the slab and the segments: growing the slab frees the one it reads,
        // and its completion clears both, taking anything committed meanwhile with it.
        if (Volatile.Read(ref _flushInProgress) != 0)
        {
            throw new InvalidOperationException("Cannot write while flush is in progress.");
        }

        // Where GetSpan would hand out len bytes, so AdvanceWrite commits the read where it landed. After a
        // spill that is a spill segment, never the slab: the flush sends the slab first, so a read into it
        // would go out ahead of the head written before it.
        Span<byte> destination = EnsureWritable(len);

        // The kernel is told the length, not the span, so the span has to hold it: a negative length is
        // some 4 GiB to the kernel, and one close enough to int.MaxValue overflows EnsureWritable's bound,
        // which then hands out only the rest of the buffer.
        if ((uint)len > (uint)destination.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(len), len, $"Only {destination.Length} bytes could be handed out.");
        }

        ValueTask<int> pending = _fileRead.Prepare();

        // Native memory, so the address outlives the span.
        _reactor.SubmitRead(fileFd, (nint)Unsafe.AsPointer(ref MemoryMarshal.GetReference(destination)), len, fileOffset, _fileRead);
        return pending;
    }

    /// <summary>
    /// Commit <paramref name="n"/> bytes just read by <see cref="ReadFileAsync"/>, so the next
    /// <c>FlushAsync</c> sends them. Pass the read's return value; a non-positive result (end of file
    /// or an error) commits nothing. The commit is <see cref="Advance"/>'s, at the same position the
    /// read was given, so it is refused the same way: during a flush, and past the rest of the slab or
    /// segment the read went into.
    /// </summary>
    public void AdvanceWrite(int n)
    {
        if (n > 0)
        {
            Advance(n);
        }
    }
}
