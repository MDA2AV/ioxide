using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// A Segmented connection's spill segments are its own: each twice the last, kept for its next response and
/// freed when it is recycled. A pool the reactor shared between connections handed one to two of them (#402).
/// </summary>
internal static unsafe class SpillSegmentTests
{
    private const int Slab = 4096;

    public static void Register(Runner runner)
    {
        runner.Test("tcp: a Segmented connection reuses its spill segments for its next response, and frees them when it is recycled", () =>
        {
            TcpConnection conn = Connection();
            try
            {
                List<nint> first = Spill(conn, 3).Starts;
                conn.CompleteFlush();   // the send is done
                List<nint> second = Spill(conn, 3).Starts;
                conn.CompleteFlush();
                int kept = KeptOf(conn);
                conn.Clear();
                int afterRecycle = KeptOf(conn);

                Assert.True(first.Distinct().Count() == 3, $"{first.Distinct().Count()} distinct segments spilled, not 3: the overflow never ran");
                Assert.True(second.SequenceEqual(first), "the second response spilled into new segments, not the ones the first kept");
                Assert.True(kept == 3, $"{kept} segments kept between responses, not 3");
                Assert.True(afterRecycle == 0, $"{afterRecycle} segments still held after the recycle");
            }
            finally
            {
                conn.Dispose();
            }
        });

        runner.Test("tcp: each spill segment of a Segmented response is twice the last, from twice the slab up to 64 slabs", () =>
        {
            TcpConnection conn = Connection();
            try
            {
                List<int> sizes = Spill(conn, 8).Sizes;
                conn.Clear();

                int[] expected = [2 * Slab, 4 * Slab, 8 * Slab, 16 * Slab, 32 * Slab, 64 * Slab, 64 * Slab, 64 * Slab];
                Assert.True(sizes.SequenceEqual(expected), $"segments of {string.Join(", ", sizes)} bytes, not {string.Join(", ", expected)}");
            }
            finally
            {
                conn.Dispose();
            }
        });
    }

    // On a reactor that never runs, as AdapterParkTests uses.
    private static TcpConnection Connection()
    {
        var reactor = new Reactor(0, new ServerConfig { ReactorCount = 1, Tcp = null, Udp = null });
        return new TcpConnection(reactor, -1, Slab, 8, WriteOverflowStrategy.Segmented);
    }

    // Fills the primary slab and then `segments` spill segments, returning where each starts and its size.
    private static (List<nint> Starts, List<int> Sizes) Spill(TcpConnection conn, int segments)
    {
        conn.Advance(conn.GetSpan(1).Length);
        var starts = new List<nint>();
        var sizes = new List<int>();
        for (int i = 0; i < segments; i++)
        {
            Span<byte> span = conn.GetSpan(1);   // the last one is full, so this is all of the next
            starts.Add((nint)Unsafe.AsPointer(ref MemoryMarshal.GetReference(span)));
            sizes.Add(span.Length);
            conn.Advance(span.Length);
        }
        return (starts, sizes);
    }

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_ovKept")]
    private static extern ref int KeptOf(TcpConnection conn);
}
