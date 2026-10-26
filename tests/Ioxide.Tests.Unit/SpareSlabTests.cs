using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// A Segmented connection's overflow slabs are its own: kept for its next response, freed when it is
/// recycled. A pool the reactor shared between connections handed one slab to two of them (#402).
/// </summary>
internal static unsafe class SpareSlabTests
{
    private const int Slab = 4096;
    private const int Spilled = 4;

    public static void Register(Runner runner)
    {
        runner.Test("tcp: a Segmented connection reuses the slabs it spilled into, and frees them when it is recycled", () =>
        {
            var reactor = new Reactor(0, new ServerConfig { ReactorCount = 1, Tcp = null, Udp = null });
            var conn = new TcpConnection(reactor, -1, Slab, 8, WriteOverflowStrategy.Segmented);
            try
            {
                HashSet<nint> first = Spill(conn);
                conn.CompleteFlush();   // the send is done
                HashSet<nint> second = Spill(conn);
                conn.CompleteFlush();
                int kept = Spares(conn)?.Count ?? 0;
                conn.Clear();
                int afterRecycle = Spares(conn)?.Count ?? 0;

                Assert.True(first.Count == Spilled, $"{first.Count} distinct slabs spilled, not {Spilled}: the overflow never ran");
                Assert.True(second.SetEquals(first), "the second response spilled into new slabs, not the ones the first gave back");
                Assert.True(kept == Spilled, $"{kept} slabs kept between responses, not {Spilled}");
                Assert.True(afterRecycle == 0, $"{afterRecycle} slabs still held after the recycle");
            }
            finally
            {
                conn.Dispose();
            }
        });
    }

    // Fills the primary slab and Spilled more, returning where each spilled one starts.
    private static HashSet<nint> Spill(TcpConnection conn)
    {
        conn.Advance(conn.GetSpan(Slab).Length);
        var starts = new HashSet<nint>();
        for (int i = 0; i < Spilled; i++)
        {
            Span<byte> span = conn.GetSpan(Slab);
            starts.Add((nint)Unsafe.AsPointer(ref MemoryMarshal.GetReference(span)));
            conn.Advance(span.Length);
        }
        return starts;
    }

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_spareSlabs")]
    private static extern ref Stack<nint>? Spares(TcpConnection conn);
}
