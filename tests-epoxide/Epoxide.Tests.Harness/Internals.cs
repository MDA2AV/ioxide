using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;
using epoxide;

namespace Epoxide.Tests;

/// <summary>
/// What a test needs to see inside epoxide that its public surface does not show: how many recv
/// buffers are out, a connection's generation, whether its slab is still allocated. epoxide grants
/// no InternalsVisibleTo and the tests never edit the runtime, so these are read the way ioxide's
/// tests read private fields - UnsafeAccessor where the member's type is public, reflection where it
/// is not (BufferPool is internal).
/// </summary>
public static unsafe class Internals
{
    private const BindingFlags Instance = BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public;
    private const BindingFlags Static = BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public;

    // ---- buffer pools ---------------------------------------------------------------------------

    /// <summary>A pool's buffers: every one it has allocated, and how many of those are free.</summary>
    public readonly record struct PoolCount(int Total, int Free)
    {
        /// <summary>Out with a reader or a writer right now.</summary>
        public int Rented => Total - Free;
    }

    private static readonly FieldInfo RecvPoolField = Field(typeof(Reactor), "RecvPool");
    private static readonly FieldInfo WriteSlabPoolField = Field(typeof(Reactor), "WriteSlabPool");
    private static readonly Type BufferPoolType = RecvPoolField.FieldType;
    private static readonly FieldInfo PoolHead = Field(BufferPoolType, "_head");
    private static readonly FieldInfo PoolChunks = Field(BufferPoolType, "_chunks");
    private static readonly FieldInfo PoolChunkCount = Field(BufferPoolType, "_chunkCount");
    private static readonly FieldInfo PoolBufferSize = Field(BufferPoolType, "_bufferSize");
    private static readonly int ChunkShift = (int)Field(BufferPoolType, "ChunkShift", Static).GetRawConstantValue()!;

    /// <summary>The reactor's recv buffers, counted on its thread (see <see cref="OnReactor{T}"/>).</summary>
    public static PoolCount RecvPool(Reactor reactor) => OnReactor(reactor, () => CountPool(RecvPoolField.GetValue(reactor)!));

    /// <summary>The reactor's spare write slabs (segmented overflow), counted on its thread.</summary>
    public static PoolCount WriteSlabPool(Reactor reactor) => OnReactor(reactor, () => CountPool(WriteSlabPoolField.GetValue(reactor)!));

    /// <summary>
    /// Total from the chunk count, free by walking the free list exactly as BufferPool.TryFree does.
    /// The walk is capped at the total, so a list that moved under it cannot loop forever.
    /// </summary>
    private static PoolCount CountPool(object pool)
    {
        long head = (long)PoolHead.GetValue(pool)!;
        var chunks = (nint[])PoolChunks.GetValue(pool)!;
        int total = (int)PoolChunkCount.GetValue(pool)! << ChunkShift;
        int size = (int)PoolBufferSize.GetValue(pool)!;
        int mask = (1 << ChunkShift) - 1;

        int free = 0;
        for (int top = (int)head - 1; top >= 0 && free <= total; free++)
        {
            byte* buffer = (byte*)chunks[top >> ChunkShift] + (nint)(top & mask) * size;
            top = *(int*)buffer;
        }

        return new PoolCount(total, free);
    }

    // ---- connections ----------------------------------------------------------------------------

    /// <summary>Bumped on every recycle, so a changed value means the connection went through the pool.</summary>
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_generation")]
    public static extern ref int Generation(TcpConnection connection);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "WriteBuffer")]
    private static extern ref byte* WriteBufferOf(TcpConnection connection);

    /// <summary>Whether the connection's native write slab is still allocated.</summary>
    public static bool HasWriteBuffer(TcpConnection connection) => WriteBufferOf(connection) != null;

    /// <summary>The handler's ref plus the reactor's: 2 while both hold it, 0 once it is recycled.</summary>
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_refs")]
    public static extern ref int Refs(TcpConnection connection);

    /// <summary>The reactor's end of a connection: wakes a parked read with the end and releases a parked flush.</summary>
    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "MarkClosed")]
    public static extern void MarkClosed(TcpConnection connection);

    // ---- reactors -------------------------------------------------------------------------------

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_epfd")]
    public static extern ref int EpollFd(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_wakeFd")]
    public static extern ref int WakeFd(Reactor reactor);

    /// <summary>Connections handed out and not yet recycled, wherever their handlers are.</summary>
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_liveConnections")]
    public static extern ref int LiveConnections(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_pool")]
    private static extern ref Stack<TcpConnection> PoolOf(Reactor reactor);

    /// <summary>Connection objects waiting in the reactor's pool for the next accept, counted on its thread.</summary>
    public static int Pooled(Reactor reactor) => OnReactor(reactor, () => PoolOf(reactor).Count);

    /// <summary>Whether the pool holds this very object - the proof a later accept could be handed it.</summary>
    public static bool InPool(Reactor reactor, TcpConnection connection)
        => OnReactor(reactor, () => PoolOf(reactor).Contains(connection));

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_postSignalPending")]
    public static extern ref int PostSignalPending(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "DrainPostQ")]
    public static extern void DrainPostQ(Reactor reactor);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "get_Stopped")]
    private static extern bool StoppedOf(Reactor reactor);

    /// <summary>Whether the reactor has finished its teardown.</summary>
    public static bool Stopped(Reactor reactor) => StoppedOf(reactor);

    private static readonly FieldInfo TimersField = Field(typeof(Reactor), "_timers");
    private static readonly PropertyInfo TimersCount = TimersField.FieldType.GetProperty("Count")!;

    /// <summary>One-shot timers armed on the reactor and not yet expired, counted on its thread.</summary>
    public static int PendingTimers(Reactor reactor)
        => OnReactor(reactor, () => (int)TimersCount.GetValue(TimersField.GetValue(reactor))!);

    // ---- native ---------------------------------------------------------------------------------

    /// <summary>Whether <see cref="Native.MonotonicMs"/> found the vDSO's clock_gettime.</summary>
    public static bool MonotonicMsFromVdso
        => (bool)typeof(Native).GetProperty("MonotonicMsFromVdso", Static)!.GetValue(null)!;

    // ---- plumbing -------------------------------------------------------------------------------

    /// <summary>
    /// Run <paramref name="read"/> on the reactor's own thread and hand back what it returned - for
    /// state the reactor mutates without locks. A stopped reactor runs nothing, so then it runs here.
    /// </summary>
    public static T OnReactor<T>(Reactor reactor, Func<T> read, int timeoutMs = 10_000)
    {
        if (reactor.OnReactorThread || Stopped(reactor))
        {
            return read();
        }

        T result = default!;
        Exception? failure = null;
        using var done = new ManualResetEventSlim();
        reactor.ScheduleOnReactor(_ =>
        {
            try
            {
                result = read();
            }
            catch (Exception e)
            {
                failure = e;
            }
            finally
            {
                done.Set();
            }
        }, null);

        if (!done.Wait(timeoutMs))
        {
            throw new TimeoutException($"the reactor did not run a posted read within {timeoutMs} ms");
        }

        if (failure is not null)
        {
            ExceptionDispatchInfo.Capture(failure).Throw();
        }
        return result;
    }

    private static FieldInfo Field(Type type, string name, BindingFlags flags = Instance)
        => type.GetField(name, flags) ?? throw new MissingFieldException(type.FullName, name);
}
