using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using static ioxide.Native;

namespace ioxide;

/// <summary>
/// The reactor as an <see cref="IRingHost"/>. Each client submission allocates a slot holding its
/// completion; the CQE carries the slot in user_data, so routing is O(1) and per-operation -
/// concurrent ops on the same fd never collide and nothing is registered around fd lifetimes.
/// The engine knows nothing about client types.
/// </summary>
public sealed unsafe partial class Reactor : IRingHost
{
    // In-flight client ops: slot → completion. Reactor-thread-only; grows on demand.
    private IRingCompletion?[] _opTargets = new IRingCompletion?[1024];

    // One timespec per op slot, for IORING_OP_TIMEOUT. The kernel reads it while the op is in
    // flight, so it has to outlive the submission; hanging it off the slot makes its lifetime
    // exactly the operation's, with no allocation per wait.
    private __kernel_timespec* _opTimespecs;
    private int _opTimespecCapacity;
    private int[] _opFree = null!;
    private int   _opFreeTop;

    // Off-reactor submissions marshal here (single-issuer SQ).
    private readonly record struct RemoteOp(byte Opcode, int Fd, nint Buffer, int Length, long Offset, IRingCompletion Completion);
    private readonly ConcurrentQueue<RemoteOp> _remoteOps = new();

    // Typed per-reactor services (clients opened in OnStart; handlers fetch them).
    private readonly Dictionary<Type, object> _services = new();

    public void AddService<T>(T service) where T : class
    {
        _services[typeof(T)] = service;
    }

    /// <summary>
    /// Get a service registered with <see cref="AddService{T}"/>; throws if absent.
    /// </summary>
    public T GetService<T>() where T : class
    {
        return _services.TryGetValue(typeof(T), out object? service)
            ? (T)service
            : throw new InvalidOperationException(
                $"No {typeof(T).Name} registered on reactor {_id}. Register it from OnStart with AddService.");
    }

    /// <summary>
    /// Runs on the reactor thread before the loop starts - open ring-native clients here.
    /// </summary>
    public Action<Reactor>? OnStart;

    /// <summary>
    /// The per-connection TCP handler, invoked once per accepted connection (CQE accept path).
    /// </summary>
    public Func<Reactor, TcpConnection, Task> TcpHandle = null!;

    /// <summary>
    /// Raised on the reactor's own thread when it is ending because of a fault rather than a
    /// <see cref="Stop"/>, after the ring has been torn down. Handle it to log, restart, or bring
    /// the process down deliberately.
    /// </summary>
    /// <remarks>
    /// Without a handler the exception propagates out of <see cref="Run"/>, which on a bare
    /// <c>new Thread(reactor.Run)</c> terminates the process. Which of the two is right is the
    /// host's call: losing one shard of N silently is as bad as taking the server down unasked.
    /// </remarks>
    public Action<Reactor, Exception>? OnFault;

    /// <summary>
    /// The per-connection QUIC handler, invoked once per adopted connection (CID demux path).
    /// Null: no handler is launched (raw engine mode, e.g. a custom <see cref="QuicConnection"/>
    /// subclass consuming its own events).
    /// </summary>
    public Func<Reactor, QuicConnection, Task>? QuicHandle;

    public void SubmitConnect(int fd, nint sockaddr, int sockaddrLen, IRingCompletion completion)
    {
        // CONNECT: sockaddr in addr, its length in off, len stays 0.
        SubmitClientOp(IORING_OP_CONNECT, fd, sockaddr, length: 0, offset: sockaddrLen, completion);
    }

    public void SubmitSend(int fd, nint buffer, int length, IRingCompletion completion)
    {
        SubmitClientOp(IORING_OP_SEND, fd, buffer, length, offset: 0, completion);
    }

    public void SubmitRecv(int fd, nint buffer, int length, IRingCompletion completion)
    {
        SubmitClientOp(IORING_OP_RECV, fd, buffer, length, offset: 0, completion);
    }

    public void SubmitRead(int fd, nint buffer, int length, long offset, IRingCompletion completion)
    {
        SubmitClientOp(IORING_OP_READ, fd, buffer, length, offset, completion);
    }

    public void SubmitWrite(int fd, nint buffer, int length, long offset, IRingCompletion completion)
    {
        SubmitClientOp(IORING_OP_WRITE, fd, buffer, length, offset, completion);
    }

    /// <summary>
    /// Completes after <paramref name="nanoseconds"/>, on this reactor. Shares the slot table and
    /// completion routing with the fd ops, but not their submission: a timeout carries a deadline
    /// where they carry a buffer, so it fills its own SQE rather than putting a branch in theirs.
    /// </summary>
    public void SubmitTimeout(long nanoseconds, IRingCompletion completion)
    {
        if (Environment.CurrentManagedThreadId != _reactorThreadId && _reactorThreadId != 0)
        {
            // The duration rides in the offset field of the queued record, which a timeout
            // otherwise leaves unused.
            HandOff(IORING_OP_TIMEOUT, fd: -1, buffer: 0, length: 0, nanoseconds, completion);
            return;
        }

        SubmitTimeoutCore(nanoseconds, completion);
    }

    private void SubmitTimeoutCore(long nanoseconds, IRingCompletion completion)
    {
        int slot = AllocOpSlot(completion);
        EnsureTimespecCapacity();

        // The deadline cannot be resolved before the slot is: the address the SQE carries is
        // this slot's.
        __kernel_timespec* ts = _opTimespecs + slot;
        long ns = nanoseconds < 1 ? 1 : nanoseconds;
        ts->tv_sec  = ns / 1_000_000_000L;
        ts->tv_nsec = ns % 1_000_000_000L;

        // No fd and no buffer: addr points at the deadline and len=1 says it is one timespec.
        // off stays 0, so this is purely time-based rather than also waiting on a number of
        // completions.
        Emit(IORING_OP_TIMEOUT, fd: -1, addr: (ulong)ts, len: 1, off: 0, slot);
    }

    private void SubmitClientOp(byte opcode, int fd, nint buffer, int length, long offset, IRingCompletion completion)
    {
        // Off-reactor callers hand over and wake, like every other producer.
        if (Environment.CurrentManagedThreadId != _reactorThreadId && _reactorThreadId != 0)
        {
            HandOff(opcode, fd, buffer, length, offset, completion);
            return;
        }

        SubmitClientOpCore(opcode, fd, buffer, length, offset, completion);
    }

    /// <summary>
    /// The SQ has one issuer, so a caller on any other thread queues the op and wakes the reactor
    /// to submit it on its own. Kept out of the submitters - the thread test stays there, this is
    /// the cold half and is marked so it does not get inlined back into a path that never runs it.
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private void HandOff(byte opcode, int fd, nint buffer, int length, long offset, IRingCompletion completion)
    {
        _remoteOps.Enqueue(new RemoteOp(opcode, fd, buffer, length, offset, completion));
        WakeFdWrite();
    }

    private void SubmitClientOpCore(byte opcode, int fd, nint buffer, int length, long offset, IRingCompletion completion)
    {
        int slot = AllocOpSlot(completion);
        Emit(opcode, fd, (ulong)buffer, (uint)length, (ulong)offset, slot);
    }

    /// <summary>
    /// Writes one SQE and tags it for the client dispatch. Every client op ends here, whatever its
    /// fields mean: a buffer and a length for the fd ops, a deadline and a count of one for a
    /// timeout.
    /// </summary>
    private void Emit(byte opcode, int fd, ulong addr, uint len, ulong off, int slot)
    {
        IoUringSqe* sqe = GetSqeOrFlush();
        Unsafe.InitBlockUnaligned(sqe, 0, 64);

        sqe->opcode    = opcode;
        sqe->fd        = fd;
        sqe->addr      = addr;
        sqe->len       = len;
        sqe->off       = off;
        sqe->user_data = Tag(KindClient, 0, slot);
    }

    private void DrainRemoteOps()
    {
        while (_remoteOps.TryDequeue(out RemoteOp op))
        {
            // The only place the two submissions have to be told apart, and off the hot path:
            // once per cross-thread handover, not once per op.
            if (op.Opcode == IORING_OP_TIMEOUT)
            {
                SubmitTimeoutCore(op.Offset, op.Completion);
            }
            else
            {
                SubmitClientOpCore(op.Opcode, op.Fd, op.Buffer, op.Length, op.Offset, op.Completion);
            }
        }
    }

    // Grown to match _opTargets, so a slot always has a timespec behind it.
    private void EnsureTimespecCapacity()
    {
        if (_opTimespecCapacity >= _opTargets.Length)
        {
            return;
        }

        nuint bytes = (nuint)(_opTargets.Length * sizeof(__kernel_timespec));
        _opTimespecs = _opTimespecs == null
            ? (__kernel_timespec*)NativeMemory.Alloc(bytes)
            : (__kernel_timespec*)NativeMemory.Realloc(_opTimespecs, bytes);
        _opTimespecCapacity = _opTargets.Length;
    }

    private int AllocOpSlot(IRingCompletion completion)
    {
        if (_opFree == null)
        {
            _opFree = new int[_opTargets.Length];
            for (int i = 0; i < _opFree.Length; i++)
            {
                _opFree[i] = _opFree.Length - 1 - i;
            }
            _opFreeTop = _opFree.Length;
        }

        if (_opFreeTop == 0)
        {
            int oldLength = _opTargets.Length;
            Array.Resize(ref _opTargets, oldLength * 2);
            Array.Resize(ref _opFree, oldLength * 2);
            for (int i = oldLength * 2 - 1; i >= oldLength; i--)
            {
                _opFree[_opFreeTop++] = i;
            }
        }

        int slot = _opFree[--_opFreeTop];
        _opTargets[slot] = completion;
        return slot;
    }
}
