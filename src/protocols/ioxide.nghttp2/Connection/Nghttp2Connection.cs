using System.Buffers;
using System.IO.Pipelines;
using System.Runtime.InteropServices;

namespace ioxide.nghttp2;

/// <summary>
/// Serves HTTP/2 over one accepted <see cref="TcpConnection"/>: nghttp2 owns framing, HPACK and
/// flow control; this owns the socket, the read loop and the handler dispatch.
///
/// <code>
/// reactor.TcpHandle = (r, conn) =>
///     new Nghttp2Connection(conn).RunBufferedAsync(request => Nghttp2Response.Text("hello"));
/// </code>
///
/// This is the mirror of the HTTP/3 side's <c>Nghttp3Connection</c> and takes the same shape, but
/// the insides differ for a reason worth knowing: nghttp3 gets streams, multiplexing and flow
/// control from QUIC underneath it, while HTTP/2 has to build all three on ONE TCP byte stream. So
/// the loop here looks like the HTTP/2 client's - feed <c>ih2_read</c>, drain <c>ih2_write</c> -
/// rather than like its HTTP/3 counterpart.
///
/// It speaks to an <see cref="IDuplexPipe"/> and therefore knows nothing about TLS. Hand it a
/// <c>TcpConnectionDualPipe</c> for h2c, or a <c>TlsConnectionDualPipe</c> for h2 over TLS, or a
/// pipe over anything else - the protocol code is identical in every case, and the transport is
/// chosen where the connection is accepted.
/// </summary>
/// <remarks>
/// Reactor thread only. nghttp2's callbacks fire INSIDE <c>ih2_read</c>, so they may only deposit
/// state - requests are recorded there and dispatched after the native call unwinds, because
/// handing control to a handler mid-<c>mem_recv</c> would let it re-enter the session.
/// </remarks>
public sealed partial class Nghttp2Connection : IDisposable
{
    // One frame's payload plus its header is the most mem_send hands back per call; 64 KiB leaves
    // room for several without regrowing.
    private const int EgressBufferSize = 64 * 1024;

    private readonly IDuplexPipe _pipe;
    private readonly Nghttp2Options _options;
    private readonly byte[] _egress = new byte[EgressBufferSize];

    // The connection underneath, when the pipe can name it - for the read timeout, see Owe.
    private readonly TcpConnection? _connection;

    // Requests that have arrived whole and are not answered yet. While there are any, the
    // connection is busy rather than waiting on its peer.
    private int _owed;

    private nint _handle;
    private GCHandle _self;
    private bool _disposed;
    private bool _failed;

    // The first exception a native callback raised, kept for the log line; _failed carries the
    // decision out to the loops, since teardown cannot happen inside a callback.
    private Exception? _callbackFault;

    // Requests still being assembled, keyed by stream. A request only leaves here when its stream
    // ends, which is when it becomes dispatchable.
    private readonly Dictionary<int, PendingRequest> _pending = new();

    // Requests whose streams ended during the current ih2_read. The callbacks only record them;
    // the loop dispatches after mem_recv returns.
    private readonly List<PendingRequest> _readyThisPass = [];

    /// <summary>
    /// Serve over an already-chosen transport. The pipe is the caller's to dispose - it may be a
    /// TLS pipe with a session behind it, and only the caller knows.
    /// </summary>
    public Nghttp2Connection(IDuplexPipe pipe, Nghttp2Options? options = null)
    {
        _pipe = pipe;
        _options = options ?? new Nghttp2Options();
        _connection = (pipe as ITcpConnectionPipe)?.Connection;
        Setup();
    }

    /// <summary>
    /// A request's stream ended, so this side owes its response. While any response is owed the
    /// connection's read timeout is suspended: the read loop stays parked for the next frame the
    /// whole time a handler works, and a slow answer to one request must not time out the
    /// connection it shares with the others. Once nothing is owed, the connection is waiting on
    /// its peer again and the clock resumes.
    /// </summary>
    private void Owe(PendingRequest pending)
    {
        if (pending.Owed)
        {
            return;
        }
        pending.Owed = true;

        if (_owed++ == 0)
        {
            _connection?.SuspendReadTimeout();
        }
    }

    /// <summary>The response is done, or will never be: every end of a request disposes it.</summary>
    private void Settle(PendingRequest pending)
    {
        if (!pending.Owed)
        {
            return;
        }
        pending.Owed = false;

        if (--_owed == 0)
        {
            _connection?.ResumeReadTimeout();
        }
    }

    /// <summary>Convenience for cleartext h2c: wraps the connection in its own duplex pipe.</summary>
    public Nghttp2Connection(TcpConnection connection, Nghttp2Options? options = null)
        : this(new TcpConnectionDualPipe(connection), options)
    {
    }

    /// <summary>True once the session can serve no more - protocol error, or the peer is gone.</summary>
    public bool IsBroken => _failed || _disposed;

    private unsafe void Setup()
    {
        _self = GCHandle.Alloc(this);

        var callbacks = new Nghttp2.Callbacks
        {
            OnBeginHeaders = &CallbackBeginHeaders,
            OnHeader       = &CallbackHeader,
            OnEndHeaders   = &CallbackEndHeaders,
            OnData         = &CallbackData,
            OnEndStream    = &CallbackEndStream,
            OnStreamError  = &CallbackStreamError,
        };

        _handle = Nghttp2.ih2_server_new(callbacks, (void*)GCHandle.ToIntPtr(_self));
        if (_handle == 0)
        {
            _failed = true;
        }
    }

    /// <summary>Send GOAWAY and stop accepting new streams. In-flight ones still finish.</summary>
    public void Shutdown() => _failed = true;

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;

        if (_handle != 0)
        {
            Nghttp2.ih2_free(_handle);
            _handle = 0;
        }
        if (_self.IsAllocated)
        {
            _self.Free();
        }

        foreach (PendingRequest pending in _pending.Values)
        {
            pending.Dispose();
        }
        _pending.Clear();
    }

    /// <summary>
    /// One request being assembled. Header bytes and body bytes land in a single pooled arena and
    /// are described by ranges, because nothing can be turned into a memory until the arena has
    /// stopped growing.
    /// </summary>
    private sealed class PendingRequest : IDisposable
    {
        private byte[] _arena = [];
        private int _used;
        private readonly List<(int NameOffset, int NameLength, int ValueOffset, int ValueLength)> _fields = [];
        private (int Offset, int Length) _body = (0, 0);

        public int StreamId;

        // The connection counting this request among those it owes an answer (Owe/Settle).
        public Nghttp2Connection? Owner;
        public bool Owed;

        // Pseudo-header ranges, lifted out of the field list as they arrive.
        public (int Offset, int Length) Method;
        public (int Offset, int Length) Path;
        public (int Offset, int Length) Scheme;
        public (int Offset, int Length) Authority;

        public (int Offset, int Length) Append(ReadOnlySpan<byte> data)
        {
            if (_arena.Length - _used < data.Length)
            {
                // In long: the doubling overflows int past 1 GiB, and Rent would then throw from
                // inside a native callback, which is fatal rather than a failed request.
                long size = Math.Max(4096, (long)_arena.Length * 2);
                while (size < (long)_used + data.Length)
                {
                    size *= 2;
                }

                byte[] grown = ArrayPool<byte>.Shared.Rent((int)Math.Min(size, Array.MaxLength));
                _arena.AsSpan(0, _used).CopyTo(grown);
                if (_arena.Length > 0)
                {
                    ArrayPool<byte>.Shared.Return(_arena);
                }
                _arena = grown;
            }

            data.CopyTo(_arena.AsSpan(_used));
            (int Offset, int Length) range = (_used, data.Length);
            _used += data.Length;
            return range;
        }

        public void AddField((int Offset, int Length) name, (int Offset, int Length) value)
            => _fields.Add((name.Offset, name.Length, value.Offset, value.Length));

        public void AppendBody(ReadOnlySpan<byte> data)
        {
            (int Offset, int Length) range = Append(data);
            if (_body.Length == 0)
            {
                _body = range;
            }
            else
            {
                // Contiguous by construction: body chunks are appended back to back with nothing
                // else in between once headers are done.
                _body.Length += range.Length;
            }
        }

        /// <summary>Materialize the public request. Valid until <see cref="Dispose"/>.</summary>
        public Nghttp2Request Freeze()
        {
            var request = new Nghttp2Request
            {
                StreamId  = StreamId,
                Method    = Slice(Method),
                Path      = Slice(Path),
                Scheme    = Slice(Scheme),
                Authority = Slice(Authority),
                Body      = Slice(_body),
            };

            foreach ((int nameOffset, int nameLength, int valueOffset, int valueLength) in _fields)
            {
                request.Headers.Add(_arena.AsMemory(nameOffset, nameLength),
                                    _arena.AsMemory(valueOffset, valueLength));
            }

            return request;
        }

        private ReadOnlyMemory<byte> Slice((int Offset, int Length) range)
            => range.Length == 0 ? default : _arena.AsMemory(range.Offset, range.Length);

        public void Dispose()
        {
            Owner?.Settle(this);

            _fields.Clear();
            if (_arena.Length > 0)
            {
                ArrayPool<byte>.Shared.Return(_arena);
                _arena = [];
            }
            _used = 0;
        }
    }
}
