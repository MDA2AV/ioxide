using System.Buffers;
using System.IO.Pipelines;
using ioxide;
using ioxide.tls;
using ioxide.utils;

namespace ioxide.Kestrel;

/// <summary>
/// A Kestrel transport duplex over an ioxide <see cref="TcpConnection"/>: two BCL <see cref="Pipe"/>s whose
/// reader schedulers route to the reactor thread (via <see cref="ReactorPipeScheduler"/>), plus a
/// recv→inbound pump and an outbound→send pump that run on the reactor. This pins Kestrel's whole request
/// loop to the reactor thread. One copy each way (recv bytes into the inbound pipe; response bytes into
/// the connection slab).
/// </summary>
internal sealed class HopDuplexPipe : IDuplexPipe, IAsyncDisposable
{
    private readonly TcpConnection _conn;
    private readonly Reactor _reactor;
    private readonly TlsSession? _tls;   // non-null on a TLS-terminated connection
    private readonly Pipe _inbound;    // recv pump writes; Kestrel reads (Transport.Input)
    private readonly Pipe _outbound;   // Kestrel writes (Transport.Output); send pump reads
    private readonly PipeReader _input; // Kestrel's Input - pins the first read onto the reactor thread

    private Task _recvPump = Task.CompletedTask;
    private Task _sendPump = Task.CompletedTask;
    private int _started;

    [System.Runtime.InteropServices.DllImport("libc", EntryPoint = "shutdown")]
    private static extern int Shutdown(int sockfd, int how);
    private const int ShutWr = 1;   // SHUT_WR

    // Pipe backpressure thresholds (bytes). Inbound (recv -> Kestrel's parser) is given a megabyte of
    // slack so a fast peer is not throttled mid-request; outbound (Kestrel's response -> the send
    // pump) is tighter, since a stalled response should stop being produced sooner. Each pipe resumes
    // at half its pause mark to avoid flapping.
    private const int InboundPauseBytes  = 1024 * 1024;
    private const int InboundResumeBytes = 512 * 1024;
    private const int OutboundPauseBytes  = 64 * 1024;
    private const int OutboundResumeBytes = 32 * 1024;

    public PipeReader Input => _input;
    public PipeWriter Output => _outbound.Writer;

    public HopDuplexPipe(TcpConnection conn, Reactor reactor, TlsSession? tls = null)
    {
        _conn = conn;
        _reactor = reactor;
        _tls = tls;
        var scheduler = new ReactorPipeScheduler(reactor);

        // Reader schedulers = the reactor: Kestrel's HTTP parse (inbound reader) and the send pump
        // (outbound reader) both run on the reactor thread.
        _inbound = new Pipe(new PipeOptions(
            readerScheduler: scheduler,
            writerScheduler: scheduler,
            pauseWriterThreshold: InboundPauseBytes,
            resumeWriterThreshold: InboundResumeBytes,
            useSynchronizationContext: false));

        _outbound = new Pipe(new PipeOptions(
            readerScheduler: scheduler,
            writerScheduler: PipeScheduler.ThreadPool,
            pauseWriterThreshold: OutboundPauseBytes,
            resumeWriterThreshold: OutboundResumeBytes,
            useSynchronizationContext: false));

        _input = new ReactorPinReader(_inbound.Reader, reactor);
    }

    /// <summary>Launches the recv and send pumps. Must be called on the reactor thread.</summary>
    public void Start()
    {
        if (Interlocked.Exchange(ref _started, 1) == 1)
        {
            return;
        }

        // The recv pump keeps a read parked for the connection's whole life - through a long
        // request and a long download alike - so ioxide's read clock would time out Kestrel's
        // requests rather than its idle connections. Kestrel runs its own clocks for that
        // (KeepAliveTimeout, RequestHeadersTimeout, the minimum data rates), so ours stays off.
        _conn.SuspendReadTimeout();

        _recvPump = RecvPumpAsync();
        _sendPump = SendPumpAsync();
    }

    // Reactor → inbound pipe. Copies (or, for TLS, decrypts) each recv slice into the pipe and flushes;
    // Kestrel reads it. Inbound records are decrypted in userspace by the session.
    private async Task RecvPumpAsync()
    {
        PipeWriter writer = _inbound.Writer;
        Exception? fault = null;
        try
        {
            // TLS: the client's first request can ride in bundled with its Finished flight (already
            // decrypted during the handshake). Hand it to Kestrel before the first recv.
            if (_tls is not null)
            {
                ReadOnlySpan<byte> initial = _tls.DrainPlaintext();
                if (!initial.IsEmpty)
                {
                    writer.Write(initial);
                    FlushResult ifr = await writer.FlushAsync();
                    if (ifr.IsCompleted || ifr.IsCanceled)
                    {
                        return;
                    }
                }
            }

            while (true)
            {
                RecvSnapshot snap = await _conn.ReadAsync();

                while (_conn.TryGetItem(snap, out SpscRecvRing.Item item))
                {
                    if (item.HasBuffer && item.Len > 0)
                    {
                        if (_tls is null)
                        {
                            CopySlice(in item, writer);
                        }
                        else
                        {
                            DecryptSlice(in item, writer, _tls);
                        }
                    }
                    _conn.ReturnBuffer(in item);
                }
                _conn.ResetRead();

                // Peer close: a TCP FIN, or (TLS) a clean close_notify decoded by the session.
                if (snap.IsClosed || (_tls is not null && _tls.Closed))
                {
                    break;
                }

                FlushResult fr = await writer.FlushAsync();
                if (fr.IsCompleted || fr.IsCanceled)
                {
                    break;
                }
            }
        }
        catch (Exception e)
        {
            // Kept, not swallowed. This pump decrypts, so the exceptions reaching here include a
            // bad MAC and a truncated record - and completing the pipe CLEANLY on those makes an
            // attack that cuts a connection short indistinguishable from a peer hanging up
            // politely (the property TlsDecryptingPipeReader documents).
            fault = e;
        }
        finally
        {
            await writer.CompleteAsync(fault);
        }
    }

    private static unsafe void CopySlice(in SpscRecvRing.Item item, PipeWriter writer)
    {
        Span<byte> dst = writer.GetSpan(item.Len);
        new ReadOnlySpan<byte>(item.Ptr, item.Len).CopyTo(dst);
        writer.Advance(item.Len);
    }

    // Feed the ciphertext slice through OpenSSL and write the plaintext. DecryptInto rather than
    // Decrypt so OpenSSL writes into the pipe's own memory - Decrypt lands the plaintext in the
    // session's buffer first and we would copy it again on the way here.
    private static unsafe void DecryptSlice(in SpscRecvRing.Item item, PipeWriter writer, TlsSession tls)
        => tls.DecryptInto(item.Ptr, item.Len, writer);

    // Outbound pipe → connection send. Drains Kestrel's response into the slab and submits one SEND.
    private async Task SendPumpAsync()
    {
        PipeReader reader = _outbound.Reader;
        Exception? fault = null;
        try
        {
            while (true)
            {
                ReadResult rr = await reader.ReadAsync();
                ReadOnlySequence<byte> buffer = rr.Buffer;

                if (!buffer.IsEmpty)
                {
                    foreach (ReadOnlyMemory<byte> segment in buffer)
                    {
                        if (_tls is null)
                        {
                            Span<byte> dst = _conn.GetSpan(segment.Length);
                            segment.Span.CopyTo(dst);
                            _conn.Advance(segment.Length);
                        }
                        else
                        {
                            // Correct in both TLS modes: under kTLS TX the plaintext goes into the
                            // slab as-is (the kernel makes the records on send); by default OpenSSL
                            // encrypts here. A bare slab copy would put CLEARTEXT on the wire for
                            // every configuration that did not opt into the kernel path.
                            _tls.Write(_conn, segment.Span);
                        }
                    }
                    await _conn.FlushAsync();
                }

                reader.AdvanceTo(buffer.End);

                if (rr.IsCompleted || rr.IsCanceled)
                {
                    break;
                }
            }
        }
        catch (Exception e)
        {
            // Same reasoning as the recv pump: a failed encrypt is not a drained stream.
            fault = e;
        }
        finally
        {
            await reader.CompleteAsync(fault);
        }
    }

    public async ValueTask DisposeAsync()
    {
        // Quiesce the send side BEFORE closing. Wake the send pump if it's parked on the output reader and
        // await it, so any in-flight SEND completes normally and the full response is flushed. Draining here
        // - rather than concurrently with MarkClosed - is what makes the response reliably reach the client
        // and avoids completing a live flush twice (MarkClosed racing the SEND CQE's CompleteFlush).
        _outbound.Reader.CancelPendingRead();
        try
        {
            await _sendPump.ConfigureAwait(false);
        } catch { }

        if (_tls is null)
        {
            // Plaintext: half-close the write side so EOF-delimited clients (TcpConnection: close / upgrade)
            // see the end of the response now - ioxide sends its own FIN only when the listener lets go
            // of the connection, after the pumps below have unwound. Then wake and unwind the recv side
            // (MarkClosed wakes a recv parked in conn.ReadAsync - schedule it on the reactor so the
            // continuation runs there, not the dispose thread).
            Shutdown(_conn.ClientFd, ShutWr);
            _reactor.ScheduleOnReactor(static c => ((TcpConnection)c!).MarkClosed(), _conn);
            _inbound.Writer.CancelPendingFlush();
            try
            {
                await _recvPump.ConfigureAwait(false);
            } catch { }
        }
        else
        {
            // TLS: unwind the recv side FIRST so the recv pump stops touching the session, then dispose it
            // - that sends close_notify (a raw teardown send in either backend, which must precede the FIN
            // while the write side is still open) and frees the SSL - then FIN.
            _reactor.ScheduleOnReactor(static c => ((TcpConnection)c!).MarkClosed(), _conn);
            _inbound.Writer.CancelPendingFlush();
            try
            {
                await _recvPump.ConfigureAwait(false);
            } catch { }
            _tls.Dispose();
            Shutdown(_conn.ClientFd, ShutWr);
        }
    }
}
