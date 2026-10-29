using System.Buffers;
using System.IO.Pipelines;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Text;
using ioxide;
using ioxide.tls;

namespace Ioxide.Tests;

/// <summary>
/// TLS on incremental mode's per-connection rings with BoringSSL decrypting, which hands each ciphertext
/// slice back to the ring as it decrypts it: a reader that falls behind pauses its connection on a dry
/// ring and resumes it, as a plaintext one does. The only other TLS test on these rings is the kTLS RX
/// handoff. Ported from kron's TlsIncrementalTest (#427).
/// </summary>
internal static class TlsIncrementalTests
{
    private const int UploadBytes = 4 * 1024 * 1024;

    public static void Register(Runner runner)
    {
        runner.Test("tls incremental: a 4 MiB upload read slowly through the TLS pipe arrives intact, while a second TLS connection is served", () =>
        {
            (string certPath, string keyPath) = TestCert.Ensure();
            var options = new TlsOptions { CertificatePath = certPath, KeyPath = keyPath };
            var upload = new Upload();

            int port = TestServer.StartConfigured(Handler(upload), new ServerConfig
            {
                // Four 4 KiB buffers per connection, a 64th of the upload, so the ring runs dry again and again.
                Incremental = new IncrementalOptions { MaxConnections = 8, RecvSlots = 4, RecvBufferSize = 4096 },
                Tcp = new TcpOptions { WriteSlabSize = 16 * 1024, PoolMax = 8, RecvQueueEntries = 64 },
            }, r => TlsService.Start(r, options)).Port;

            // Its own thread: the write blocks for as long as the server holds back.
            string? answer = null;
            Exception? failure = null;
            var uploader = new Thread(() =>
            {
                try
                {
                    using TcpClient client = Connect(port);
                    using SslStream ssl = Handshake(client);
                    ssl.Write(Pattern(UploadBytes));

                    byte[] two = new byte[2];
                    ssl.ReadExactly(two);
                    answer = Encoding.ASCII.GetString(two);
                }
                catch (Exception e)
                {
                    failure = e;
                }
            })
            {
                IsBackground = true,
                Name = "tls-incremental-upload",
            };
            uploader.Start();

            try
            {
                Assert.True(upload.Holding.Task.Wait(20_000), $"the upload's first read never came: {failure?.Message}");
                TcpConnection holding = upload.Holding.Task.Result;
                Assert.True(Paused(holding), "the upload's ring never ran dry while its reader held back, so it was never paused");
                int waiting = Unread(holding.ClientFd);

                // Handshake and all, a second connection is served while the first waits on its dry ring.
                using (TcpClient client = Connect(port))
                using (SslStream ssl = Handshake(client))
                {
                    byte[] line = "served while the first waits\n"u8.ToArray();
                    ssl.Write(line);

                    byte[] echoed = new byte[line.Length];
                    ssl.ReadExactly(echoed);
                    Assert.True(echoed.AsSpan().SequenceEqual(line),
                        $"the second connection was answered \"{Encoding.ASCII.GetString(echoed)}\"");
                }
                Assert.True(Unread(holding.ClientFd) >= waiting, "the upload resumed while the second connection was being served");

                Volatile.Write(ref upload.Released, 1);
                Assert.True(uploader.Join(60_000), $"the upload never finished; the server saw: {upload.Seen}");
                Assert.True(failure is null, $"the upload failed: {failure?.Message}; the server saw: {upload.Seen}");
                Assert.True(answer == "ok", $"the upload was answered \"{answer}\"; the server saw: {upload.Seen}");
            }
            finally
            {
                Volatile.Write(ref upload.Released, 1);
            }
        }, skip: !TestServer.KernelAtLeast(6, 12));
    }

    // Byte i of the upload: a hash of its position, so a byte lost, repeated or out of place shows.
    private static byte At(long i) => (byte)(((ulong)i * 0x9E3779B97F4A7C15UL) >> 56);

    private static byte[] Pattern(int count)
    {
        var bytes = new byte[count];
        for (int i = 0; i < count; i++)
        {
            bytes[i] = At(i);
        }
        return bytes;
    }

    // The uploading connection, handed over once its reader holds back, then what it read.
    private sealed class Upload
    {
        public readonly TaskCompletionSource<TcpConnection> Holding = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int Released;
        public int Handshakes;
        public volatile string Seen = "nothing yet";
    }

    // The first connection to complete a handshake is the upload; every later one echoes lines.
    private static Func<Reactor, TcpConnection, Task> Handler(Upload upload) => async (reactor, conn) =>
    {
        TlsSession? session = null;
        TlsConnectionDualPipe? pipe = null;
        try
        {
            try
            {
                session = await reactor.GetService<TlsService>()!.AcceptAsync(conn);
            }
            catch
            {
                return;   // the harness probes the port with a raw TCP connection
            }

            pipe = new TlsConnectionDualPipe(conn, session);
            if (Interlocked.Increment(ref upload.Handshakes) == 1)
            {
                await ReadSlowly(reactor, conn, session, pipe, upload);
            }
            else
            {
                await EchoLines(pipe);
            }
        }
        finally
        {
            if (pipe is not null)
            {
                await pipe.DisposeAsync();
            }
            else
            {
                session?.Dispose();
            }
            conn.DecRef();
        }
    };

    /// <summary>
    /// Reads once, holds back until released while the peer floods, then reads the rest with a ring wait
    /// between reads, checking every byte. Answers "ok" for an upload that arrived whole and intact on a
    /// connection that stayed open, with BoringSSL decrypting it, and "no" otherwise.
    /// </summary>
    private static async Task ReadSlowly(Reactor reactor, TcpConnection conn, TlsSession session,
        TlsConnectionDualPipe pipe, Upload upload)
    {
        var tick = new RingOpSource();
        long got = 0;
        long firstWrong = -1;
        int reads = 0;
        bool ended = false;

        try
        {
            while (got < UploadBytes)
            {
                ReadResult result = await pipe.Input.ReadAsync();
                reads++;
                foreach (ReadOnlyMemory<byte> segment in result.Buffer)
                {
                    ReadOnlySpan<byte> bytes = segment.Span;
                    for (int k = 0; k < bytes.Length && firstWrong < 0; k++)
                    {
                        if (bytes[k] != At(got + k))
                        {
                            firstWrong = got + k;
                        }
                    }
                    got += bytes.Length;
                }
                pipe.Input.AdvanceTo(result.Buffer.End);

                if (result.IsCompleted)
                {
                    ended = got < UploadBytes;
                    break;
                }

                if (reads == 1)
                {
                    upload.Holding.TrySetResult(conn);
                    while (Volatile.Read(ref upload.Released) == 0)
                    {
                        await Wait(reactor, tick, 5);
                    }
                }
                await Wait(reactor, tick, 1);
            }
        }
        catch (Exception e)
        {
            upload.Seen = $"a read failed after {got} bytes: {e.Message}";
            throw;
        }

        bool intact = got == UploadBytes && firstWrong < 0 && !ended && !session.KernelRx;
        upload.Seen = $"{got} of {UploadBytes} bytes in {reads} reads, first wrong byte at {firstWrong}, "
            + $"ended early {ended}, kernel RX {session.KernelRx}";

        pipe.Output.Write(intact ? "ok"u8 : "no"u8);
        await pipe.Output.FlushAsync();

        // Until the client has read the answer and gone.
        while (true)
        {
            ReadResult rest = await pipe.Input.ReadAsync();
            pipe.Input.AdvanceTo(rest.Buffer.End);
            if (rest.IsCompleted)
            {
                return;
            }
        }
    }

    // Echoes each line it is sent.
    private static async Task EchoLines(TlsConnectionDualPipe pipe)
    {
        while (true)
        {
            ReadResult result = await pipe.Input.ReadAsync();
            ReadOnlySequence<byte> buffer = result.Buffer;
            SequencePosition? newline = buffer.PositionOf((byte)'\n');

            if (newline is null)
            {
                pipe.Input.AdvanceTo(buffer.Start, buffer.End);
            }
            else
            {
                byte[] line = buffer.Slice(0, buffer.GetPosition(1, newline.Value)).ToArray();
                pipe.Input.AdvanceTo(buffer.GetPosition(1, newline.Value));
                pipe.Output.Write(line);
                await pipe.Output.FlushAsync();
            }

            if (result.IsCompleted)
            {
                return;
            }
        }
    }

    // A wait on the ring, so the handler never leaves the reactor.
    private static async ValueTask Wait(Reactor reactor, RingOpSource tick, int milliseconds)
    {
        ValueTask<int> wait = tick.Prepare();
        reactor.SubmitTimeout(milliseconds * 1_000_000L, tick);
        await wait;
    }

    private static TcpClient Connect(int port)
    {
        var client = new TcpClient();
        client.Connect("127.0.0.1", port);
        client.ReceiveTimeout = 60_000;
        client.SendTimeout = 60_000;
        return client;
    }

    private static SslStream Handshake(TcpClient client)
    {
        var ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: false, (_, _, _, _) => true);
        ssl.AuthenticateAsClient(new SslClientAuthenticationOptions
        {
            TargetHost = "localhost",
            EnabledSslProtocols = SslProtocols.Tls13,
        });
        return ssl;
    }

    /// <summary>
    /// Whether <paramref name="conn"/> is paused: still open, with bytes waiting on its socket that a quarter
    /// of a second later are all still there. An armed recv takes them as they land, so they stay only while
    /// the recv is parked.
    /// </summary>
    private static bool Paused(TcpConnection conn)
    {
        long deadline = Environment.TickCount64 + 10_000;
        int last = -1;
        int still = 0;

        while (Environment.TickCount64 < deadline)
        {
            int waiting = Unread(conn.ClientFd);
            still = waiting > 0 && waiting == last && !conn.IsClosed ? still + 1 : 0;
            if (still == 5)
            {
                return true;
            }

            last = waiting;
            Thread.Sleep(50);
        }

        return false;
    }

    private const ulong Fionread = 0x541B;

    [DllImport("libc", SetLastError = true)]
    private static extern int ioctl(int fd, ulong request, out int value);

    // Bytes received on the socket that nothing has read yet.
    private static int Unread(int fd) => ioctl(fd, Fionread, out int waiting) == 0 ? waiting : -1;
}
