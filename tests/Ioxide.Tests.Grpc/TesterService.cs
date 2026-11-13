using System.Buffers;
using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using Google.Protobuf;
using Grpc.Core;
using Grpc.Net.Client;
using ioxide;
using ioxide.grpc;
using ioxide.http2;
using ioxide.tls;
using Ioxide.Tests.Grpc;

namespace Ioxide.Tests;

/// <summary>What a test learns from the server side of its calls.</summary>
internal sealed class Probe
{
    public readonly TaskCompletionSource<ServerCallContext> Held = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public readonly TaskCompletionSource Cancelled = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public readonly TaskCompletionSource<Exception> StreamFault = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public readonly TaskCompletionSource<int> Collected = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public readonly TaskCompletionSource Release = new();   // inline: a method waiting on it resumes on the releasing thread
    public int Calls;
    public int Connections;   // accepted by the server, so a test can tell a reconnect from the same connection
    public int Holding;
    public int Cancels;
    public CancellationToken Token;
    public volatile bool CancelledOnReactor;
    public volatile bool TokenSetAtFault;
}

/// <summary>The service under test: each method does what the Ask tells it, and reports to its probe.</summary>
internal sealed class TesterService(Probe probe) : Tester.TesterBase
{
    public override async Task<Reply> Unary(Ask request, ServerCallContext context)
    {
        int call = Interlocked.Increment(ref probe.Calls);
        if (request.TakeToken)
        {
            probe.Token = context.CancellationToken;
        }
        if (request.FailFirst && call == 1)
        {
            throw new RpcException(new Status(StatusCode.Unavailable, "try again"));
        }
        if (request.ThrowCancelled)
        {
            throw new OperationCanceledException("the method's own timeout");
        }
        if (request.BadTrailer.Length > 0)
        {
            context.ResponseTrailers.Add("x-bad", request.BadTrailer);
            context.ResponseTrailers.Add("x-good", "ok");
        }
        await EchoMetadataAsync(context);
        for (int i = 0; i < request.Trailers; i++)
        {
            context.ResponseTrailers.Add($"x-t-{i}", "v");
        }
        End(request, context);
        return new Reply
        {
            Text = request.Text,
            Body = request.Body,
            Method = context.Method,
            Deadline = context.Deadline == DateTime.MaxValue ? "" : context.Deadline.ToString("o"),
        };
    }

    public override async Task Replies(Ask request, IServerStreamWriter<Reply> responseStream, ServerCallContext context)
    {
        await EchoMetadataAsync(context);
        if (request.TakeToken)
        {
            context.CancellationToken.Register(() => probe.Cancelled.TrySetResult());
        }
        ByteString body = ByteString.CopyFrom(new byte[request.ReplySize]);
        try
        {
            for (int i = 0; i < request.Replies; i++)
            {
                await responseStream.WriteAsync(new Reply { Index = i, Body = body });
                if (request.WaitToken && i == 0)
                {
                    await Cancelled(context.CancellationToken);   // the client cancels after the first reply
                }
            }
        }
        catch (Exception e)
        {
            probe.TokenSetAtFault = context.CancellationToken.IsCancellationRequested;
            probe.StreamFault.TrySetResult(e);
            throw;
        }
        End(request, context);
    }

    // A message with a status ends the call there, with the client possibly still sending.
    public override async Task<Reply> Collect(IAsyncStreamReader<Ask> requestStream, ServerCallContext context)
    {
        long total = 0;
        int count = 0;
        Ask? last = null;
        try
        {
            while (await requestStream.MoveNext(CancellationToken.None))
            {
                last = requestStream.Current;
                total += last.Body.Length;
                count++;
                if (last.Status != 0)
                {
                    break;
                }
            }
        }
        catch (Exception e)
        {
            probe.StreamFault.TrySetResult(e);
            throw;
        }
        probe.Collected.TrySetResult(count);
        if (last is not null)
        {
            End(last, context);
        }
        return new Reply { Total = total, Count = count };
    }

    public override async Task Echo(IAsyncStreamReader<Ask> requestStream, IServerStreamWriter<Reply> responseStream, ServerCallContext context)
    {
        int index = 0;
        try
        {
            while (await requestStream.MoveNext(CancellationToken.None))
            {
                Ask ask = requestStream.Current;
                await responseStream.WriteAsync(new Reply { Text = ask.Text, Body = ask.Body, Index = index++ });
            }
        }
        catch (Exception e)
        {
            probe.StreamFault.TrySetResult(e);
            throw;
        }
    }

    // Waits on the call's own token, so it returns only once the client cancels or its deadline passes.
    public override async Task<Reply> Hold(Ask request, ServerCallContext context)
    {
        Interlocked.Increment(ref probe.Holding);
        if (request.TokenLate)
        {
            probe.Held.TrySetResult(context);
            await probe.Release.Task;
        }

        CancellationToken token = request.TokenElsewhere
            ? OnReactor.CallFromAnotherThread(() => context.CancellationToken)
            : context.CancellationToken;
        var cancelled = new TaskCompletionSource();
        using (token.Register(() =>
        {
            probe.CancelledOnReactor = Reactor.Current is not null;
            cancelled.TrySetResult();
        }))
        {
            probe.Held.TrySetResult(context);
            await cancelled.Task;
        }
        Interlocked.Increment(ref probe.Cancels);
        probe.Cancelled.TrySetResult();
        throw new RpcException(new Status(StatusCode.Cancelled, "held until cancelled"));
    }

    private static async Task Cancelled(CancellationToken token)
    {
        var cancelled = new TaskCompletionSource();
        using (token.Register(() => cancelled.TrySetResult()))
        {
            await cancelled.Task;
        }
    }

    // x-echo and x-echo-bin come back as response headers, and as x-echo-trailer(-bin) trailers.
    private static async Task EchoMetadataAsync(ServerCallContext context)
    {
        Metadata.Entry? text = context.RequestHeaders.Get("x-echo");
        Metadata.Entry? binary = context.RequestHeaders.Get("x-echo-bin");
        if (text is null && binary is null)
        {
            return;
        }

        var headers = new Metadata();
        if (text is not null)
        {
            headers.Add("x-echo", text.Value);
            context.ResponseTrailers.Add("x-echo-trailer", text.Value);
        }
        if (binary is not null)
        {
            headers.Add("x-echo-bin", binary.ValueBytes);
            context.ResponseTrailers.Add("x-echo-trailer-bin", binary.ValueBytes);
        }
        await context.WriteResponseHeadersAsync(headers);
    }

    private static void End(Ask request, ServerCallContext context)
    {
        if (request.Fault)
        {
            throw new InvalidOperationException("the method failed with a secret: hunter2");
        }
        if (request.Status != 0)
        {
            var status = new Status((StatusCode)request.Status, request.Detail);
            if (!request.SetStatus)
            {
                throw new RpcException(status);
            }
            context.Status = status;
        }
    }
}

/// <summary>A reactor serving <see cref="TesterService"/> over h2c.</summary>
internal static class GrpcServer
{
    public static int Start(Probe probe, GrpcOptions? options = null)
        => TestServer.Start(Serve(probe, new GrpcServices(options).Add(Tester.BindService, new TesterService(probe)), mixed: false));

    /// <summary>The same, with its reactor handed back, for a test that stops it.</summary>
    public static (int Port, Reactor Reactor, Thread Thread) StartStoppable(Probe probe)
        => TestServer.StartConfigured(Serve(probe, new GrpcServices().Add(Tester.BindService, new TesterService(probe)), mixed: false),
            TestServer.DefaultConfig());

    /// <summary>A connection that serves gRPC beside plain HTTP/2, telling them apart with IsGrpc.</summary>
    public static int StartMixed(Probe probe)
        => TestServer.Start(Serve(probe, new GrpcServices().Add(Tester.BindService, new TesterService(probe)), mixed: true));

    private static Func<Reactor, TcpConnection, Task> Serve(Probe probe, GrpcServices services, bool mixed) => async (_, conn) =>
    {
        Interlocked.Increment(ref probe.Connections);
        try
        {
            await new Http2Connection(conn).RunAsync((request, body, writer) => mixed && !GrpcServices.IsGrpc(request)
                ? Plain(writer)
                : services.HandleAsync(request, body, writer));
        }
        finally
        {
            conn.DecRef();
        }
    };

    // The plain side of a mixed connection: "plain", and the connection ends the stream.
    private static async ValueTask Plain(Http2ResponseWriter writer)
    {
        writer.WriteHeaders(new Http2Response());
        writer.Write("plain"u8);
        await writer.FlushAsync();
    }

    /// <summary>The same over TLS, with h2 negotiated by ALPN - how gRPC is usually deployed.</summary>
    public static int StartTls(Probe probe)
    {
        (string certPath, string keyPath) = TestCert.Ensure();
        GrpcServices services = new GrpcServices().Add(Tester.BindService, new TesterService(probe));
        return TestServer.Start(async (reactor, conn) =>
        {
            Interlocked.Increment(ref probe.Connections);
            TlsSession? session = null;
            TlsConnectionDualPipe? pipe = null;
            try
            {
                session = await reactor.GetService<TlsService>()!.AcceptAsync(conn);
                pipe = new TlsConnectionDualPipe(conn, session);
                await new Http2Connection(pipe).RunAsync(services.HandleAsync);
            }
            catch
            {
                // The harness probes the port with a raw TCP connection, which fails the handshake.
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
        }, r => TlsService.Start(r, new TlsOptions { CertificatePath = certPath, KeyPath = keyPath, Alpn = ["h2"] }));
    }

    public static GrpcChannel Channel(int port, Action<GrpcChannelOptions>? configure = null)
    {
        var options = new GrpcChannelOptions
        {
            MaxReceiveMessageSize = 16 * 1024 * 1024,
            MaxSendMessageSize = 16 * 1024 * 1024,
        };
        configure?.Invoke(options);
        return GrpcChannel.ForAddress($"http://127.0.0.1:{port}", options);
    }

    /// <summary>A gRPC request made by hand, for what Grpc.Net.Client never sends.</summary>
    public static RawReply Raw(int port, string path, byte[] body, params (string Name, string Value)[] headers)
    {
        using var http = new HttpClient(new SocketsHttpHandler()) { Timeout = TimeSpan.FromSeconds(10) };
        using var request = new HttpRequestMessage(HttpMethod.Post, $"http://127.0.0.1:{port}{path}")
        {
            Content = new ByteArrayContent(body),
            Version = HttpVersion.Version20,
            VersionPolicy = HttpVersionPolicy.RequestVersionExact,
        };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/grpc");
        request.Headers.TE.ParseAdd("trailers");
        foreach ((string name, string value) in headers)
        {
            request.Headers.TryAddWithoutValidation(name, value);
        }

        using HttpResponseMessage response = http.SendAsync(request).GetAwaiter().GetResult();
        byte[] content = response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
        string? status = Field(response.TrailingHeaders, "grpc-status") ?? Field(response.Headers, "grpc-status");   // trailers-only puts it in the headers
        Reply? reply = content.Length >= 5 ? Reply.Parser.ParseFrom(content, 5, content.Length - 5) : null;
        return new RawReply(response.StatusCode, status, reply, response.Headers);

        static string? Field(HttpHeaders fields, string name) => fields.TryGetValues(name, out IEnumerable<string>? values) ? values.First() : null;
    }

    /// <summary>Messages framed as gRPC sends them: the 5-byte prefix, then each payload.</summary>
    public static byte[] Framed(params byte[][] payloads)
    {
        var framed = new List<byte>();
        foreach (byte[] payload in payloads)
        {
            byte[] prefix = new byte[5];
            BinaryPrimitives.WriteUInt32BigEndian(prefix.AsSpan(1), (uint)payload.Length);
            framed.AddRange(prefix);
            framed.AddRange(payload);
        }
        return [.. framed];
    }

    /// <summary>A channel to <see cref="StartTls"/>, trusting exactly the suite's self-signed certificate.</summary>
    public static GrpcChannel TlsChannel(int port)
    {
        using X509Certificate2 expected = X509Certificate2.CreateFromPem(File.ReadAllText(TestCert.Ensure().CertPath));
        string thumbprint = expected.Thumbprint;
        return GrpcChannel.ForAddress($"https://127.0.0.1:{port}", new GrpcChannelOptions
        {
            HttpHandler = new SocketsHttpHandler
            {
                SslOptions = { RemoteCertificateValidationCallback = (_, cert, _, _) => cert?.GetCertHashString() == thumbprint },
            },
        });
    }

    public static ByteString Bytes(int length)
    {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++)
        {
            bytes[i] = (byte)(i % 251);   // a pattern a dropped or repeated chunk cannot hide in
        }
        return ByteString.CopyFrom(bytes);
    }

    /// <summary>
    /// Runs a control call and requires it to have ridden the connection already open: the client reconnects
    /// on its own, so a call that took the connection down would otherwise pass unnoticed.
    /// </summary>
    public static void OnSameConnection(Probe probe, Action control)
    {
        int before = Volatile.Read(ref probe.Connections);
        control();
        int after = Volatile.Read(ref probe.Connections);
        Assert.True(after == before, $"the control call needed a new connection ({before} -> {after}): the call before it took its connection down");
    }

    /// <summary>The status a failed call ended with, or OK when it did not fail.</summary>
    public static Status Outcome(Action call)
    {
        try
        {
            call();
            return Status.DefaultSuccess;
        }
        catch (RpcException e)
        {
            return e.Status;
        }
    }
}

internal sealed record RawReply(HttpStatusCode Http, string? Status, Reply? Reply, HttpResponseHeaders Headers);
