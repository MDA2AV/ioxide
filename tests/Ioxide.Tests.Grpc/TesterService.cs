using System.Security.Cryptography.X509Certificates;
using Google.Protobuf;
using Grpc.Core;
using Grpc.Net.Client;
using ioxide.grpc;
using ioxide.http2;
using ioxide.nghttp2;
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
    public int Calls;
    public int Connections;   // accepted by the server, so a test can tell a reconnect from the same connection
}

/// <summary>The service under test: each method does what the Ask tells it, and reports to its probe.</summary>
internal sealed class TesterService(Probe probe) : Tester.TesterBase
{
    public override async Task<Reply> Unary(Ask request, ServerCallContext context)
    {
        Interlocked.Increment(ref probe.Calls);
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
        ByteString body = ByteString.CopyFrom(new byte[request.ReplySize]);
        try
        {
            for (int i = 0; i < request.Replies; i++)
            {
                await responseStream.WriteAsync(new Reply { Index = i, Body = body });
            }
        }
        catch (Exception e)
        {
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
        var cancelled = new TaskCompletionSource();
        using (context.CancellationToken.Register(() => cancelled.TrySetResult()))
        {
            probe.Held.TrySetResult(context);
            await cancelled.Task;
        }
        probe.Cancelled.TrySetResult();
        throw new RpcException(new Status(StatusCode.Cancelled, "held until cancelled"));
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

/// <summary>A reactor serving <see cref="TesterService"/> over h2c, on either HTTP/2 stack.</summary>
internal static class GrpcServer
{
    public static readonly bool[] Stacks = [false, true];

    public static string Name(bool native) => native ? "nghttp2" : "ioxide.http2";

    public static int Start(bool native, Probe probe, GrpcOptions? options = null)
    {
        GrpcServices services = new GrpcServices(options).Add(Tester.BindService, new TesterService(probe));
        return TestServer.Start(async (_, conn) =>
        {
            Interlocked.Increment(ref probe.Connections);
            try
            {
                if (native)
                {
                    await new Nghttp2Connection(conn, GrpcServices.Nghttp2Options).RunAsync(services.HandleAsync);
                }
                else
                {
                    await new Http2Connection(conn, GrpcServices.Http2Options).RunAsync(services.HandleAsync);
                }
            }
            finally
            {
                conn.DecRef();
            }
        });
    }

    /// <summary>The same over TLS, with h2 negotiated by ALPN - how gRPC is usually deployed.</summary>
    public static int StartTls(bool native, Probe probe)
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
                if (native)
                {
                    await new Nghttp2Connection(pipe, GrpcServices.Nghttp2Options).RunAsync(services.HandleAsync);
                }
                else
                {
                    await new Http2Connection(pipe, GrpcServices.Http2Options).RunAsync(services.HandleAsync);
                }
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

    public static GrpcChannel Channel(int port) => GrpcChannel.ForAddress($"http://127.0.0.1:{port}", new GrpcChannelOptions
    {
        MaxReceiveMessageSize = 16 * 1024 * 1024,
        MaxSendMessageSize = 16 * 1024 * 1024,
    });

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
