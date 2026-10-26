using Grpc.Core;
using Grpc.Net.Client;
using Ioxide.Tests.Grpc;

namespace Ioxide.Tests;

/// <summary>
/// The four kinds of call, each through Grpc.Net.Client - the reference client, which validates the
/// framing, the content-type and the status trailers itself - against both HTTP/2 stacks.
/// </summary>
internal static class GrpcCallTests
{
    public static void Register(Runner runner)
    {
        foreach (bool native in GrpcServer.Stacks)
        {
            string stack = GrpcServer.Name(native);

            runner.Test($"grpc ({stack}): a unary call round-trips its message", () =>
            {
                int port = GrpcServer.Start(native, new Probe());
                using GrpcChannel channel = GrpcServer.Channel(port);

                Reply reply = new Tester.TesterClient(channel).Unary(new Ask { Text = "hello", Body = GrpcServer.Bytes(100) });

                Assert.Equal("hello", reply.Text);
                Assert.True(reply.Body.Equals(GrpcServer.Bytes(100)), $"the body came back as {reply.Body.Length} bytes that differ");
                Assert.Equal("/ioxide.tests.Tester/Unary", reply.Method);
            });

            runner.Test($"grpc ({stack}): an empty message is a message, framed and answered", () =>
            {
                int port = GrpcServer.Start(native, new Probe());
                using GrpcChannel channel = GrpcServer.Channel(port);

                Reply reply = new Tester.TesterClient(channel).Unary(new Ask());

                Assert.Equal("", reply.Text);
                Assert.Equal(0, reply.Body.Length);
            });

            runner.Test($"grpc ({stack}): a message past every HTTP/2 window arrives whole, both ways", () =>
            {
                int port = GrpcServer.Start(native, new Probe());
                using GrpcChannel channel = GrpcServer.Channel(port);

                // 3 MiB: past the 64 KiB connection window, the 1 MiB stream window and several frames.
                Reply reply = new Tester.TesterClient(channel).Unary(new Ask { Body = GrpcServer.Bytes(3 * 1024 * 1024) });

                Assert.True(reply.Body.Equals(GrpcServer.Bytes(3 * 1024 * 1024)),
                    $"{reply.Body.Length} bytes came back, not the 3 MiB pattern sent");
            });

            runner.Test($"grpc ({stack}): server streaming delivers every reply, in order", () =>
            {
                int port = GrpcServer.Start(native, new Probe());
                using GrpcChannel channel = GrpcServer.Channel(port);

                // 2 x 300 KiB outruns the client's stream window, so the writer waits on credit mid-stream.
                foreach ((int count, int size) in new[] { (200, 64), (2, 300 * 1024) })
                {
                    using AsyncServerStreamingCall<Reply> call = new Tester.TesterClient(channel)
                        .Replies(new Ask { Replies = count, ReplySize = size });

                    var indices = new List<int>();
                    foreach (Reply reply in ReadAll(call.ResponseStream))
                    {
                        Assert.Equal(size, reply.Body.Length);
                        indices.Add(reply.Index);
                    }

                    Assert.True(indices.SequenceEqual(Enumerable.Range(0, count)),
                        $"{count} replies of {size} B: got {indices.Count}, first out of order at {FirstMismatch(indices)}");
                    Assert.Equal(StatusCode.OK, call.GetStatus().StatusCode);
                }
            });

            runner.Test($"grpc ({stack}): client streaming reads every message up to the half-close", () =>
            {
                var probe = new Probe();
                int port = GrpcServer.Start(native, probe);
                using GrpcChannel channel = GrpcServer.Channel(port);

                using AsyncClientStreamingCall<Ask, Reply> call = new Tester.TesterClient(channel).Collect();
                for (int i = 0; i < 40; i++)
                {
                    call.RequestStream.WriteAsync(new Ask { Body = GrpcServer.Bytes(16 * 1024) }).GetAwaiter().GetResult();
                }
                call.RequestStream.CompleteAsync().GetAwaiter().GetResult();
                Reply reply = call.ResponseAsync.GetAwaiter().GetResult();

                Assert.Equal(40, reply.Count);
                Assert.Equal(40L * 16 * 1024, reply.Total);
            });

            runner.Test($"grpc ({stack}): bidirectional streaming answers each message while the request is still open", () =>
            {
                int port = GrpcServer.Start(native, new Probe());
                using GrpcChannel channel = GrpcServer.Channel(port);

                using AsyncDuplexStreamingCall<Ask, Reply> call = new Tester.TesterClient(channel).Echo();

                // Ping-pong: the next message is sent only once its reply is in. A server that waits
                // for the end of the request before answering deadlocks here instead.
                for (int i = 0; i < 20; i++)
                {
                    call.RequestStream.WriteAsync(new Ask { Text = $"ping {i}", Body = GrpcServer.Bytes(i * 1000) })
                        .GetAwaiter().GetResult();
                    Assert.True(Next(call.ResponseStream, 10_000), $"no reply to ping {i} while the request stayed open");
                    Reply reply = call.ResponseStream.Current;
                    Assert.Equal($"ping {i}", reply.Text);
                    Assert.Equal(i, reply.Index);
                    Assert.Equal(i * 1000, reply.Body.Length);
                }

                call.RequestStream.CompleteAsync().GetAwaiter().GetResult();
                Assert.True(!Next(call.ResponseStream, 10_000), "a reply arrived after the last ping");
                Assert.Equal(StatusCode.OK, call.GetStatus().StatusCode);
            });

            runner.Test($"grpc ({stack}): calls run over TLS, with h2 negotiated by ALPN", () =>
            {
                int port = GrpcServer.StartTls(native, new Probe());
                using GrpcChannel channel = GrpcServer.TlsChannel(port);
                var client = new Tester.TesterClient(channel);

                Assert.Equal("over tls", client.Unary(new Ask { Text = "over tls" }).Text);

                using AsyncServerStreamingCall<Reply> call = client.Replies(new Ask { Replies = 50, ReplySize = 4096 });
                Assert.Equal(50, ReadAll(call.ResponseStream).Count());
                Assert.Equal(StatusCode.OK, call.GetStatus().StatusCode);
            });

            runner.Test($"grpc ({stack}): calls multiplexed on one connection all complete", () =>
            {
                var probe = new Probe();
                int port = GrpcServer.Start(native, probe);
                using GrpcChannel channel = GrpcServer.Channel(port);
                var client = new Tester.TesterClient(channel);

                Task<Reply>[] calls = [.. Enumerable.Range(0, 64).Select(i =>
                    client.UnaryAsync(new Ask { Text = $"call {i}", Body = GrpcServer.Bytes(i * 512) }).ResponseAsync)];
                Assert.True(Task.WaitAll(calls, 30_000), "not every multiplexed call completed");

                for (int i = 0; i < calls.Length; i++)
                {
                    Assert.Equal($"call {i}", calls[i].Result.Text);
                    Assert.Equal(i * 512, calls[i].Result.Body.Length);
                }
                Assert.Equal(64, Volatile.Read(ref probe.Calls));
            });
        }
    }

    private static IEnumerable<Reply> ReadAll(IAsyncStreamReader<Reply> stream)
    {
        while (Next(stream, 10_000))
        {
            yield return stream.Current;
        }
    }

    // Bounded, so a server that never answers fails the test instead of hanging it.
    private static bool Next(IAsyncStreamReader<Reply> stream, int timeoutMs)
    {
        Task<bool> next = stream.MoveNext(CancellationToken.None);
        Assert.True(next.Wait(timeoutMs), "the next message never arrived");
        return next.Result;
    }

    private static string FirstMismatch(List<int> indices)
    {
        for (int i = 0; i < indices.Count; i++)
        {
            if (indices[i] != i)
            {
                return $"{i} (was {indices[i]})";
            }
        }
        return "none";
    }
}
