using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using Google.Protobuf;
using Grpc.Core;
using Grpc.Net.Client;
using Grpc.Net.Client.Configuration;
using ioxide.grpc;
using Ioxide.Tests.Grpc;

namespace Ioxide.Tests;

/// <summary>How a call ends - the status and message in its trailers - and the metadata on either side of it.</summary>
internal static class GrpcStatusTests
{
    public static void Register(Runner runner)
    {
        runner.Test("grpc: an RpcException's status and message reach the client", () =>
        {
            int port = GrpcServer.Start(new Probe());
            using GrpcChannel channel = GrpcServer.Channel(port);
            var client = new Tester.TesterClient(channel);

            Status status = GrpcServer.Outcome(() => client.Unary(new Ask { Status = (int)StatusCode.NotFound, Detail = "no such thing" }));
            Assert.Equal(StatusCode.NotFound, status.StatusCode);
            Assert.Equal("no such thing", status.Detail);

            // And after messages went out: a server stream can still fail, in its trailers.
            using AsyncServerStreamingCall<Reply> call = client.Replies(new Ask
            {
                Replies = 3, ReplySize = 10, Status = (int)StatusCode.DataLoss, Detail = "after three",
            });
            int replies = 0;
            Status streamed = GrpcServer.Outcome(() =>
            {
                while (call.ResponseStream.MoveNext(CancellationToken.None).GetAwaiter().GetResult())
                {
                    replies++;
                }
            });
            Assert.Equal(3, replies);
            Assert.Equal(StatusCode.DataLoss, streamed.StatusCode);
            Assert.Equal("after three", streamed.Detail);
        });

        runner.Test("grpc: a call that ends while the client is still uploading reports its status, and the connection carries on", () =>
        {
            var probe = new Probe();
            int port = GrpcServer.Start(probe);
            using GrpcChannel channel = GrpcServer.Channel(port);
            var client = new Tester.TesterClient(channel);

            // Never half-closed: the method answers with the upload still open.
            using AsyncClientStreamingCall<Ask, Reply> call = client.Collect();
            call.RequestStream.WriteAsync(new Ask { Body = GrpcServer.Bytes(1000) }).GetAwaiter().GetResult();
            call.RequestStream.WriteAsync(new Ask { Status = (int)StatusCode.OutOfRange, Detail = "enough" }).GetAwaiter().GetResult();

            Status status = GrpcServer.Outcome(() => call.ResponseAsync.GetAwaiter().GetResult());
            Assert.Equal(StatusCode.OutOfRange, status.StatusCode);
            Assert.Equal("enough", status.Detail);

            // control: the same connection still takes an upload bigger than its whole receive window
            GrpcServer.OnSameConnection(probe, () =>
                Assert.Equal(256 * 1024, client.Unary(new Ask { Body = GrpcServer.Bytes(256 * 1024) }).Body.Length));
        });

        runner.Test("grpc: a status message survives percent-encoding, UTF-8 and all", () =>
        {
            int port = GrpcServer.Start(new Probe());
            using GrpcChannel channel = GrpcServer.Channel(port);

            const string detail = "50% off: ünïcödé ✓\nline two\t%41";
            Status status = GrpcServer.Outcome(() => new Tester.TesterClient(channel)
                .Unary(new Ask { Status = (int)StatusCode.InvalidArgument, Detail = detail }));

            Assert.Equal(StatusCode.InvalidArgument, status.StatusCode);
            Assert.Equal(detail, status.Detail);
        });

        runner.Test("grpc: a status set on the context ends the call as an exception would", () =>
        {
            int port = GrpcServer.Start(new Probe());
            using GrpcChannel channel = GrpcServer.Channel(port);

            Status status = GrpcServer.Outcome(() => new Tester.TesterClient(channel)
                .Unary(new Ask { Status = (int)StatusCode.FailedPrecondition, Detail = "set, not thrown", SetStatus = true }));

            Assert.Equal(StatusCode.FailedPrecondition, status.StatusCode);
            Assert.Equal("set, not thrown", status.Detail);
        });

        runner.Test("grpc: an exception that is no RpcException is UNKNOWN, and its message stays on the server", () =>
        {
            int port = GrpcServer.Start(new Probe());
            using GrpcChannel channel = GrpcServer.Channel(port);

            Status status = GrpcServer.Outcome(() => new Tester.TesterClient(channel).Unary(new Ask { Fault = true }));

            Assert.Equal(StatusCode.Unknown, status.StatusCode);
            Assert.True(!status.Detail.Contains("hunter2"), $"the exception's message reached the client: '{status.Detail}'");
        });

        runner.Test("grpc: request metadata reaches the method, and its headers and trailers reach the client", () =>
        {
            int port = GrpcServer.Start(new Probe());
            using GrpcChannel channel = GrpcServer.Channel(port);

            byte[] binary = [0x00, 0xff, 0x10, 0x80, 0x7f];   // not text, and not a multiple of three
            using AsyncUnaryCall<Reply> call = new Tester.TesterClient(channel).UnaryAsync(new Ask { Text = "m" },
                new Metadata { { "x-echo", "a value" }, { "x-echo-bin", binary } });

            Metadata headers = call.ResponseHeadersAsync.GetAwaiter().GetResult();
            Assert.Equal("m", call.ResponseAsync.GetAwaiter().GetResult().Text);
            Metadata trailers = call.GetTrailers();

            Assert.Equal("a value", headers.GetValue("x-echo"));
            Assert.True(binary.AsSpan().SequenceEqual(headers.GetValueBytes("x-echo-bin")), "the binary header came back different");
            Assert.Equal("a value", trailers.GetValue("x-echo-trailer"));
            Assert.True(binary.AsSpan().SequenceEqual(trailers.GetValueBytes("x-echo-trailer-bin")), "the binary trailer came back different");
        });

        runner.Test("grpc: a trailer section of 70 fields arrives whole", () =>
        {
            int port = GrpcServer.Start(new Probe());
            using GrpcChannel channel = GrpcServer.Channel(port);

            using AsyncUnaryCall<Reply> call = new Tester.TesterClient(channel).UnaryAsync(new Ask { Trailers = 70 });
            Assert.Equal(StatusCode.OK, GrpcServer.Outcome(() => call.ResponseAsync.GetAwaiter().GetResult()).StatusCode);
            Assert.Equal(70, call.GetTrailers().Count(entry => entry.Key.StartsWith("x-t-")));
        });

        runner.Test("grpc: trailers past 64 KiB arrive whole, over CONTINUATION frames", () =>
        {
            var probe = new Probe();
            int port = GrpcServer.Start(probe);

            // A client that takes header blocks this big, so the test is of the server's framing.
            using GrpcChannel channel = GrpcServer.Channel(port, options => options.HttpHandler = new SocketsHttpHandler { MaxResponseHeadersLength = 1024 });
            var client = new Tester.TesterClient(channel);
            Assert.Equal("open", client.Unary(new Ask { Text = "open" }).Text);

            GrpcServer.OnSameConnection(probe, () =>
            {
                // A deadline, so a stream that never ends fails the test rather than hanging it.
                using AsyncUnaryCall<Reply> call = client.UnaryAsync(new Ask { Trailers = 7000 }, deadline: DateTime.UtcNow.AddSeconds(10));
                Status status = GrpcServer.Outcome(() => call.ResponseAsync.GetAwaiter().GetResult());
                Assert.True(status.StatusCode == StatusCode.OK, $"the call ended {status}");
                Assert.Equal(7000, call.GetTrailers().Count(entry => entry.Key.StartsWith("x-t-")));
                Assert.Equal("after", client.Unary(new Ask { Text = "after" }).Text);
            });
        });

        runner.Test("grpc: a trailer whose value is not printable ASCII is dropped, and the call carries on", () =>
        {
            int port = GrpcServer.Start(new Probe());
            using GrpcChannel channel = GrpcServer.Channel(port);

            using AsyncUnaryCall<Reply> call = new Tester.TesterClient(channel).UnaryAsync(new Ask { BadTrailer = "Não encontrado" });
            Assert.Equal(StatusCode.OK, GrpcServer.Outcome(() => call.ResponseAsync.GetAwaiter().GetResult()).StatusCode);
            Metadata trailers = call.GetTrailers();
            Assert.Equal("ok", trailers.GetValue("x-good"));
            Assert.True(trailers.Get("x-bad") is null, $"a value no peer can read went out as '{trailers.GetValue("x-bad")}'");
        });

        runner.Test("grpc: a call that fails before its first message is trailers-only, so a client can retry it", () =>
        {
            var probe = new Probe();
            int port = GrpcServer.Start(probe);
            using GrpcChannel channel = GrpcServer.Channel(port, options => options.ServiceConfig = new ServiceConfig
            {
                MethodConfigs =
                {
                    new MethodConfig
                    {
                        Names = { MethodName.Default },
                        RetryPolicy = new RetryPolicy
                        {
                            MaxAttempts = 2,
                            InitialBackoff = TimeSpan.FromMilliseconds(1),
                            MaxBackoff = TimeSpan.FromMilliseconds(1),
                            BackoffMultiplier = 1,
                            RetryableStatusCodes = { StatusCode.Unavailable },
                        },
                    },
                },
            });

            // A client commits to a call once it has its headers; only a status in them leaves it free to retry.
            Reply reply = new Tester.TesterClient(channel).Unary(new Ask { Text = "again", FailFirst = true });
            Assert.Equal("again", reply.Text);
            Assert.Equal(2, Volatile.Read(ref probe.Calls));
        });

        runner.Test("grpc: a cancellation of the method's own is UNKNOWN, not the client's CANCELLED", () =>
        {
            int port = GrpcServer.Start(new Probe());
            using GrpcChannel channel = GrpcServer.Channel(port);

            Status status = GrpcServer.Outcome(() => new Tester.TesterClient(channel).Unary(new Ask { ThrowCancelled = true }));
            Assert.Equal(StatusCode.Unknown, status.StatusCode);
        });

        runner.Test("grpc: a grpc-timeout in microseconds gives the method the deadline it names", () =>
        {
            int port = GrpcServer.Start(new Probe());

            // grpc-go and grpc-java send every deadline from 100 ms to 100 s in microseconds.
            RawReply raw = GrpcServer.Raw(port, "/ioxide.tests.Tester/Unary", GrpcServer.Framed(new Ask().ToByteArray()), ("grpc-timeout", "5000000u"));
            Assert.Equal("0", raw.Status);
            TimeSpan left = DateTime.Parse(raw.Reply!.Deadline, null, DateTimeStyles.RoundtripKind) - DateTime.UtcNow;
            Assert.True(left > TimeSpan.FromSeconds(4), $"5,000,000 microseconds reached the method as {left.TotalMilliseconds:0} ms");
        });

        runner.Test("grpc: a unary request with no message, or two, is UNIMPLEMENTED", () =>
        {
            int port = GrpcServer.Start(new Probe());
            byte[] ask = new Ask { Text = "x" }.ToByteArray();

            Assert.Equal("12", GrpcServer.Raw(port, "/ioxide.tests.Tester/Unary", []).Status);
            Assert.Equal("12", GrpcServer.Raw(port, "/ioxide.tests.Tester/Unary", GrpcServer.Framed(ask, ask)).Status);
        });

        runner.Test("grpc: a request message that doesn't parse is INTERNAL", () =>
        {
            int port = GrpcServer.Start(new Probe());

            // Field 31 with wire type 7, which protobuf gives no meaning.
            Assert.Equal("13", GrpcServer.Raw(port, "/ioxide.tests.Tester/Unary", GrpcServer.Framed([0xFF, 0x01])).Status);
        });

        runner.Test("grpc: -bin values joined with a comma reach the method one by one", () =>
        {
            int port = GrpcServer.Start(new Probe());

            // 00 01 02, then 03 04 05: the method echoes the last x-echo-bin it holds.
            RawReply raw = GrpcServer.Raw(port, "/ioxide.tests.Tester/Unary", GrpcServer.Framed(new Ask().ToByteArray()), ("x-echo-bin", "AAEC,AwQF"));
            Assert.Equal("0", raw.Status);
            string echoed = raw.Headers.TryGetValues("x-echo-bin", out IEnumerable<string>? values) ? values.Single() : "nothing";
            Assert.Equal("AwQF", echoed);
        });

        runner.Test("grpc: a method nobody bound is UNIMPLEMENTED", () =>
        {
            var probe = new Probe();
            int port = GrpcServer.Start(probe);
            using GrpcChannel channel = GrpcServer.Channel(port);

            Status status = GrpcServer.Outcome(() => new Unbound.UnboundClient(channel).Unary(new Ask()));
            Assert.Equal(StatusCode.Unimplemented, status.StatusCode);

            // control: the same connection serves a bound method
            GrpcServer.OnSameConnection(probe, () =>
                Assert.Equal("still here", new Tester.TesterClient(channel).Unary(new Ask { Text = "still here" }).Text));
        });

        runner.Test("grpc: a request message past MaxReceiveMessageSize is RESOURCE_EXHAUSTED", () =>
        {
            var probe = new Probe();
            int port = GrpcServer.Start(probe, new GrpcOptions { MaxReceiveMessageSize = 64 * 1024 });
            using GrpcChannel channel = GrpcServer.Channel(port);
            var client = new Tester.TesterClient(channel);

            Status status = GrpcServer.Outcome(() => client.Unary(new Ask { Body = GrpcServer.Bytes(64 * 1024 + 1) }));
            Assert.Equal(StatusCode.ResourceExhausted, status.StatusCode);

            // control: the limit itself is allowed (the Ask's own framing adds a few bytes, so a little under)
            GrpcServer.OnSameConnection(probe, () =>
                Assert.Equal(60 * 1024, client.Unary(new Ask { Body = GrpcServer.Bytes(60 * 1024) }).Body.Length));
        });

        runner.Test("grpc: the deadline the client sets is the deadline the method sees", () =>
        {
            int port = GrpcServer.Start(new Probe());
            using GrpcChannel channel = GrpcServer.Channel(port);
            var client = new Tester.TesterClient(channel);

            DateTime deadline = DateTime.UtcNow.AddMinutes(5);
            Reply reply = client.Unary(new Ask(), deadline: deadline);
            DateTime seen = DateTime.Parse(reply.Deadline, null, System.Globalization.DateTimeStyles.RoundtripKind);
            Assert.True(Math.Abs((seen - deadline).TotalSeconds) < 30, $"the client set {deadline:o}, the method saw {reply.Deadline}");

            Assert.Equal("", client.Unary(new Ask()).Deadline);   // control: no deadline sent, none seen
        });

        runner.Test("grpc: a request that is not gRPC is refused at the HTTP layer", () =>
        {
            int port = GrpcServer.Start(new Probe());
            using var http = new HttpClient(new SocketsHttpHandler())
            {
                DefaultRequestVersion = HttpVersion.Version20,
                DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
                Timeout = TimeSpan.FromSeconds(10),
            };

            var content = new ByteArrayContent([1, 2, 3]);
            content.Headers.ContentType = new MediaTypeHeaderValue("text/plain");
            using HttpResponseMessage post = http.PostAsync($"http://127.0.0.1:{port}/ioxide.tests.Tester/Unary", content)
                .GetAwaiter().GetResult();
            Assert.Equal(HttpStatusCode.UnsupportedMediaType, post.StatusCode);

            using HttpResponseMessage get = http.GetAsync($"http://127.0.0.1:{port}/ioxide.tests.Tester/Unary").GetAwaiter().GetResult();
            Assert.Equal(HttpStatusCode.MethodNotAllowed, get.StatusCode);
            Assert.True(get.Content.Headers.Allow.Contains("POST"), $"a 405 names the methods it allows, not '{string.Join(", ", get.Content.Headers.Allow)}'");
        });
    }
}
