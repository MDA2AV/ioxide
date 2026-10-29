using System.Net;
using System.Net.Http.Headers;
using Grpc.Core;
using Grpc.Net.Client;
using ioxide.grpc;
using Ioxide.Tests.Grpc;

namespace Ioxide.Tests;

/// <summary>How a call ends - the status and message in its trailers - and the metadata on either side of it.</summary>
internal static class GrpcStatusTests
{
    public static void Register(Runner runner)
    {
        foreach (bool native in GrpcServer.Stacks)
        {
            string stack = GrpcServer.Name(native);

            runner.Test($"grpc ({stack}): an RpcException's status and message reach the client", () =>
            {
                int port = GrpcServer.Start(native, new Probe());
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

            runner.Test($"grpc ({stack}): a call that ends while the client is still uploading reports its status, and the connection carries on", () =>
            {
                var probe = new Probe();
                int port = GrpcServer.Start(native, probe);
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

            runner.Test($"grpc ({stack}): a status message survives percent-encoding, UTF-8 and all", () =>
            {
                int port = GrpcServer.Start(native, new Probe());
                using GrpcChannel channel = GrpcServer.Channel(port);

                const string detail = "50% off: ünïcödé ✓\nline two\t%41";
                Status status = GrpcServer.Outcome(() => new Tester.TesterClient(channel)
                    .Unary(new Ask { Status = (int)StatusCode.InvalidArgument, Detail = detail }));

                Assert.Equal(StatusCode.InvalidArgument, status.StatusCode);
                Assert.Equal(detail, status.Detail);
            });

            runner.Test($"grpc ({stack}): a status set on the context ends the call as an exception would", () =>
            {
                int port = GrpcServer.Start(native, new Probe());
                using GrpcChannel channel = GrpcServer.Channel(port);

                Status status = GrpcServer.Outcome(() => new Tester.TesterClient(channel)
                    .Unary(new Ask { Status = (int)StatusCode.FailedPrecondition, Detail = "set, not thrown", SetStatus = true }));

                Assert.Equal(StatusCode.FailedPrecondition, status.StatusCode);
                Assert.Equal("set, not thrown", status.Detail);
            });

            runner.Test($"grpc ({stack}): an exception that is no RpcException is UNKNOWN, and its message stays on the server", () =>
            {
                int port = GrpcServer.Start(native, new Probe());
                using GrpcChannel channel = GrpcServer.Channel(port);

                Status status = GrpcServer.Outcome(() => new Tester.TesterClient(channel).Unary(new Ask { Fault = true }));

                Assert.Equal(StatusCode.Unknown, status.StatusCode);
                Assert.True(!status.Detail.Contains("hunter2"), $"the exception's message reached the client: '{status.Detail}'");
            });

            runner.Test($"grpc ({stack}): request metadata reaches the method, and its headers and trailers reach the client", () =>
            {
                int port = GrpcServer.Start(native, new Probe());
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

            runner.Test(native
                ? "grpc (nghttp2): trailers past its 64-field limit reset their own call, and the connection carries on"
                : "grpc (ioxide.http2): a trailer section of 70 fields arrives whole", () =>
            {
                var probe = new Probe();
                int port = GrpcServer.Start(native, probe);
                using GrpcChannel channel = GrpcServer.Channel(port);
                var client = new Tester.TesterClient(channel);
                Assert.Equal("open", client.Unary(new Ask { Text = "open" }).Text);

                GrpcServer.OnSameConnection(probe, () =>
                {
                    using AsyncUnaryCall<Reply> call = client.UnaryAsync(new Ask { Trailers = 70 });
                    Status status = GrpcServer.Outcome(() => call.ResponseAsync.GetAwaiter().GetResult());
                    if (native)
                    {
                        Assert.Equal(StatusCode.Internal, status.StatusCode);
                    }
                    else
                    {
                        Assert.Equal(StatusCode.OK, status.StatusCode);
                        Assert.Equal(70, call.GetTrailers().Count(entry => entry.Key.StartsWith("x-t-")));
                    }

                    Assert.Equal("after", client.Unary(new Ask { Text = "after" }).Text);
                });
            });

            runner.Test($"grpc ({stack}): a method nobody bound is UNIMPLEMENTED", () =>
            {
                var probe = new Probe();
                int port = GrpcServer.Start(native, probe);
                using GrpcChannel channel = GrpcServer.Channel(port);

                Status status = GrpcServer.Outcome(() => new Unbound.UnboundClient(channel).Unary(new Ask()));
                Assert.Equal(StatusCode.Unimplemented, status.StatusCode);

                // control: the same connection serves a bound method
                GrpcServer.OnSameConnection(probe, () =>
                    Assert.Equal("still here", new Tester.TesterClient(channel).Unary(new Ask { Text = "still here" }).Text));
            });

            runner.Test($"grpc ({stack}): a request message past MaxReceiveMessageSize is RESOURCE_EXHAUSTED", () =>
            {
                var probe = new Probe();
                int port = GrpcServer.Start(native, probe, new GrpcOptions { MaxReceiveMessageSize = 64 * 1024 });
                using GrpcChannel channel = GrpcServer.Channel(port);
                var client = new Tester.TesterClient(channel);

                Status status = GrpcServer.Outcome(() => client.Unary(new Ask { Body = GrpcServer.Bytes(64 * 1024 + 1) }));
                Assert.Equal(StatusCode.ResourceExhausted, status.StatusCode);

                // control: the limit itself is allowed (the Ask's own framing adds a few bytes, so a little under)
                GrpcServer.OnSameConnection(probe, () =>
                    Assert.Equal(60 * 1024, client.Unary(new Ask { Body = GrpcServer.Bytes(60 * 1024) }).Body.Length));
            });

            runner.Test($"grpc ({stack}): the deadline the client sets is the deadline the method sees", () =>
            {
                int port = GrpcServer.Start(native, new Probe());
                using GrpcChannel channel = GrpcServer.Channel(port);
                var client = new Tester.TesterClient(channel);

                DateTime deadline = DateTime.UtcNow.AddMinutes(5);
                Reply reply = client.Unary(new Ask(), deadline: deadline);
                DateTime seen = DateTime.Parse(reply.Deadline, null, System.Globalization.DateTimeStyles.RoundtripKind);
                Assert.True(Math.Abs((seen - deadline).TotalSeconds) < 30, $"the client set {deadline:o}, the method saw {reply.Deadline}");

                Assert.Equal("", client.Unary(new Ask()).Deadline);   // control: no deadline sent, none seen
            });

            runner.Test($"grpc ({stack}): a request that is not gRPC is refused at the HTTP layer", () =>
            {
                int port = GrpcServer.Start(native, new Probe());
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
            });
        }
    }
}
