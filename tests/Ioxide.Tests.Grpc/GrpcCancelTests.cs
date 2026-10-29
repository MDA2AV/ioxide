using Grpc.Core;
using Grpc.Net.Client;
using Ioxide.Tests.Grpc;

namespace Ioxide.Tests;

/// <summary>
/// A call the client gives up on. The client resets the stream - for a cancel and for a deadline
/// alike - and the method has to hear it: through its token while it waits on something else, and
/// through its reads and writes while it streams.
/// </summary>
internal static class GrpcCancelTests
{
    public static void Register(Runner runner)
    {
        foreach (bool native in GrpcServer.Stacks)
        {
            string stack = GrpcServer.Name(native);

            runner.Test($"grpc ({stack}): a client that cancels cancels the method's token", () =>
            {
                var probe = new Probe();
                int port = GrpcServer.Start(native, probe);
                using GrpcChannel channel = GrpcServer.Channel(port);
                using var cancel = new CancellationTokenSource();

                using AsyncUnaryCall<Reply> call = new Tester.TesterClient(channel).HoldAsync(new Ask(), cancellationToken: cancel.Token);
                Assert.True(probe.Held.Task.Wait(10_000), "the call never reached the method");
                cancel.Cancel();

                Assert.True(probe.Cancelled.Task.Wait(10_000), "the client cancelled, and the method's token never heard");
                Assert.Equal(StatusCode.Cancelled, GrpcServer.Outcome(() => call.ResponseAsync.GetAwaiter().GetResult()).StatusCode);
            });

            runner.Test($"grpc ({stack}): a deadline that passes cancels the method's token", () =>
            {
                var probe = new Probe();
                int port = GrpcServer.Start(native, probe);
                using GrpcChannel channel = GrpcServer.Channel(port);

                using AsyncUnaryCall<Reply> call = new Tester.TesterClient(channel)
                    .HoldAsync(new Ask(), deadline: DateTime.UtcNow.AddMilliseconds(500));

                Assert.True(probe.Held.Task.Wait(10_000), "the call never reached the method");
                Assert.True(probe.Held.Task.Result.Deadline != DateTime.MaxValue, "the method saw no deadline");
                Assert.True(probe.Cancelled.Task.Wait(10_000), "the deadline passed, and the method's token never heard");
                Assert.Equal(StatusCode.DeadlineExceeded, GrpcServer.Outcome(() => call.ResponseAsync.GetAwaiter().GetResult()).StatusCode);
            });

            runner.Test($"grpc ({stack}): an upload cancelled midway fails the method's read, rather than ending its stream", () =>
            {
                var probe = new Probe();
                int port = GrpcServer.Start(native, probe);
                using GrpcChannel channel = GrpcServer.Channel(port);
                using var cancel = new CancellationTokenSource();

                using AsyncClientStreamingCall<Ask, Reply> call = new Tester.TesterClient(channel).Collect(cancellationToken: cancel.Token);
                call.RequestStream.WriteAsync(new Ask { Body = GrpcServer.Bytes(1000) }).GetAwaiter().GetResult();
                call.RequestStream.WriteAsync(new Ask { Body = GrpcServer.Bytes(1000) }).GetAwaiter().GetResult();
                cancel.Cancel();

                // Both arrive at the same "nothing more": a reset that read as the end of the stream
                // would hand the method a two-message upload as if it were the whole of it.
                Task<Exception> fault = probe.StreamFault.Task;
                Task finished = Task.WhenAny(fault, probe.Collected.Task);
                Assert.True(finished.Wait(10_000), "the method's read neither failed nor ended after the cancel");
                Assert.True(fault.IsCompleted, $"the cancelled upload ended the method's stream as complete, after {Collected(probe)} messages");
                Assert.True(fault.Result is OperationCanceledException, $"the read failed with {fault.Result.GetType().Name}, not a cancellation");
            });

            runner.Test($"grpc ({stack}): a server stream the client cancels fails the method's next write", () =>
            {
                var probe = new Probe();
                int port = GrpcServer.Start(native, probe);
                using GrpcChannel channel = GrpcServer.Channel(port);
                using var cancel = new CancellationTokenSource();

                // Far more than the client reads: the method is still writing, or waiting on credit, when the cancel lands.
                using AsyncServerStreamingCall<Reply> call = new Tester.TesterClient(channel)
                    .Replies(new Ask { Replies = 1_000_000, ReplySize = 1024 }, cancellationToken: cancel.Token);
                for (int i = 0; i < 5; i++)
                {
                    Assert.True(call.ResponseStream.MoveNext(CancellationToken.None).Wait(10_000), "a reply never arrived");
                }
                cancel.Cancel();

                Assert.True(probe.StreamFault.Task.Wait(10_000), "the method kept writing to a stream the client cancelled");
                Assert.True(probe.StreamFault.Task.Result is OperationCanceledException,
                    $"the write failed with {probe.StreamFault.Task.Result.GetType().Name}, not a cancellation");
            });

            runner.Test($"grpc ({stack}): control: the connection serves new calls after one was cancelled", () =>
            {
                var probe = new Probe();
                int port = GrpcServer.Start(native, probe);
                using GrpcChannel channel = GrpcServer.Channel(port);
                var client = new Tester.TesterClient(channel);
                using var cancel = new CancellationTokenSource();

                using AsyncUnaryCall<Reply> held = client.HoldAsync(new Ask(), cancellationToken: cancel.Token);
                Assert.True(probe.Held.Task.Wait(10_000), "the call never reached the method");
                cancel.Cancel();
                Assert.True(probe.Cancelled.Task.Wait(10_000), "the cancel never reached the method");

                GrpcServer.OnSameConnection(probe, () => Assert.Equal("after", client.Unary(new Ask { Text = "after" }).Text));
            });
        }
    }

    // A failure message is built even when the assert passes, so it must not wait on a count that never comes.
    private static string Collected(Probe probe)
        => probe.Collected.Task.IsCompleted ? probe.Collected.Task.Result.ToString() : "no";
}
