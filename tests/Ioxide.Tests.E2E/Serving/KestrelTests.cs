using ioxide;
using ioxide.Kestrel;
using Microsoft.AspNetCore.Http;

namespace Ioxide.Tests;

/// <summary>The Kestrel transport's endpoint helpers, against a real reactor.</summary>
internal static class KestrelTests
{
    public static void Register(Runner runner)
    {
        runner.Test("kestrel: OnReactor from another thread fails once the reactor has stopped, instead of waiting forever", () =>
        {
            (Reactor reactor, Thread thread) = StartReactor();
            reactor.Stop();
            Assert.True(thread.Join(TimeSpan.FromSeconds(10)), "the reactor did not stop");

            Task<int> call = ContextOn(reactor).OnReactor(static _ => Task.FromResult(0));

            Assert.True(((IAsyncResult)call).AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(5)),
                "OnReactor to a stopped reactor never completed");
            Assert.True(call.Exception?.InnerException is ObjectDisposedException,
                $"OnReactor to a stopped reactor ended {call.Status}: {call.Exception?.InnerException?.GetType().Name}");
        });

        runner.Test("kestrel: OnReactor from another thread runs the work on the reactor's thread", () =>
        {
            (Reactor reactor, Thread reactorThread) = StartReactor();

            Task<Thread> call = ContextOn(reactor).OnReactor(static _ => Task.FromResult(Thread.CurrentThread));

            Thread ranOn = Finished(call).Result;
            Assert.True(ranOn == reactorThread, $"the work ran on '{ranOn.Name}', not on the reactor's thread");
        });

        runner.Test("kestrel: OnReactor from another thread continues the caller on the reactor once the work is done", () =>
        {
            (Reactor reactor, Thread reactorThread) = StartReactor();
            HttpContext context = ContextOn(reactor);

            // Released by a post, so the work ends on the reactor, and only after the caller is waiting for it.
            var release = new TaskCompletionSource<int>();
            Task<Thread> call = CallAsync();
            reactor.ScheduleOnReactor(static s => ((TaskCompletionSource<int>)s!).SetResult(0), release);

            Thread continuedOn = Finished(call).Result;
            Assert.True(continuedOn == reactorThread, $"the caller continued on '{continuedOn.Name}', not on the reactor's thread");

            async Task<Thread> CallAsync()
            {
                await context.OnReactor(_ => release.Task);
                return Thread.CurrentThread;
            }
        });

        runner.Test("kestrel: OnReactor from another thread flows the caller's AsyncLocal values into the work", () =>
        {
            (Reactor reactor, _) = StartReactor();

            // Made after the reactor started, so only the caller's context can hold a value for it.
            var flowed = new AsyncLocal<string?> { Value = "caller" };

            Task<string?> call = ContextOn(reactor).OnReactor(_ => Task.FromResult<string?>(flowed.Value));

            Assert.Equal("caller", Finished(call).Result);
        });

        runner.Test("kestrel: OnReactor from another thread leaves the task Canceled, not Faulted, when the work is canceled", () =>
        {
            (Reactor reactor, _) = StartReactor();

            Task<int> call = ContextOn(reactor).OnReactor(static _ => Task.FromCanceled<int>(new CancellationToken(canceled: true)));

            Assert.Equal(TaskStatus.Canceled, Finished(call).Status);
        });
    }

    private static (Reactor Reactor, Thread Thread) StartReactor()
    {
        (_, Reactor reactor, Thread thread) = TestServer.StartConfigured(Handlers.Raw, new ServerConfig
        {
            RecvBufferSize = 4096, RecvSlots = 64,
            Tcp = new TcpOptions { WriteSlabSize = 4096, PoolMax = 8, RecvQueueEntries = 64 },
        });
        return (reactor, thread);
    }

    private static HttpContext ContextOn(Reactor reactor)
    {
        var context = new DefaultHttpContext();
        context.Features.Set<IReactorFeature>(new ReactorFeature(reactor));
        return context;
    }

    private static Task<T> Finished<T>(Task<T> call)
    {
        Assert.True(((IAsyncResult)call).AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(5)), "OnReactor never completed");
        return call;
    }

    private sealed class ReactorFeature(Reactor reactor) : IReactorFeature
    {
        public Reactor Reactor => reactor;
    }
}
