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
            (_, Reactor reactor, Thread thread) = TestServer.StartConfigured(Handlers.Raw, new ServerConfig
            {
                RecvBufferSize = 4096, RecvSlots = 64,
                Tcp = new TcpOptions { WriteSlabSize = 4096, PoolMax = 8, RecvQueueEntries = 64 },
            });
            reactor.Stop();
            Assert.True(thread.Join(TimeSpan.FromSeconds(10)), "the reactor did not stop");

            var context = new DefaultHttpContext();
            context.Features.Set<IReactorFeature>(new ReactorFeature(reactor));

            Task<int> call = context.OnReactor(static _ => Task.FromResult(0));

            Assert.True(((IAsyncResult)call).AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(5)),
                "OnReactor to a stopped reactor never completed");
            Assert.True(call.Exception?.InnerException is ObjectDisposedException,
                $"OnReactor to a stopped reactor ended {call.Status}: {call.Exception?.InnerException?.GetType().Name}");
        });
    }

    private sealed class ReactorFeature(Reactor reactor) : IReactorFeature
    {
        public Reactor Reactor => reactor;
    }
}
