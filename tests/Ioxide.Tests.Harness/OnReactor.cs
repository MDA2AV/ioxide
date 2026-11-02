using System.Runtime.ExceptionServices;
using ioxide;

namespace Ioxide.Tests;

/// <summary>Test code run on a reactor, and calls made to its clients from a thread that is not the reactor's.</summary>
public static class OnReactor
{
    /// <summary>
    /// Runs <paramref name="body"/> on a reactor of its own, from its <c>OnStart</c>, and returns what it
    /// returned - or what it threw - to the test thread.
    /// </summary>
    public static string Run(Func<Reactor, Task<string>> body, int timeoutMs = 30_000)
    {
        var outcome = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        TestServer.Start((_, connection) => { connection.DecRef(); return Task.CompletedTask; },
            onStart: reactor => _ = RunAsync(reactor));
        Assert.True(outcome.Task.Wait(timeoutMs), $"the code on the reactor did not finish within {timeoutMs} ms");
        return outcome.Task.Result;

        async Task RunAsync(Reactor reactor)
        {
            try
            {
                outcome.TrySetResult(await body(reactor));
            }
            catch (Exception e)
            {
                outcome.TrySetResult($"threw {e.GetType().Name}: {e.Message}");
            }
        }
    }

    /// <summary>
    /// Makes <paramref name="call"/> on a thread of its own and waits for it to return. Made from a reactor, that
    /// holds the reactor meanwhile: what the call changed before it returned shows there afterwards, and none of it
    /// can have run on the reactor.
    /// </summary>
    public static T CallFromAnotherThread<T>(Func<T> call)
    {
        T result = default!;
        ExceptionDispatchInfo? failure = null;
        var thread = new Thread(() =>
        {
            try
            {
                result = call();
            }
            catch (Exception e)
            {
                failure = ExceptionDispatchInfo.Capture(e);
            }
        });
        thread.Start();
        thread.Join();
        failure?.Throw();
        return result;
    }

    /// <inheritdoc cref="CallFromAnotherThread{T}"/>
    public static void CallFromAnotherThread(Action call) => CallFromAnotherThread(() =>
    {
        call();
        return true;
    });
}
