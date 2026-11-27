using System.Net.Sockets;
using ioxide;
using ioxide.pg;

namespace Ioxide.Tests;

/// <summary>
/// <see cref="PgPool.Current"/>: the pool started on the calling thread's reactor. A fake server, so no postgres is
/// needed.
/// </summary>
internal static class PgCurrentTests
{
    public static void Register(Runner runner)
    {
        runner.Test("pg pool: Current is the pool its reactor started, on that reactor's thread only, until it is disposed", () =>
        {
            using var server = new FakeServer((_, socket) =>
            {
                try
                {
                    PgStopTests.AnswerStartup(socket);
                    while (socket.Receive(new byte[256]) > 0)
                    {
                    }
                }
                catch (Exception e) when (e is SocketException or IOException)
                {
                    // the stop closes it
                }
            });

            string outcome = OnReactor.Run(async reactor =>
            {
                string before = Find();
                PgPool pool = PgPool.Start(reactor, PgStopTests.Options(server.Port));
                bool same = ReferenceEquals(PgPool.Current, pool) && ReferenceEquals(reactor.GetService<PgPool>(), pool);
                string elsewhere = await Task.Run(Find);

                await new ReactorSwitch(reactor);
                string back = ReferenceEquals(PgPool.Current, pool) ? "the same" : "another";
                pool.Dispose();
                return $"before: {before}, after Start: {same}, on the thread pool: {elsewhere}, back on the reactor: {back}, disposed: {Find()}";
            });

            Assert.Equal("before: none, after Start: True, on the thread pool: none, back on the reactor: the same, disposed: none", outcome);
        });

        runner.Test("pg pool: each reactor's Current is its own pool", () =>
        {
            using var server = new FakeServer((_, socket) =>
            {
                try
                {
                    PgStopTests.AnswerStartup(socket);
                    while (socket.Receive(new byte[256]) > 0)
                    {
                    }
                }
                catch (Exception e) when (e is SocketException or IOException)
                {
                    // the stop closes it
                }
            });

            PgPool? first = null;
            string firstOutcome = OnReactor.Run(reactor =>
            {
                first = PgPool.Start(reactor, PgStopTests.Options(server.Port));
                return Task.FromResult(ReferenceEquals(PgPool.Current, first) ? "its own" : "another");
            });
            string secondOutcome = OnReactor.Run(reactor =>
            {
                PgPool second = PgPool.Start(reactor, PgStopTests.Options(server.Port));
                return Task.FromResult(ReferenceEquals(PgPool.Current, second) && !ReferenceEquals(second, first) ? "its own" : "another");
            });

            Assert.Equal("its own, its own", $"{firstOutcome}, {secondOutcome}");
        });
    }

    // Whether this thread has a Current, without letting what it throws out.
    private static string Find()
    {
        try
        {
            _ = PgPool.Current;
            return "found";
        }
        catch (InvalidOperationException)
        {
            return "none";
        }
    }
}
