using ioxide;
using ioxide.ngtcp2;

namespace Ioxide.Tests;

/// <summary>
/// Handshakes in flight while another reactor binds the QUIC port. The kernel spreads a
/// SO_REUSEPORT group's flows by hashing over its members, so a reactor joining the group moves
/// some of them - and a client whose handshake started on one reactor sends the rest of it to
/// another.
/// </summary>
internal static class QuicFleetJoinTests
{
    public static void Register(Runner runner)
    {
        runner.Test("quic/fleet: a handshake under way when another reactor binds the port completes", () =>
        {
            // The startup race: clients connecting while the reactors are still binding, one after
            // the other. Every first Initial reaches the only socket bound so far, which accepts the
            // connection. Once the second reactor joins, about half the clients hash to it, and it
            // dropped the Handshake packets they sent there - a long header, so never forwarded -
            // until the server gave up on the handshake 10 s later.
            (string certPath, string keyPath) = TestCert.Ensure();
            using var engine = new QuicEngine(certPath, keyPath, cidLength: 8);
            using var holdLast = new ManualResetEventSlim(false);
            using var lastStarted = new ManualResetEventSlim(false);

            (int port, Reactor[] fleet) = TestServer.StartQuicSharded(2, engine.CreateFactory(), EchoHandler,
                holdLast: holdLast, lastStarted: lastStarted);

            const int Clients = 12;   // each moves to the late reactor with odds of one in two
            var clients = new List<QuicTestClient>();
            try
            {
                try
                {
                    for (int i = 0; i < Clients; i++)
                    {
                        var client = new QuicTestClient("127.0.0.1", port);
                        clients.Add(client);
                        client.Connect();
                        client.SendFirstFlight();   // queued on the one socket bound so far
                    }
                }
                finally
                {
                    holdLast.Set();
                }
                Assert.True(lastStarted.Wait(10_000), "the second reactor never started");

                // An echo per client, not the client's own view of its handshake: it counts the
                // handshake done once its Finished is SENT, and only the server knows it arrived.
                int served = 0;
                foreach (QuicTestClient client in clients)
                {
                    if (client.CompleteHandshake(3_000) && client.RequestEcho("ping"u8.ToArray(), 3_000) == "ping")
                    {
                        served++;
                    }
                }

                Assert.True(fleet[1].QuicForwardsSent > 0,
                    "no client's datagrams reached the late reactor, so the case under test never happened");
                Assert.True(served == Clients,
                    $"{served} of {Clients} clients were served: the rest had their handshake end on the reactor that did not own it");
            }
            finally
            {
                foreach (QuicTestClient client in clients)
                {
                    client.Dispose();
                }
            }
        });
    }

    private static async Task EchoHandler(Reactor reactor, QuicConnection conn)
    {
        try
        {
            while (true)
            {
                QuicRecvSnapshot snap = await conn.ReadAsync();

                while (conn.TryGetDelivery(in snap, out QuicRecvRing.Delivery item))
                {
                    conn.SendStream(item.StreamId, item.AsSpan(), item.Fin);
                    conn.ReturnBuffer(in item);
                }

                if (snap.IsClosed)
                {
                    break;
                }
                conn.ResetRead();
            }
        }
        finally
        {
            conn.DecRef();
        }
    }
}
