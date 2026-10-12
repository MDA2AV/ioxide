using System.Net.Sockets;

namespace Ioxide.Tests;

/// <summary>
/// Joins a connection a <see cref="FakeServer"/> accepted to a real server, so a script can
/// misbehave on some connections and hand the rest to the real thing.
/// </summary>
public static class Forwarder
{
    /// <summary>Copies bytes both ways between <paramref name="accepted"/> and host:port until either side closes.</summary>
    public static void Forward(Socket accepted, string host, int port)
    {
        using var upstream = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        upstream.Connect(host, port);

        var back = new Thread(() => Pump(upstream, accepted)) { IsBackground = true, Name = $"forward-{port}" };
        back.Start();
        Pump(accepted, upstream);
        back.Join();
    }

    private static void Pump(Socket from, Socket to)
    {
        var buffer = new byte[16 * 1024];

        try
        {
            int n;
            while ((n = from.Receive(buffer)) > 0)
            {
                to.Send(buffer, n, SocketFlags.None);
            }
        }
        catch (Exception)
        {
            // Either side closed under the copy.
        }

        try
        {
            to.Shutdown(SocketShutdown.Send);
        }
        catch (Exception)
        {
            // Already closed.
        }
    }
}
