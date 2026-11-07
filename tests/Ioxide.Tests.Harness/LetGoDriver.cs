using System.Net;
using System.Net.Sockets;
using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// Clients that outlive their handlers, for any server on the TCP transport. Once a handler has let go nobody reads
/// its connection, so what its client goes on sending holds buffers. A server survives that if a new client is still
/// served and the connections end, whichever way the client goes and whether or not a read timeout is set.
/// </summary>
public static class LetGoDriver
{
    public const int GraceMs = 4_000;

    private const int Clients = 3;

    /// <summary>Which rings the clients empty, and what that takes: below the 64-entry queue, so nothing overflows.</summary>
    public sealed record Mode(string Name, int SendsEach, int BytesEach, Func<ServerConfig, ServerConfig> Rings);

    public static readonly Mode Shared = new("shared ring", SendsEach: 30, BytesEach: 1,
        config => config with { RecvBufferSize = 4096, RecvSlots = 64 });

    public static readonly Mode Incremental = new("incremental", SendsEach: 8, BytesEach: 8 * 1024,
        config => config with { Incremental = new IncrementalOptions { MaxConnections = 16, RecvSlots = 4, RecvBufferSize = 4096 } });

    /// <summary>What the clients do next, and whether that ends the connections.</summary>
    public sealed record Ending(string Name, bool Leave, int ReadTimeoutMs, bool Ends);

    public static readonly Ending TheyLeave = new("they leave", Leave: true, ReadTimeoutMs: 300, Ends: true);
    public static readonly Ending TheyLeaveNoTimeout = new("they leave, no read timeout", Leave: true, ReadTimeoutMs: 0, Ends: true);
    public static readonly Ending TheyStay = new("they stay, until the read timeout", Leave: false, ReadTimeoutMs: 300, Ends: true);
    public static readonly Ending TheyStayNoTimeout = new("they stay, no read timeout", Leave: false, ReadTimeoutMs: 0, Ends: false);

    /// <summary>Every case that can show anything: a ring of its own takes nobody else's buffers, and with no end coming nothing can be seen to close.</summary>
    public static IEnumerable<(Mode Mode, Ending Ending, string Name)> Cases()
    {
        foreach (Mode mode in new[] { Shared, Incremental })
        {
            foreach (Ending ending in new[] { TheyLeave, TheyLeaveNoTimeout, TheyStay, TheyStayNoTimeout })
            {
                if (mode != Incremental || ending != TheyStayNoTimeout)
                {
                    yield return (mode, ending, $"{mode.Name}, {ending.Name}");
                }
            }
        }
    }

    public static ServerConfig Configure(Mode mode, Ending ending, ServerConfig? config = null)
    {
        config ??= new ServerConfig();
        return mode.Rings(config) with
        {
            Tcp = (config.Tcp ?? new TcpOptions()) with { RecvQueueEntries = 64, ReadTimeoutMs = ending.ReadTimeoutMs, SendTimeoutMs = 500 },
        };
    }

    /// <param name="letGoClient">A connected client whose handler has let go, or is about to.</param>
    /// <param name="served">Whether a new client, using the server as it should, gets its answer.</param>
    public static void Check(Func<Socket> letGoClient, Func<bool> served, Mode mode, Ending ending)
    {
        Thread.Sleep(150);   // what the harness's listen probe left behind has gone
        int before = OpenSockets();

        var clients = new List<Socket>();
        try
        {
            for (int i = 0; i < Clients; i++)
            {
                clients.Add(letGoClient());
            }

            byte[] message = new byte[mode.BytesEach];
            for (int round = 0; round < mode.SendsEach; round++)
            {
                foreach (Socket client in clients)
                {
                    TrySend(client, message);
                }

                Thread.Sleep(1);   // apart, so each is a recv of its own
            }

            if (ending.Leave)
            {
                clients.ForEach(client => client.Dispose());
                clients.Clear();
            }

            Thread.Sleep(ending.ReadTimeoutMs > 0 ? 1_000 : 300);

            Assert.True(served(), "a new client was never answered: the connections its handlers let go kept the buffers");

            if (ending.Ends)
            {
                int expected = before + clients.Count;
                Assert.True(Eventually(() => OpenSockets() <= expected),
                    $"{OpenSockets() - expected} connections still open, with a new client served and their handlers long gone");
            }
        }
        finally
        {
            clients.ForEach(client => client.Dispose());
        }
    }

    public static Socket Connect(int port, int? receiveBuffer = null)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
        {
            NoDelay = true,
            ReceiveTimeout = GraceMs,
            SendTimeout = GraceMs,
        };
        if (receiveBuffer is int bytes)
        {
            socket.ReceiveBufferSize = bytes;   // before the connect, so it is the window advertised
        }

        socket.Connect(IPAddress.Loopback, port);
        return socket;
    }

    /// <summary>Connected, and everything the server sent has been read through to its FIN or reset.</summary>
    public static Socket Refused(int port, ReadOnlySpan<byte> first)
    {
        Socket client = Connect(port);
        client.Send(first);
        ReadToEnd(client);
        return client;
    }

    public static void ReadToEnd(Socket client)
    {
        var buffer = new byte[4096];
        try
        {
            while (client.Receive(buffer) > 0)
            {
            }
        }
        catch (SocketException e) when (e.SocketErrorCode == SocketError.ConnectionReset)
        {
            // A reset is an end too: the sends that follow are what the test is about.
        }
    }

    public static bool Answers(Func<bool> request)
    {
        try
        {
            return request();
        }
        catch (Exception e) when (e is IOException or SocketException or System.Security.Authentication.AuthenticationException)
        {
            return false;
        }
    }

    public static int OpenSockets()
    {
        int count = 0;
        foreach (string fd in Directory.GetFiles("/proc/self/fd"))
        {
            if (new FileInfo(fd).LinkTarget?.StartsWith("socket:", StringComparison.Ordinal) == true)
            {
                count++;
            }
        }

        return count;
    }

    public static bool Eventually(Func<bool> condition)
    {
        long deadlineMs = Environment.TickCount64 + GraceMs;
        while (Environment.TickCount64 < deadlineMs)
        {
            if (condition())
            {
                return true;
            }

            Thread.Sleep(10);
        }

        return condition();
    }

    private static void TrySend(Socket client, byte[] message)
    {
        try
        {
            client.Send(message);
        }
        catch (SocketException)
        {
            // The server has already ended this one, which is allowed at any point from here.
        }
    }
}
