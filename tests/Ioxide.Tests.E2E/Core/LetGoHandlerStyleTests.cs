using System.IO.Pipelines;
using System.Net.Sockets;
using ioxide;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>
/// Every way a handler can be reading when it lets go, in both ring modes, against every way its client can carry on.
/// What it took has to come back through whatever holds it: the queue, a reader's chain, or a stream's current slice.
/// </summary>
internal static class LetGoHandlerStyleTests
{
    private static readonly byte[] Pong = "pong"u8.ToArray();

    private static readonly (string Name, Func<Reactor, TcpConnection, Task> Handler)[] Styles =
    [
        ("returning from raw reads", Raw),
        ("throwing from raw reads", Throwing),
        ("leaving what it read in a pipe reader", ReaderHolding),
        ("completing its pipe reader", ReaderCompleted),
        ("leaving a read parked on its pipe reader", ReaderParked),
        ("leaving a dual pipe as it is", DualPipe),
        ("leaving part of a buffer in a stream", StreamHolding),
        ("disposing its stream", StreamDisposed),
    ];

    public static void Register(Runner runner)
    {
        bool noIncremental = !TestServer.KernelAtLeast(6, 12);

        foreach ((string style, Func<Reactor, TcpConnection, Task> handler) in Styles)
        {
            foreach ((LetGoDriver.Mode mode, LetGoDriver.Ending ending, string name) in LetGoDriver.Cases())
            {
                runner.Test($"let-go, {style}: {name}", () =>
                {
                    int port = TestServer.StartConfigured(handler, LetGoDriver.Configure(mode, ending)).Port;

                    // More than one byte, so a stream reading one has the rest of the buffer left over.
                    LetGoDriver.Check(() => LetGoDriver.Refused(port, "RRRR"u8), () => Asked(port), mode, ending);
                }, skip: noIncremental && mode == LetGoDriver.Incremental);
            }
        }
    }

    private static async Task Raw(Reactor _, TcpConnection conn)
    {
        try
        {
            while (await NextMarker(conn) == 'P')
            {
                await Answer(conn);
            }
        }
        finally
        {
            conn.DecRef();
        }
    }

    private static async Task Throwing(Reactor _, TcpConnection conn)
    {
        int marker;
        while ((marker = await NextMarker(conn)) == 'P')
        {
            await Answer(conn);
        }

        if (marker < 0)
        {
            conn.DecRef();   // the harness's listen probe
            return;
        }

        throw new InvalidOperationException("the handler failed, for the test");   // the reactor lets go for it
    }

    private static async Task ReaderHolding(Reactor _, TcpConnection conn)
    {
        try
        {
            await ReadWith(new TcpConnectionPipeReader(conn), conn);
        }
        finally
        {
            conn.DecRef();
        }
    }

    private static async Task ReaderCompleted(Reactor _, TcpConnection conn)
    {
        var reader = new TcpConnectionPipeReader(conn);
        try
        {
            await ReadWith(reader, conn);
        }
        finally
        {
            reader.Complete();
            conn.DecRef();
        }
    }

    private static async Task ReaderParked(Reactor reactor, TcpConnection conn)
    {
        var reader = new TcpConnectionPipeReader(conn);
        try
        {
            while (true)
            {
                ReadResult read = await reader.ReadAsync();
                if (read.Buffer.IsEmpty)
                {
                    return;   // the harness's listen probe
                }

                bool asked = read.Buffer.FirstSpan[0] == (byte)'P';
                reader.AdvanceTo(read.Buffer.End);
                if (!asked)
                {
                    _ = reader.ReadAsync();
                    return;
                }

                await Answer(conn);
            }
        }
        finally
        {
            conn.DecRef();
        }
    }

    private static async Task DualPipe(Reactor _, TcpConnection conn)
    {
        try
        {
            await ReadWith(new TcpConnectionDualPipe(conn).Input, conn);
        }
        finally
        {
            conn.DecRef();
        }
    }

    private static async Task StreamHolding(Reactor _, TcpConnection conn)
    {
        try
        {
            await ReadWith(new TcpConnectionStream(conn), conn);
        }
        finally
        {
            conn.DecRef();
        }
    }

    private static async Task StreamDisposed(Reactor _, TcpConnection conn)
    {
        try
        {
            await using var stream = new TcpConnectionStream(conn);
            await ReadWith(stream, conn);
        }
        finally
        {
            conn.DecRef();
        }
    }

    // Answers while it's asked, and stops at anything else with what it read still where it read it.
    private static async Task ReadWith(PipeReader reader, TcpConnection conn)
    {
        while (true)
        {
            ReadResult read = await reader.ReadAsync();
            if (read.Buffer.IsEmpty || read.Buffer.FirstSpan[0] != (byte)'P')
            {
                return;
            }

            reader.AdvanceTo(read.Buffer.End);
            await Answer(conn);
        }
    }

    private static async Task ReadWith(TcpConnectionStream stream, TcpConnection conn)
    {
        byte[] one = new byte[1];
        while (await stream.ReadAsync(one) == 1 && one[0] == (byte)'P')
        {
            await Answer(conn);
        }
    }

    private static async Task<int> NextMarker(TcpConnection conn)
    {
        while (true)
        {
            RecvSnapshot snapshot = await conn.ReadAsync();

            int marker = -1;
            while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
            {
                if (item.HasBuffer)
                {
                    marker = marker < 0 ? item.AsSpan()[0] : marker;
                    conn.ReturnBuffer(in item);
                }
            }

            if (marker >= 0 || snapshot.IsClosed)
            {
                return marker;
            }
        }
    }

    private static async Task Answer(TcpConnection conn)
    {
        conn.Write(Pong);
        await conn.FlushAsync();
    }

    private static bool Asked(int port) => LetGoDriver.Answers(() =>
    {
        using Socket socket = LetGoDriver.Connect(port);
        socket.Send("P"u8);

        var answer = new byte[4];
        for (int got = 0; got < answer.Length;)
        {
            int n = socket.Receive(answer, got, answer.Length - got, SocketFlags.None);
            if (n == 0)
            {
                return false;
            }

            got += n;
        }

        return answer.AsSpan().SequenceEqual(Pong);
    });
}
