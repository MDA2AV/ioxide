namespace Ioxide.Tests;

/// <summary>This process's TCP connections from /proc/net/tcp, which unlike a descriptor count shows a socket outliving its close().</summary>
public static class TcpSockets
{
    private const string Established = "01";   // the "st" column

    /// <summary>One IPv4 connection, named by both of its ends exactly as /proc/net/tcp prints them.</summary>
    public readonly record struct Connection(string Local, string Remote);

    /// <summary>This process's IPv4 connections that are ESTABLISHED to <paramref name="remotePort"/>.</summary>
    public static HashSet<Connection> EstablishedTo(int remotePort)
    {
        HashSet<string> mine = OwnSocketInodes();
        var found = new HashSet<Connection>();

        foreach (string[] row in Rows())
        {
            if (row[3] == Established && PortOf(row[2]) == remotePort && mine.Contains(row[9]))
            {
                found.Add(new Connection(row[1], row[2]));
            }
        }

        return found;
    }

    /// <summary>Whether <paramref name="connection"/> is still ESTABLISHED, whether or not a descriptor still holds it.</summary>
    public static bool StillEstablished(Connection connection)
        => Rows().Any(row => row[1] == connection.Local && row[2] == connection.Remote && row[3] == Established);

    /// <summary>Waits for <paramref name="count"/> connections to <paramref name="remotePort"/> beyond <paramref name="earlier"/>, and returns what it found.</summary>
    public static HashSet<Connection> WaitForNew(int remotePort, HashSet<Connection> earlier, int count, int timeoutMs = 10_000)
    {
        long deadlineMs = Environment.TickCount64 + timeoutMs;

        while (true)
        {
            HashSet<Connection> fresh = EstablishedTo(remotePort);
            fresh.ExceptWith(earlier);

            if (fresh.Count >= count || Environment.TickCount64 > deadlineMs)
            {
                return fresh;
            }

            Thread.Sleep(20);
        }
    }

    /// <summary>Waits until any of <paramref name="connections"/> stops being ESTABLISHED, and returns the ones that have.</summary>
    public static List<Connection> WaitForAnyToEnd(IReadOnlyCollection<Connection> connections, int timeoutMs)
    {
        long deadlineMs = Environment.TickCount64 + timeoutMs;

        while (true)
        {
            List<Connection> ended = connections.Where(c => !StillEstablished(c)).ToList();

            if (ended.Count > 0 || Environment.TickCount64 > deadlineMs)
            {
                return ended;
            }

            Thread.Sleep(20);
        }
    }

    // Columns: sl, local_address, rem_address, st, tx:rx queues, tr:when, retrnsmt, uid, timeout, inode.
    private static IEnumerable<string[]> Rows()
        => File.ReadAllLines("/proc/net/tcp")
            .Skip(1)
            .Select(line => line.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            .Where(row => row.Length > 9);

    private static int PortOf(string endpoint) => Convert.ToInt32(endpoint[(endpoint.IndexOf(':') + 1)..], 16);

    // A socket descriptor links to "socket:[inode]", the number in the inode column.
    private static HashSet<string> OwnSocketInodes()
    {
        var inodes = new HashSet<string>();

        foreach (string fd in Directory.EnumerateFileSystemEntries("/proc/self/fd"))
        {
            try
            {
                string? target = new FileInfo(fd).LinkTarget;
                if (target is not null && target.StartsWith("socket:[", StringComparison.Ordinal))
                {
                    inodes.Add(target["socket:[".Length..^1]);
                }
            }
            catch (IOException)
            {
                // Closed between the listing and the read.
            }
        }

        return inodes;
    }
}
