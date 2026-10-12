using System.Diagnostics;
using System.Globalization;

namespace Ioxide.Tests;

/// <summary>
/// Which of this process's descriptors a child it starts inherits. A descriptor without close-on-exec
/// survives the exec, and the child then keeps that socket or file open for as long as it runs.
/// </summary>
public static class ExecInheritance
{
    /// <summary>What <paramref name="fd"/> refers to ("socket:[inode]", a path), or "" when it is not open.</summary>
    public static string Target(int fd)
    {
        try
        {
            return new FileInfo($"/proc/self/fd/{fd}").LinkTarget ?? "";
        }
        catch (IOException)
        {
            return "";
        }
    }

    /// <summary>This process's IPv4 TCP socket listening on <paramref name="port"/>, or "".</summary>
    public static string TcpListener(int port) => Own("/proc/self/net/tcp", port, listening: true);

    /// <summary>This process's IPv4 UDP socket bound to <paramref name="port"/>, or "".</summary>
    public static string Udp(int port) => Own("/proc/self/net/udp", port, listening: false);

    /// <summary>Starts a child process, returns what its descriptors refer to, and ends it.</summary>
    public static HashSet<string> HeldByChild()
    {
        // Start returns once the exec has happened, so close-on-exec has already been applied.
        using Process child = Process.Start(new ProcessStartInfo("sleep", "30") { UseShellExecute = false })!;
        try
        {
            return Directory.EnumerateFileSystemEntries($"/proc/{child.Id}/fd")
                .Select(fd => new FileInfo(fd).LinkTarget ?? "")
                .ToHashSet();
        }
        finally
        {
            child.Kill();
            child.WaitForExit();
        }
    }

    // /proc/net lists every socket in the namespace, so the match is kept only if this process holds it.
    private static string Own(string table, int port, bool listening)
    {
        HashSet<string> mine = Directory.EnumerateFileSystemEntries("/proc/self/fd")
            .Select(fd => Target(int.Parse(Path.GetFileName(fd), CultureInfo.InvariantCulture)))
            .ToHashSet();

        foreach (string line in File.ReadLines(table).Skip(1))
        {
            // sl local_address rem_address st ... inode: "0100007F:4E20", state 0A is LISTEN.
            string[] f = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            int localPort = int.Parse(f[1].AsSpan(f[1].IndexOf(':') + 1), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            string target = $"socket:[{f[9]}]";
            if (localPort == port && (!listening || f[3] == "0A") && mine.Contains(target))
            {
                return target;
            }
        }

        return "";
    }
}
