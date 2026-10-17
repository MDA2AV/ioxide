using System.Net.Sockets;

namespace Epoxide.Tests;

// Optional things the tests drive but do not own: sidecars, and the system curl.
// Each reports ABSENCE rather than failing, so every suite stays runnable on a bare machine.

/// <summary>Reachability checks so sidecar-backed tests skip cleanly when the dependency is absent.</summary>
public static class Sidecars
{
    public static bool Reachable(string host, int port)
    {
        try
        {
            using var probe = new TcpClient();
            probe.Connect(host, port);
            return true;
        }
        catch
        {
            return false;
        }
    }

    // kTLS needs the kernel's 'tls' module; the loaded module shows up here.
    public static bool KtlsAvailable() => Directory.Exists("/sys/module/tls");
}

/// <summary>
/// The system curl, over TCP - a client that validates the chain AND matches the name, which is
/// what makes it worth driving alongside SslStream.
/// </summary>
/// <remarks>
/// SslStream in this harness accepts any certificate, so it can say WHICH one arrived but never
/// whether anyone would take it. curl answers the second question, and it is the one that matters
/// while certificates are being replaced underneath it.
/// </remarks>
public static class Curl
{
    private static readonly Lazy<bool> Present = new(() =>
    {
        try
        {
            return Run("curl", ["--version"], timeoutMs: 5000).Exit == 0;
        }
        catch (Exception)
        {
            return false;
        }
    });

    public static bool Available => Present.Value;

    /// <summary>
    /// One verified HTTPS GET. <paramref name="host"/> is sent as SNI and checked against the
    /// certificate; the connection still goes to loopback, which is what --resolve is for.
    /// Optionally presents a client certificate, for a server that asks for one.
    /// </summary>
    public static (int Exit, string Stdout, string Stderr) Get(string host, int port, string caPath,
        string path = "/", string? clientCert = null, string? clientKey = null, int timeoutMs = 15000)
    {
        var args = new List<string>
        {
            "--cacert", caPath,
            "--resolve", $"{host}:{port}:127.0.0.1",
            "--max-time", "15",
            "--silent", "--show-error",
        };

        if (clientCert is not null && clientKey is not null)
        {
            args.Add("--cert");
            args.Add(clientCert);
            args.Add("--key");
            args.Add(clientKey);
        }

        args.Add($"https://{host}:{port}{path}");

        return Run("curl", [.. args], timeoutMs);
    }

    /// <summary>Runs a binary and hands back what it said. Never throws on a non-zero exit - a refused
    /// connection IS the result some tests are asserting on.</summary>
    public static (int Exit, string Stdout, string Stderr) Run(string binary, string[] args, int timeoutMs = 15000)
    {
        var info = new System.Diagnostics.ProcessStartInfo
        {
            FileName = binary,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        foreach (string a in args)
        {
            info.ArgumentList.Add(a);
        }

        using var process = System.Diagnostics.Process.Start(info)
            ?? throw new IOException($"could not start {binary}");

        string stdout = process.StandardOutput.ReadToEnd();
        string stderr = process.StandardError.ReadToEnd();

        if (!process.WaitForExit(timeoutMs))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException($"{binary} did not exit within {timeoutMs}ms");
        }

        return (process.ExitCode, stdout, stderr);
    }
}
