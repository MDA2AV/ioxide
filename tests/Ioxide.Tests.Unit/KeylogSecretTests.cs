using System.Text;
using ioxide.tls;

namespace Ioxide.Tests;

/// <summary>
/// The traffic secret kTLS takes from BoringSSL's key-log line, decoded from the line's bytes: a string of the line
/// would keep the secret, as hex, where nothing can zero it (#542).
/// </summary>
internal static class KeylogSecretTests
{
    private static readonly byte[] Secret = Enumerable.Range(0, 32).Select(i => (byte)(i * 7 + 1)).ToArray();

    private static byte[] Line(string label, string hex, string end = "")
        => Encoding.ASCII.GetBytes($"{label} {new string('a', 64)} {hex}{end}");

    public static void Register(Runner runner)
    {
        runner.Test("keylog: a traffic secret line decodes to the secret, in either case, with or without a newline", () =>
        {
            foreach (string hex in new[] { Convert.ToHexString(Secret), Convert.ToHexStringLower(Secret) })
            {
                foreach (string end in new[] { "", "\n" })
                {
                    byte[]? secret = TlsService.TrafficSecret(Line("SERVER_TRAFFIC_SECRET_0", hex, end));
                    Assert.True(secret is not null && secret.AsSpan().SequenceEqual(Secret),
                        $"'{hex}' ending '{end.Replace("\n", "\\n")}' decoded to {(secret is null ? "nothing" : Convert.ToHexString(secret))}");
                }
            }
        });

        runner.Test("keylog: decoding a secret allocates its own array and nothing else", () =>
        {
            byte[] line = Line("CLIENT_TRAFFIC_SECRET_0", Convert.ToHexString(Secret));
            TlsService.TrafficSecret(line);   // the first call may tier up or initialise statics

            long before = GC.GetAllocatedBytesForCurrentThread();
            byte[]? secret = TlsService.TrafficSecret(line);
            long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

            // 32 bytes take a 56-byte array on x64; a string of this line alone would be over 300.
            Assert.True(secret is not null && allocated <= Secret.Length + 32,
                $"decoding a {Secret.Length}-byte secret allocated {allocated} bytes");
        });
    }
}
