using System.Text;
using ioxide;
using ioxide.http2;
using ioxide.nghttp2;

namespace Ioxide.Tests;

/// <summary>
/// TryGetHeader and Cookies on both HTTP/2 stacks' requests, which read through the core's
/// KeyValueList and CookieEnumerator. Each request is filled the way its decoder fills it: one
/// line per field, in wire order.
/// </summary>
internal static class Http2RequestHeaderTests
{
    private delegate bool HeaderLookup(ReadOnlySpan<byte> name, out ReadOnlyMemory<byte> value);

    public static void Register(Runner runner)
    {
        foreach (bool native in new[] { false, true })
        {
            bool ng = native;
            string stack = ng ? "nghttp2" : "ioxide.http2";

            runner.Test($"h2 request ({stack}): TryGetHeader answers the first line with exactly that name", () =>
            {
                (KeyValueList headers, HeaderLookup tryGetHeader, _) = New(ng);
                Add(headers, "x-trace", "first");
                Add(headers, "accept", "text/plain");
                Add(headers, "x-trace", "second");

                Assert.Equal("first", Lookup(tryGetHeader, "x-trace"));    // a repeated name answers with its first line
                Assert.Equal("text/plain", Lookup(tryGetHeader, "accept"));
                Assert.Equal("absent", Lookup(tryGetHeader, "x-missing"));
                Assert.Equal("absent", Lookup(tryGetHeader, "X-Trace"));   // names arrive lowercase and match exactly
            });

            runner.Test($"h2 request ({stack}): Cookies walks every pair of every cookie line, in order", () =>
            {
                // RFC 9113 8.2.3 lets a client split its cookie header into several lines, each with one or more pairs.
                (KeyValueList headers, _, Func<CookieEnumerator> cookies) = New(ng);
                Add(headers, "cookie", "a=1; b=2");
                Add(headers, "x-cookie", "z=9");   // not a cookie line, though its value reads as a pair
                Add(headers, "cookie", "c=3");
                Add(headers, "cookie", "d=4; e=5");

                Assert.Equal("a=1|b=2|c=3|d=4|e=5", Pairs(cookies()));
            });
        }
    }

    // A fresh request of either stack: the list its decoder fills, and its own two lookups.
    private static (KeyValueList Headers, HeaderLookup TryGetHeader, Func<CookieEnumerator> Cookies) New(bool native)
    {
        if (native)
        {
            var request = new Nghttp2Request();
            return (request.Headers, request.TryGetHeader, () => request.Cookies);
        }

        var managed = new Http2Request();
        return (managed.Headers, managed.TryGetHeader, () => managed.Cookies);
    }

    private static void Add(KeyValueList headers, string name, string value)
        => headers.Add(Encoding.ASCII.GetBytes(name), Encoding.ASCII.GetBytes(value));

    private static string Lookup(HeaderLookup tryGetHeader, string name)
        => tryGetHeader(Encoding.ASCII.GetBytes(name), out ReadOnlyMemory<byte> value) ? Ascii(value) : "absent";

    private static string Pairs(CookieEnumerator cookies)
    {
        var pairs = new List<string>();
        foreach ((ReadOnlyMemory<byte> name, ReadOnlyMemory<byte> value) in cookies)
        {
            pairs.Add($"{Ascii(name)}={Ascii(value)}");
        }
        return string.Join('|', pairs);
    }

    private static string Ascii(ReadOnlyMemory<byte> bytes) => Encoding.ASCII.GetString(bytes.Span);
}
