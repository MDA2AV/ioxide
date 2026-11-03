using ioxide;
using ioxide.httpclient;

namespace Ioxide.Tests;

/// <summary>
/// The HTTP message types every client shares: the header list and the response arena. They hold
/// no I/O, but all three protocols write through them, so a bug here is a bug in h1, h2 and h3 at
/// once.
/// </summary>
internal static class MessageTests
{
    public static void Register(Runner runner)
    {
        runner.Test("headers: preserve order and duplicates", () =>
        {
            // Order is protocol-visible (set-cookie especially), and duplicate names are legal,
            // so this is a list and not a dictionary.
            var headers = new KeyValueList();
            headers.Add("set-cookie"u8.ToArray(), "a=1"u8.ToArray());
            headers.Add("content-type"u8.ToArray(), "text/plain"u8.ToArray());
            headers.Add("set-cookie"u8.ToArray(), "b=2"u8.ToArray());

            Assert.Equal(3, headers.Count);
            Assert.Equal("set-cookie", Text(headers[0].Key));
            Assert.Equal("a=1", Text(headers[0].Value));
            Assert.Equal("content-type", Text(headers[1].Key));
            Assert.Equal("b=2", Text(headers[2].Value));
        });

        runner.Test("headers: Clear resets the count but keeps the capacity", () =>
        {
            // Responses are pooled and refilled, so Clear must not drop the arrays it grew.
            var headers = new KeyValueList();
            for (int i = 0; i < 40; i++)
            {
                headers.Add("x"u8.ToArray(), "y"u8.ToArray());
            }

            headers.Clear();
            Assert.Equal(0, headers.Count);

            headers.Add("after"u8.ToArray(), "clear"u8.ToArray());
            Assert.Equal(1, headers.Count);
            Assert.Equal("after", Text(headers[0].Key));
        });

        runner.Test("response arena: ranges survive growth", () =>
        {
            // Append records offsets into one buffer that reallocates as it grows. A range taken
            // before a growth must still resolve to the same bytes after it, or a header parsed
            // early would point at someone else's data.
            using var response = new HttpClientResponse();

            (int Offset, int Length) first = response.Append("first"u8);
            response.Append(new byte[8192]);                       // forces at least one growth
            (int Offset, int Length) last = response.Append("last"u8);

            response.AddHeaderRange(first, last);
            response.SetBodyRange((0, 0));
            response.Freeze();

            Assert.Equal(1, response.Headers.Count);
            Assert.Equal("first", Text(response.Headers[0].Key));
            Assert.Equal("last", Text(response.Headers[0].Value));
        });

        runner.Test("response arena: body range slices only the body", () =>
        {
            // Header bytes land in the arena first, so the body range starts where they end.
            using var response = new HttpClientResponse();

            (int Offset, int Length) name = response.Append("content-type"u8);
            (int Offset, int Length) value = response.Append("text/plain"u8);
            response.AddHeaderRange(name, value);

            int bodyStart = response.ArenaLength;
            response.Append("BODY-BYTES"u8);
            response.SetBodyRange((bodyStart, 10));
            response.Freeze();

            Assert.Equal("BODY-BYTES", Text(response.Body));
            Assert.Equal("content-type", Text(response.Headers[0].Key));
        });

        runner.Test("response: LowercaseArena makes a wire name matchable", () =>
        {
            // TryGetHeader compares exactly. Wire names arrive in any case, so the h1 parser
            // lowercases them in the arena first - this is that step, not a lenient lookup.
            using var response = new HttpClientResponse();

            (int Offset, int Length) name = response.Append("Content-Type"u8);
            (int Offset, int Length) value = response.Append("text/html"u8);
            response.LowercaseArena(name);
            response.AddHeaderRange(name, value);
            response.SetBodyRange((0, 0));
            response.Freeze();

            Assert.True(response.TryGetHeader("content-type"u8, out ReadOnlyMemory<byte> found),
                "lowercased name should be found");
            Assert.Equal("text/html", Text(found));
            Assert.True(!response.TryGetHeader("content-length"u8, out _),
                "absent header should not be found");
        });

        runner.Test("response: ResetForInterim drops a 1xx and reuses the arena", () =>
        {
            // 103 Early Hints arrives, then the real response on the same connection. Everything
            // from the interim section has to go, or its headers are returned as the final body.
            using var response = new HttpClientResponse();

            (int Offset, int Length) hint = response.Append("link"u8);
            response.AddHeaderRange(hint, hint);
            response.Status = 103;

            response.ResetForInterim();

            Assert.Equal(0, response.ArenaLength);
            Assert.Equal(0, response.Status);

            // Write the real response into the reused arena and materialize. Freeze is what turns
            // recorded ranges into Headers, so asserting the count BEFORE it would pass even if
            // ResetForInterim had kept every interim range - the test could not fail.
            (int Offset, int Length) name = response.Append("content-type"u8);
            (int Offset, int Length) value = response.Append("text/plain"u8);
            response.AddHeaderRange(name, value);
            response.SetBodyRange((0, 0));
            response.Status = 200;
            response.Freeze();

            Assert.Equal(1, response.Headers.Count);
            Assert.Equal("content-type", Text(response.Headers[0].Key));
            Assert.Equal("text/plain", Text(response.Headers[0].Value));
        });
    }

    private static string Text(ReadOnlyMemory<byte> value)
        => System.Text.Encoding.ASCII.GetString(value.Span);
}
