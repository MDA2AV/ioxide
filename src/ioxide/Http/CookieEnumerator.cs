namespace ioxide;

/// <summary>
/// Walks a request's cookies as (name, value) byte pairs, straight off its <c>cookie</c> field
/// lines - no strings, no allocation, nothing stored. HTTP/3 lets ONE logical cookie header
/// arrive split across several field lines (RFC 9114 §4.2.1), so this walks every cookie line and
/// every ';'-separated pair inside each; values slice the request's arena and are valid until the
/// handler returns.
/// </summary>
public ref struct CookieEnumerator
{
    private readonly KeyValueList _headers;
    private int _lineIndex;
    private ReadOnlyMemory<byte> _rest;   // unparsed tail of the current cookie line

    public CookieEnumerator(KeyValueList headers)
    {
        _headers = headers;
        _lineIndex = 0;
        _rest = default;
        Current = default;
    }

    public (ReadOnlyMemory<byte> Name, ReadOnlyMemory<byte> Value) Current { get; private set; }

    public readonly CookieEnumerator GetEnumerator() => this;

    public bool MoveNext()
    {
        while (true)
        {
            // One "name=value" off the front of the current line; pairs are ';'-separated
            // (conforming peers send "; ").
            while (!_rest.IsEmpty)
            {
                ReadOnlySpan<byte> span = _rest.Span;

                int start = 0;
                while (start < span.Length && (span[start] == (byte)' ' || span[start] == (byte)';'))
                {
                    start++;
                }
                if (start == span.Length)
                {
                    break;
                }

                int end = span[start..].IndexOf((byte)';');
                end = end < 0 ? span.Length : start + end;

                ReadOnlyMemory<byte> pair = _rest[start..end];
                _rest = end < span.Length ? _rest[(end + 1)..] : default;

                int equals = pair.Span.IndexOf((byte)'=');
                if (equals <= 0)
                {
                    continue;   // malformed or valueless - skip, don't fail the request
                }

                Current = (pair[..equals], pair[(equals + 1)..]);
                return true;
            }

            // Current line exhausted: find the next cookie field line, if any.
            ReadOnlySpan<KeyValuePair<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>>> lines = _headers.AsSpan();
            while (_lineIndex < lines.Length)
            {
                KeyValuePair<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>> line = lines[_lineIndex++];
                if (line.Key.Span.SequenceEqual("cookie"u8))
                {
                    _rest = line.Value;
                    break;
                }
            }
            if (_rest.IsEmpty)
            {
                return false;
            }
        }
    }
}
