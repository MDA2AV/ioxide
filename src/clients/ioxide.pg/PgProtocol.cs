using System.Buffers.Binary;
using System.Text;

namespace ioxide.pg;

/// <summary>
/// The Postgres v3 frontend/backend protocol. This class is pure: it formats and parses bytes, and
/// knows nothing about io_uring, reactors, or sockets.
/// </summary>
internal static class PgProtocol
{
    // The protocol version is 3.0, encoded as the major number in the high 16 bits.
    private const int ProtocolVersion3 = 3 << 16;

    // Backend message tags (the ones the simple-query flow can meet; everything
    // else is skipped by walking the self-describing length).
    public const byte Authentication  = (byte)'R';
    public const byte ErrorResponse   = (byte)'E';
    public const byte ReadyForQuery   = (byte)'Z';
    public const byte RowDescription  = (byte)'T';
    public const byte DataRow         = (byte)'D';
    public const byte CommandComplete = (byte)'C';
    public const byte ParseComplete   = (byte)'1';   // extended protocol: Parse acknowledged
    public const byte BindComplete    = (byte)'2';   // extended protocol: Bind acknowledged

    /// <summary>
    /// Write a StartupMessage carrying the user and database parameters, returning its total
    /// length. This is the first thing a client sends after the socket connects.
    /// </summary>
    public static int WriteStartup(Span<byte> buffer, string user, string database)
    {
        // The first eight bytes are the message length and the protocol version. We don't know the
        // length until the parameter list is written, so leave room and fill them in at the end.
        int position = 8;

        position += WriteCString(buffer, position, "user");
        position += WriteCString(buffer, position, user);

        position += WriteCString(buffer, position, "database");
        position += WriteCString(buffer, position, database);

        // An empty key (a lone NUL) terminates the parameter list.
        buffer[position++] = 0;

        BinaryPrimitives.WriteInt32BigEndian(buffer, position);
        BinaryPrimitives.WriteInt32BigEndian(buffer[4..], ProtocolVersion3);

        return position;
    }

    /// <summary>
    /// Write a simple Query message ('Q') wrapping <paramref name="sql"/>, returning its total
    /// length. Size the buffer with <see cref="QueryLength"/> first.
    /// </summary>
    public static int WriteQuery(Span<byte> buffer, string sql)
    {
        // Layout: a 'Q' tag, a 4-byte length covering everything after the tag, then the SQL text
        // as a NUL-terminated string.
        buffer[0] = (byte)'Q';

        int bodyLength = WriteCString(buffer, 5, sql);

        BinaryPrimitives.WriteInt32BigEndian(buffer[1..], 4 + bodyLength);

        return 5 + bodyLength;
    }

    /// <summary>SASLInitialResponse: mechanism name + the client-first message.</summary>
    public static int WriteSaslInitialResponse(Span<byte> buffer, string mechanism, ReadOnlySpan<byte> initial)
    {
        buffer[0] = (byte)'p';
        int position = 5;
        position += WriteCString(buffer, position, mechanism);
        BinaryPrimitives.WriteInt32BigEndian(buffer[position..], initial.Length);
        position += 4;
        initial.CopyTo(buffer[position..]);
        position += initial.Length;
        BinaryPrimitives.WriteInt32BigEndian(buffer[1..], position - 1);
        return position;
    }

    /// <summary>SASLResponse: the raw continuation payload (client-final message).</summary>
    public static int WriteSaslResponse(Span<byte> buffer, ReadOnlySpan<byte> data)
    {
        buffer[0] = (byte)'p';
        BinaryPrimitives.WriteInt32BigEndian(buffer[1..], 4 + data.Length);
        data.CopyTo(buffer[5..]);
        return 5 + data.Length;
    }

    /// <summary>Does an AuthenticationSASL mechanism list (body after the code) offer SCRAM-SHA-256?</summary>
    public static bool OffersScramSha256(ReadOnlySpan<byte> mechanisms)
    {
        while (mechanisms.Length > 0)
        {
            int end = mechanisms.IndexOf((byte)0);
            if (end <= 0) break;
            if (mechanisms[..end].SequenceEqual("SCRAM-SHA-256"u8)) return true;
            mechanisms = mechanisms[(end + 1)..];
        }
        return false;
    }

    /// <summary>The exact bytes <see cref="WriteQuery"/> needs for <paramref name="sql"/>.</summary>
    public static int QueryLength(string sql)
    {
        return 5 + Encoding.UTF8.GetByteCount(sql) + 1;
    }

    /// <summary>
    /// Write one extended-protocol command: an optional Parse (when the statement is new), then
    /// Bind (text-format params, text-format results), Execute (all rows), and Sync. The Sync makes
    /// the server answer with one ReadyForQuery, so the command routes like a simple query.
    /// </summary>
    public static int WriteExtended(Span<byte> buffer, bool parse, string statementName, string sql, ReadOnlySpan<PgParam> args)
    {
        int position = 0;
        if (parse)
        {
            position += WriteParse(buffer, statementName, sql);
        }
        position += WriteBind(buffer[position..], statementName, args);
        position += WriteExecute(buffer[position..]);
        position += WriteSync(buffer[position..]);
        return position;
    }

    /// <summary>An upper bound on the bytes <see cref="WriteExtended"/> needs (params sized to their max text length).</summary>
    public static int ExtendedLength(bool parse, string statementName, string sql, ReadOnlySpan<PgParam> args)
    {
        int nameLen = Encoding.UTF8.GetByteCount(statementName) + 1;
        int total = 0;
        if (parse)
        {
            total += 5 + nameLen + Encoding.UTF8.GetByteCount(sql) + 1 + 2;   // Parse: name, sql, int16 param-type count
        }
        int paramBytes = 0;
        foreach (PgParam a in args)
        {
            paramBytes += 4 + a.MaxBytes;        // int32 length prefix + value
        }
        total += 5 + 1 + nameLen + 2 + 2 + paramBytes + 2;   // Bind: portal, stmt, fmt-count, param-count, params, result-fmt-count
        total += 5 + 1 + 4;                                  // Execute: portal, max-rows
        total += 5;                                          // Sync
        return total;
    }

    // Parse ('P'): statement name, the SQL with $n placeholders, and an int16 0 = infer parameter types.
    private static int WriteParse(Span<byte> buffer, string statementName, string sql)
    {
        buffer[0] = (byte)'P';
        int position = 5;
        position += WriteCString(buffer, position, statementName);
        position += WriteCString(buffer, position, sql);
        BinaryPrimitives.WriteInt16BigEndian(buffer[position..], 0);
        position += 2;
        BinaryPrimitives.WriteInt32BigEndian(buffer[1..], position - 1);
        return position;
    }

    // Bind ('B'): unnamed portal, the statement, all-text params, then all-text results.
    private static int WriteBind(Span<byte> buffer, string statementName, ReadOnlySpan<PgParam> args)
    {
        buffer[0] = (byte)'B';
        int position = 5;
        buffer[position++] = 0;                              // portal "" (NUL only)
        position += WriteCString(buffer, position, statementName);
        BinaryPrimitives.WriteInt16BigEndian(buffer[position..], 0);   // 0 param format codes = all text
        position += 2;
        BinaryPrimitives.WriteInt16BigEndian(buffer[position..], (short)args.Length);
        position += 2;
        foreach (PgParam a in args)
        {
            if (a.IsNull)
            {
                BinaryPrimitives.WriteInt32BigEndian(buffer[position..], -1);
                position += 4;
            }
            else
            {
                int written = a.WriteText(buffer[(position + 4)..]);
                BinaryPrimitives.WriteInt32BigEndian(buffer[position..], written);
                position += 4 + written;
            }
        }
        BinaryPrimitives.WriteInt16BigEndian(buffer[position..], 0);   // 0 result format codes = all text
        position += 2;
        BinaryPrimitives.WriteInt32BigEndian(buffer[1..], position - 1);
        return position;
    }

    // Execute ('E'): unnamed portal, max-rows 0 = return every row.
    private static int WriteExecute(Span<byte> buffer)
    {
        buffer[0] = (byte)'E';
        int position = 5;
        buffer[position++] = 0;                              // portal ""
        BinaryPrimitives.WriteInt32BigEndian(buffer[position..], 0);
        position += 4;
        BinaryPrimitives.WriteInt32BigEndian(buffer[1..], position - 1);
        return position;
    }

    // Sync ('S'): a bare 4-byte length.
    private static int WriteSync(Span<byte> buffer)
    {
        buffer[0] = (byte)'S';
        BinaryPrimitives.WriteInt32BigEndian(buffer[1..], 4);
        return 5;
    }

    private static int WriteCString(Span<byte> buffer, int position, string text)
    {
        // Reserve the trailing NUL up front; GetBytes throws if the text doesn't fit,
        // which callers prevent by sizing the buffer first.
        int written = Encoding.UTF8.GetBytes(text, buffer.Slice(position, buffer.Length - position - 1));

        buffer[position + written] = 0;

        return written + 1;
    }

    /// <summary>
    /// Read one complete message at <paramref name="position"/>, advancing it. False if not fully
    /// arrived; throws on malformed framing (unresynchronizable).
    /// </summary>
    public static bool TryReadMessage(ReadOnlySpan<byte> buffer, ref int position, out byte tag, out int bodyStart, out int bodyLength)
    {
        tag = 0;
        bodyStart = 0;
        bodyLength = 0;

        // Every message is a 1-byte tag, a 4-byte length (which counts itself), then the body.
        if (position + 5 > buffer.Length)
        {
            return false;
        }

        tag = buffer[position];
        int length = BinaryPrimitives.ReadInt32BigEndian(buffer[(position + 1)..]);

        if (length < 4)
        {
            throw new PgException($"malformed backend message: tag '{(char)tag}' length {length}");
        }

        if (position + 1 + length > buffer.Length)
        {
            return false;   // not fully arrived; recv more
        }

        bodyStart = position + 5;
        bodyLength = length - 4;
        position += 1 + length;

        return true;
    }

    /// <summary>
    /// Read the first field of a DataRow body. Reports offset/length relative to the body, with
    /// length -1 for SQL NULL. False if the row has no fields.
    /// </summary>
    public static bool TryReadFirstField(ReadOnlySpan<byte> body, out int fieldOffset, out int fieldLength)
    {
        fieldOffset = 0;
        fieldLength = 0;

        // An int16 field count, then for each field an int32 length and its bytes.
        if (body.Length < 6)
        {
            return false;
        }

        short fieldCount = BinaryPrimitives.ReadInt16BigEndian(body);
        if (fieldCount <= 0)
        {
            return false;
        }

        int length = BinaryPrimitives.ReadInt32BigEndian(body[2..]);

        if (length < 0)
        {
            fieldOffset = 6;
            fieldLength = -1;   // SQL NULL
            return true;
        }

        if (6 + length > body.Length)
        {
            throw new PgException("malformed DataRow: field overruns the message body");
        }

        fieldOffset = 6;
        fieldLength = length;
        return true;
    }

    /// <summary>The AuthenticationRequest code: 0 = Ok.</summary>
    public static int ReadAuthCode(ReadOnlySpan<byte> body)
    {
        return body.Length >= 4 ? BinaryPrimitives.ReadInt32BigEndian(body) : -1;
    }

    /// <summary>
    /// Parse a RowDescription ('T') body into column metadata: an int16 field count, then per field a
    /// NUL-terminated name, table OID (int32), column attribute (int16), type OID (int32), type size
    /// (int16), type modifier (int32), and format code (int16).
    /// </summary>
    public static PgColumn[] ParseRowDescription(ReadOnlySpan<byte> body)
    {
        if (body.Length < 2)
        {
            return [];
        }
        short count = BinaryPrimitives.ReadInt16BigEndian(body);
        if (count <= 0)
        {
            return [];
        }

        var columns = new PgColumn[count];
        int p = 2;
        for (int i = 0; i < count; i++)
        {
            int nameEnd = body[p..].IndexOf((byte)0);
            if (nameEnd < 0 || p + nameEnd + 1 + 18 > body.Length)
            {
                throw new PgException("malformed RowDescription");
            }
            string name = Encoding.UTF8.GetString(body.Slice(p, nameEnd));
            p += nameEnd + 1;

            int tableOid = BinaryPrimitives.ReadInt32BigEndian(body[p..]);       p += 4;
            short colAttr = BinaryPrimitives.ReadInt16BigEndian(body[p..]);      p += 2;
            int typeOid = BinaryPrimitives.ReadInt32BigEndian(body[p..]);        p += 4;
            short typeSize = BinaryPrimitives.ReadInt16BigEndian(body[p..]);     p += 2;
            int typeMod = BinaryPrimitives.ReadInt32BigEndian(body[p..]);        p += 4;
            short formatCode = BinaryPrimitives.ReadInt16BigEndian(body[p..]);   p += 2;

            columns[i] = new PgColumn(name, tableOid, colAttr, typeOid, typeSize, typeMod, formatCode);
        }
        return columns;
    }

    /// <summary>
    /// Parse an ErrorResponse (or NoticeResponse) body: a sequence of (field-type byte,
    /// NUL-terminated string) pairs ending with a lone NUL. Reports severity, SQLSTATE, message.
    /// </summary>
    public static (string Severity, string SqlState, string Message) ReadError(ReadOnlySpan<byte> body)
    {
        string severity = "";
        string sqlState = "";
        string message = "";
        string detail = "";
        string hint = "";

        int i = 0;
        while (i < body.Length && body[i] != 0)
        {
            byte field = body[i++];

            int start = i;
            while (i < body.Length && body[i] != 0)
            {
                i++;
            }

            string value = Encoding.UTF8.GetString(body[start..i]);
            i++;   // skip the NUL

            switch ((char)field)
            {
                case 'S': severity = value; break;
                case 'C': sqlState = value; break;
                case 'M': message  = value; break;
                case 'D': detail   = value; break;   // detail and hint are often the most useful part
                case 'H': hint     = value; break;
            }
        }

        if (detail.Length > 0) message += $" DETAIL: {detail}";
        if (hint.Length > 0)   message += $" HINT: {hint}";

        return (severity, sqlState, message);
    }

    /// <summary>A NUL-terminated UTF8 string at the start of <paramref name="body"/> (e.g. a CommandComplete tag).</summary>
    public static string ReadCString(ReadOnlySpan<byte> body)
    {
        int end = body.IndexOf((byte)0);
        return Encoding.UTF8.GetString(end >= 0 ? body[..end] : body);
    }
}
