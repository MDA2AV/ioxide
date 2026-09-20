namespace ioxide.http2;

/// <summary>
/// HPACK (RFC 7541): the header compression HTTP/2 mandates. Prefix-coded integers, a 61-entry
/// static table both peers know, a dynamic table each peer maintains, and optional Huffman coding
/// of the literals.
///
/// The dynamic table is the part that has to be exactly right: it is CONNECTION state, mutated as a
/// side effect of decoding, so a decoder that mis-sizes an entry or forgets an eviction stays
/// desynchronised from the peer forever - every later header block decodes to garbage. Hence the
/// RFC's own size accounting (name + value + 32) rather than anything cheaper.
/// </summary>
internal sealed class HpackDecoder
{
    private readonly DynamicTable _table;

    internal HpackDecoder(int maxTableSize = 4096) => _table = new DynamicTable(maxTableSize);

    /// <summary>Thrown on a malformed block. The connection is done: HPACK has no resync point.</summary>
    internal sealed class HpackException(string message) : Exception(message);

    /// <summary>
    /// Decode one header block, invoking <paramref name="onHeader"/> per field. Names and values
    /// point into <paramref name="scratch"/> or into the tables, and are valid until the next call.
    /// </summary>
    internal void Decode(ReadOnlySpan<byte> block, Span<byte> scratch, HeaderSink onHeader)
    {
        int position = 0;
        int scratchUsed = 0;

        while (position < block.Length)
        {
            byte first = block[position];

            if ((first & 0x80) != 0)
            {
                // 1xxxxxxx - fully indexed: both name and value come from a table.
                int index = (int)ReadInteger(block, ref position, 7);
                Lookup(index, out ReadOnlySpan<byte> name, out ReadOnlySpan<byte> value);
                onHeader(name, value);
                continue;
            }

            bool index0 = (first & 0x40) != 0;                       // 01xxxxxx - literal, indexed
            bool sizeUpdate = !index0 && (first & 0x20) != 0;        // 001xxxxx - table size update

            if (sizeUpdate)
            {
                int newSize = (int)ReadInteger(block, ref position, 5);
                _table.Resize(newSize);
                continue;
            }

            // 01xxxxxx incremental, 0000xxxx without indexing, 0001xxxx never indexed.
            int prefix = index0 ? 6 : 4;
            int nameIndex = (int)ReadInteger(block, ref position, prefix);

            ReadOnlySpan<byte> headerName;
            if (nameIndex == 0)
            {
                headerName = ReadLiteral(block, ref position, scratch, ref scratchUsed);
            }
            else
            {
                Lookup(nameIndex, out headerName, out _);
            }

            ReadOnlySpan<byte> headerValue = ReadLiteral(block, ref position, scratch, ref scratchUsed);

            if (index0)
            {
                _table.Add(headerName, headerValue);
            }

            onHeader(headerName, headerValue);
        }
    }

    internal delegate void HeaderSink(ReadOnlySpan<byte> name, ReadOnlySpan<byte> value);

    // out parameters rather than a tuple: a tuple cannot hold ref structs, and these have to stay
    // spans so a table hit costs no copy.
    private void Lookup(int index, out ReadOnlySpan<byte> name, out ReadOnlySpan<byte> value)
    {
        if (index <= 0)
        {
            throw new HpackException("HPACK index 0 is not a table entry");
        }

        if (index <= HpackStatic.Count)
        {
            (byte[] staticName, byte[] staticValue) = HpackStatic.Entries[index];
            name = staticName;
            value = staticValue;
            return;
        }

        _table.Get(index - HpackStatic.Count - 1, out name, out value);
    }

    /// <summary>
    /// RFC 7541 section 5.1. The low <paramref name="prefixBits"/> of the first byte hold the value
    /// unless they are all ones, in which case the remainder follows as a varint of 7-bit groups.
    /// </summary>
    private static uint ReadInteger(ReadOnlySpan<byte> block, ref int position, int prefixBits)
    {
        if (position >= block.Length)
        {
            throw new HpackException("truncated HPACK integer");
        }

        int mask = (1 << prefixBits) - 1;
        uint value = (uint)(block[position++] & mask);
        if (value < mask)
        {
            return value;
        }

        int shift = 0;
        while (true)
        {
            if (position >= block.Length)
            {
                throw new HpackException("truncated HPACK integer continuation");
            }
            if (shift > 21)
            {
                // Past this a well-formed length cannot fit anything we would accept, and a hostile
                // peer would otherwise spin here shifting forever.
                throw new HpackException("HPACK integer too large");
            }

            byte next = block[position++];
            value += (uint)(next & 0x7F) << shift;
            if ((next & 0x80) == 0)
            {
                return value;
            }
            shift += 7;
        }
    }

    // A literal is [H|len][octets], Huffman-coded when the top bit of the length byte is set.
    // 'scoped' on the cursors: the returned span points into `scratch`, never into a cursor, and
    // without saying so ref-safety assumes the worst and refuses the return.
    private static ReadOnlySpan<byte> ReadLiteral(ReadOnlySpan<byte> block, scoped ref int position,
        Span<byte> scratch, scoped ref int scratchUsed)
    {
        if (position >= block.Length)
        {
            throw new HpackException("truncated HPACK literal");
        }

        bool huffman = (block[position] & 0x80) != 0;
        int length = (int)ReadInteger(block, ref position, 7);

        if (length < 0 || position + length > block.Length)
        {
            throw new HpackException("HPACK literal runs past the block");
        }

        ReadOnlySpan<byte> raw = block.Slice(position, length);
        position += length;

        if (!huffman)
        {
            // Copied into scratch anyway: the caller's span must stay valid after the block buffer
            // is recycled, and the tables need owned bytes.
            if (scratchUsed + length > scratch.Length)
            {
                throw new HpackException("HPACK header block exceeds the decode buffer");
            }
            raw.CopyTo(scratch[scratchUsed..]);
            ReadOnlySpan<byte> plain = scratch.Slice(scratchUsed, length);
            scratchUsed += length;
            return plain;
        }

        int decoded = Huffman.Decode(raw, scratch[scratchUsed..]);
        if (decoded < 0)
        {
            throw new HpackException("invalid HPACK Huffman sequence");
        }
        ReadOnlySpan<byte> result = scratch.Slice(scratchUsed, decoded);
        scratchUsed += decoded;
        return result;
    }

    /// <summary>
    /// The decoder's half of the shared dynamic table: newest first, evicting from the tail until
    /// the RFC's size accounting fits.
    /// </summary>
    private sealed class DynamicTable(int maxSize)
    {
        private readonly List<(byte[] Name, byte[] Value)> _entries = [];
        private int _size;
        private int _maxSize = maxSize;

        internal void Add(ReadOnlySpan<byte> name, ReadOnlySpan<byte> value)
        {
            int entrySize = name.Length + value.Length + 32;

            // An entry larger than the whole table is legal: it empties the table and is not added.
            if (entrySize > _maxSize)
            {
                _entries.Clear();
                _size = 0;
                return;
            }

            _entries.Insert(0, (name.ToArray(), value.ToArray()));
            _size += entrySize;
            Evict();
        }

        internal void Get(int index, out ReadOnlySpan<byte> name, out ReadOnlySpan<byte> value)
        {
            if ((uint)index >= (uint)_entries.Count)
            {
                throw new HpackException($"HPACK dynamic index {index} out of range ({_entries.Count} entries)");
            }
            (byte[] entryName, byte[] entryValue) = _entries[index];
            name = entryName;
            value = entryValue;
        }

        internal void Resize(int newMaxSize)
        {
            _maxSize = newMaxSize;
            Evict();
        }

        private void Evict()
        {
            while (_size > _maxSize && _entries.Count > 0)
            {
                (byte[] name, byte[] value) = _entries[^1];
                _size -= name.Length + value.Length + 32;
                _entries.RemoveAt(_entries.Count - 1);
            }
        }
    }
}
