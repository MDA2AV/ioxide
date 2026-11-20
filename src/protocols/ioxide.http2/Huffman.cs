namespace ioxide.http2;

/// <summary>
/// HPACK Huffman decoding (RFC 7541 Appendix B). QPACK reuses the same table, so this file is shared verbatim with ioxide.http3. The
/// symbol table below is extracted from nghttp3's generated huffman_sym_table (codes left-aligned
/// in 32 bits), so it is byte-identical to what the reference implementation encodes with. Decode
/// walks a binary tree built once at startup - not the fastest possible scheme, but branch-simple
/// and obviously correct; swap in a table-driven FSM if it ever shows in a profile.
/// </summary>
internal static class Huffman
{
    // (bits, code) per symbol 0..256; symbol 256 is EOS (never emitted, used only for padding).
    private static readonly (byte Bits, uint Code)[] Symbols =
    {
        (13, 0xFFC00000u), (23, 0xFFFFB000u), (28, 0xFFFFFE20u), (28, 0xFFFFFE30u),
        (28, 0xFFFFFE40u), (28, 0xFFFFFE50u), (28, 0xFFFFFE60u), (28, 0xFFFFFE70u),
        (28, 0xFFFFFE80u), (24, 0xFFFFEA00u), (30, 0xFFFFFFF0u), (28, 0xFFFFFE90u),
        (28, 0xFFFFFEA0u), (30, 0xFFFFFFF4u), (28, 0xFFFFFEB0u), (28, 0xFFFFFEC0u),
        (28, 0xFFFFFED0u), (28, 0xFFFFFEE0u), (28, 0xFFFFFEF0u), (28, 0xFFFFFF00u),
        (28, 0xFFFFFF10u), (28, 0xFFFFFF20u), (30, 0xFFFFFFF8u), (28, 0xFFFFFF30u),
        (28, 0xFFFFFF40u), (28, 0xFFFFFF50u), (28, 0xFFFFFF60u), (28, 0xFFFFFF70u),
        (28, 0xFFFFFF80u), (28, 0xFFFFFF90u), (28, 0xFFFFFFA0u), (28, 0xFFFFFFB0u),
        (6, 0x50000000u), (10, 0xFE000000u), (10, 0xFE400000u), (12, 0xFFA00000u),
        (13, 0xFFC80000u), (6, 0x54000000u), (8, 0xF8000000u), (11, 0xFF400000u),
        (10, 0xFE800000u), (10, 0xFEC00000u), (8, 0xF9000000u), (11, 0xFF600000u),
        (8, 0xFA000000u), (6, 0x58000000u), (6, 0x5C000000u), (6, 0x60000000u),
        (5, 0x0u), (5, 0x8000000u), (5, 0x10000000u), (6, 0x64000000u),
        (6, 0x68000000u), (6, 0x6C000000u), (6, 0x70000000u), (6, 0x74000000u),
        (6, 0x78000000u), (6, 0x7C000000u), (7, 0xB8000000u), (8, 0xFB000000u),
        (15, 0xFFF80000u), (6, 0x80000000u), (12, 0xFFB00000u), (10, 0xFF000000u),
        (13, 0xFFD00000u), (6, 0x84000000u), (7, 0xBA000000u), (7, 0xBC000000u),
        (7, 0xBE000000u), (7, 0xC0000000u), (7, 0xC2000000u), (7, 0xC4000000u),
        (7, 0xC6000000u), (7, 0xC8000000u), (7, 0xCA000000u), (7, 0xCC000000u),
        (7, 0xCE000000u), (7, 0xD0000000u), (7, 0xD2000000u), (7, 0xD4000000u),
        (7, 0xD6000000u), (7, 0xD8000000u), (7, 0xDA000000u), (7, 0xDC000000u),
        (7, 0xDE000000u), (7, 0xE0000000u), (7, 0xE2000000u), (7, 0xE4000000u),
        (8, 0xFC000000u), (7, 0xE6000000u), (8, 0xFD000000u), (13, 0xFFD80000u),
        (19, 0xFFFE0000u), (13, 0xFFE00000u), (14, 0xFFF00000u), (6, 0x88000000u),
        (15, 0xFFFA0000u), (5, 0x18000000u), (6, 0x8C000000u), (5, 0x20000000u),
        (6, 0x90000000u), (5, 0x28000000u), (6, 0x94000000u), (6, 0x98000000u),
        (6, 0x9C000000u), (5, 0x30000000u), (7, 0xE8000000u), (7, 0xEA000000u),
        (6, 0xA0000000u), (6, 0xA4000000u), (6, 0xA8000000u), (5, 0x38000000u),
        (6, 0xAC000000u), (7, 0xEC000000u), (6, 0xB0000000u), (5, 0x40000000u),
        (5, 0x48000000u), (6, 0xB4000000u), (7, 0xEE000000u), (7, 0xF0000000u),
        (7, 0xF2000000u), (7, 0xF4000000u), (7, 0xF6000000u), (15, 0xFFFC0000u),
        (11, 0xFF800000u), (14, 0xFFF40000u), (13, 0xFFE80000u), (28, 0xFFFFFFC0u),
        (20, 0xFFFE6000u), (22, 0xFFFF4800u), (20, 0xFFFE7000u), (20, 0xFFFE8000u),
        (22, 0xFFFF4C00u), (22, 0xFFFF5000u), (22, 0xFFFF5400u), (23, 0xFFFFB200u),
        (22, 0xFFFF5800u), (23, 0xFFFFB400u), (23, 0xFFFFB600u), (23, 0xFFFFB800u),
        (23, 0xFFFFBA00u), (23, 0xFFFFBC00u), (24, 0xFFFFEB00u), (23, 0xFFFFBE00u),
        (24, 0xFFFFEC00u), (24, 0xFFFFED00u), (22, 0xFFFF5C00u), (23, 0xFFFFC000u),
        (24, 0xFFFFEE00u), (23, 0xFFFFC200u), (23, 0xFFFFC400u), (23, 0xFFFFC600u),
        (23, 0xFFFFC800u), (21, 0xFFFEE000u), (22, 0xFFFF6000u), (23, 0xFFFFCA00u),
        (22, 0xFFFF6400u), (23, 0xFFFFCC00u), (23, 0xFFFFCE00u), (24, 0xFFFFEF00u),
        (22, 0xFFFF6800u), (21, 0xFFFEE800u), (20, 0xFFFE9000u), (22, 0xFFFF6C00u),
        (22, 0xFFFF7000u), (23, 0xFFFFD000u), (23, 0xFFFFD200u), (21, 0xFFFEF000u),
        (23, 0xFFFFD400u), (22, 0xFFFF7400u), (22, 0xFFFF7800u), (24, 0xFFFFF000u),
        (21, 0xFFFEF800u), (22, 0xFFFF7C00u), (23, 0xFFFFD600u), (23, 0xFFFFD800u),
        (21, 0xFFFF0000u), (21, 0xFFFF0800u), (22, 0xFFFF8000u), (21, 0xFFFF1000u),
        (23, 0xFFFFDA00u), (22, 0xFFFF8400u), (23, 0xFFFFDC00u), (23, 0xFFFFDE00u),
        (20, 0xFFFEA000u), (22, 0xFFFF8800u), (22, 0xFFFF8C00u), (22, 0xFFFF9000u),
        (23, 0xFFFFE000u), (22, 0xFFFF9400u), (22, 0xFFFF9800u), (23, 0xFFFFE200u),
        (26, 0xFFFFF800u), (26, 0xFFFFF840u), (20, 0xFFFEB000u), (19, 0xFFFE2000u),
        (22, 0xFFFF9C00u), (23, 0xFFFFE400u), (22, 0xFFFFA000u), (25, 0xFFFFF600u),
        (26, 0xFFFFF880u), (26, 0xFFFFF8C0u), (26, 0xFFFFF900u), (27, 0xFFFFFBC0u),
        (27, 0xFFFFFBE0u), (26, 0xFFFFF940u), (24, 0xFFFFF100u), (25, 0xFFFFF680u),
        (19, 0xFFFE4000u), (21, 0xFFFF1800u), (26, 0xFFFFF980u), (27, 0xFFFFFC00u),
        (27, 0xFFFFFC20u), (26, 0xFFFFF9C0u), (27, 0xFFFFFC40u), (24, 0xFFFFF200u),
        (21, 0xFFFF2000u), (21, 0xFFFF2800u), (26, 0xFFFFFA00u), (26, 0xFFFFFA40u),
        (28, 0xFFFFFFD0u), (27, 0xFFFFFC60u), (27, 0xFFFFFC80u), (27, 0xFFFFFCA0u),
        (20, 0xFFFEC000u), (24, 0xFFFFF300u), (20, 0xFFFED000u), (21, 0xFFFF3000u),
        (22, 0xFFFFA400u), (21, 0xFFFF3800u), (21, 0xFFFF4000u), (23, 0xFFFFE600u),
        (22, 0xFFFFA800u), (22, 0xFFFFAC00u), (25, 0xFFFFF700u), (25, 0xFFFFF780u),
        (24, 0xFFFFF400u), (24, 0xFFFFF500u), (26, 0xFFFFFA80u), (23, 0xFFFFE800u),
        (26, 0xFFFFFAC0u), (27, 0xFFFFFCC0u), (26, 0xFFFFFB00u), (26, 0xFFFFFB40u),
        (27, 0xFFFFFCE0u), (27, 0xFFFFFD00u), (27, 0xFFFFFD20u), (27, 0xFFFFFD40u),
        (27, 0xFFFFFD60u), (28, 0xFFFFFFE0u), (27, 0xFFFFFD80u), (27, 0xFFFFFDA0u),
        (27, 0xFFFFFDC0u), (27, 0xFFFFFDE0u), (27, 0xFFFFFE00u), (26, 0xFFFFFB80u),
        (30, 0xFFFFFFFCu),
    };

    // Binary decode tree over int pairs: node*2 slots, [node*2 + bit] = child index, or
    // -(symbol + 1) for a leaf. Root = 0.
    private static readonly int[] Tree = BuildTree();

    private static int[] BuildTree()
    {
        var tree = new List<int[]>() { new[] { 0, 0 } };
        for (int sym = 0; sym < 256; sym++)   // EOS excluded: hitting it is a decode error
        {
            (byte bits, uint code) = Symbols[sym];
            int node = 0;
            for (int i = 0; i < bits; i++)
            {
                int bit = (int)((code >> (31 - i)) & 1);
                if (i == bits - 1)
                {
                    tree[node][bit] = -(sym + 1);
                    break;
                }
                if (tree[node][bit] == 0)
                {
                    tree.Add(new[] { 0, 0 });
                    tree[node][bit] = tree.Count - 1;
                }
                node = tree[node][bit];
            }
        }

        var flat = new int[tree.Count * 2];
        for (int i = 0; i < tree.Count; i++)
        {
            flat[i * 2] = tree[i][0];
            flat[i * 2 + 1] = tree[i][1];
        }
        return flat;
    }

    /// <summary>
    /// Decode a Huffman-coded field into <paramref name="output"/>; returns bytes written or -1 on
    /// a malformed coding (invalid padding, EOS, or overflow of the output buffer).
    /// </summary>
    public static int Decode(ReadOnlySpan<byte> input, Span<byte> output)
    {
        int node = 0;
        int written = 0;
        int depth = 0;   // bits consumed since the last emitted symbol (padding validity check)
        bool ones = true;   // and whether every one of them was a 1, as EOS's prefix is

        foreach (byte b in input)
        {
            for (int i = 7; i >= 0; i--)
            {
                int bit = (b >> i) & 1;
                int next = Tree[node * 2 + bit];
                depth++;
                ones &= bit == 1;
                if (next < 0)
                {
                    if (written >= output.Length)
                    {
                        return -1;
                    }
                    output[written++] = (byte)(-next - 1);
                    node = 0;
                    depth = 0;
                    ones = true;
                }
                else
                {
                    if (next == 0 && node != 0)
                    {
                        return -1;   // fell off the tree - invalid coding
                    }
                    node = next;
                }
            }
        }

        // Trailing bits must be a prefix of EOS (all ones) and shorter than a byte (RFC 7541 5.2).
        return depth > 7 || !ones ? -1 : written;
    }

    /// <summary>Worst-case decoded size (shortest code is 5 bits: 8/5 expansion).</summary>
    public static int MaxDecodedLength(int encodedLength) => encodedLength * 8 / 5 + 1;
}
