using ioxide.http3;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  Fuzz the managed parsers that read bytes chosen by whoever connected.
//
//  This is where ioxide's parsing actually lives. The QUIC transport is vendored ngtcp2 and the
//  TLS is BoringSSL or picotls, so the hand-written attack surface is small and almost all of it is
//  C#: QPACK field sections, HTTP/3 varints, frame headers. Those decode straight from the wire
//  into a request a handler then trusts.
//
//      dotnet run -c Release --project fuzz/Ioxide.Fuzz            # every target, 2m each
//      dotnet run -c Release --project fuzz/Ioxide.Fuzz qpack 60   # one target, 60s
//      dotnet run -c Release --project fuzz/Ioxide.Fuzz qpack 60 12345    # ...from a seed
//
//  What separates this from Ioxide.Tests.Chaos: Chaos holds hostile inputs someone thought of, it
//  is deterministic and it gates a merge. This generates inputs nobody thought of, runs for as
//  long as you give it, and a green run proves only that this run was green. A crash here is not a
//  finding until it is a named, minimal test in tests/ - the seed printed below reproduces it.
//
//  The oracle is not "did not throw". These are Try* parsers, so their contract is to RETURN FALSE
//  on bad input; an exception escaping one is the bug. Each target also checks the invariant that
//  makes a silent parser bug visible - chiefly that `consumed` never exceeds what was handed in,
//  which is what a length that wrapped or a loop that did not advance looks like from outside.
// ─────────────────────────────────────────────────────────────────────────────────────────────

string target = args.Length > 0 ? args[0] : "all";
int seconds = args.Length > 1 && int.TryParse(args[1], out int s) ? s : 120;
ulong seed = args.Length > 2 && ulong.TryParse(args[2], out ulong x) ? x : 0x9E3779B97F4A7C15ul;

var targets = new (string Name, Action<Rng, int> Run)[]
{
    ("varint", FuzzVarint),
    ("qpack-int", FuzzQpackInt),
    ("qpack", FuzzQpackFieldSection),
};

int ran = 0;
foreach ((string name, Action<Rng, int> run) in targets)
{
    if (target != "all" && target != name)
    {
        continue;
    }

    ran++;
    var rng = new Rng(seed);
    Console.WriteLine($"== {name}: {seconds}s from seed {seed}");

    long iterations = 0;
    long deadline = Environment.TickCount64 + seconds * 1000L;
    while (Environment.TickCount64 < deadline)
    {
        for (int i = 0; i < 1000; i++)
        {
            run(rng, i);
        }
        iterations += 1000;
    }

    Console.WriteLine($"   {iterations:N0} iterations, no escape");
}

if (ran == 0)
{
    Console.Error.WriteLine($"no such target '{target}'. Known: all, {string.Join(", ", targets.Select(t => t.Name))}");
    return 1;
}

return 0;

// ── the targets ──────────────────────────────────────────────────────────────────────────────

// One varint off the wire. Every HTTP/3 frame header and stream type is built out of these, so a
// parser that reports consuming more than it was given corrupts every frame boundary after it.
static void FuzzVarint(Rng rng, int _)
{
    Span<byte> buf = stackalloc byte[16];
    int len = rng.Next(0, buf.Length + 1);
    rng.Fill(buf[..len]);

    if (Varint.TryRead(buf[..len], out long value, out int consumed))
    {
        if (consumed <= 0 || consumed > len) Fail($"varint consumed {consumed} of {len}");
        if (value < 0) Fail($"varint decoded a negative value: {value}");
    }
    else
    {
        if (consumed != 0) Fail($"a failed varint read reported consuming {consumed}");
    }
}

// QPACK's prefixed integer, the encoding every field line starts with. The continuation bytes are
// unbounded on the wire, so this is the natural place for a length to run away.
static void FuzzQpackInt(Rng rng, int _)
{
    Span<byte> buf = stackalloc byte[24];
    int len = rng.Next(0, buf.Length + 1);
    rng.Fill(buf[..len]);
    int prefixBits = rng.Next(1, 9);

    if (Qpack.TryReadInt(buf[..len], prefixBits, out long value, out int consumed))
    {
        if (consumed <= 0 || consumed > len) Fail($"qpack int consumed {consumed} of {len}");
        if (value < 0) Fail($"qpack int decoded a negative value: {value}");
    }
}

// A whole field section: prefixed integers, static-table indices and Huffman-coded strings,
// decoded into the request object a handler is then handed. This is the deepest managed parser on
// the inbound path and the one with the most structure to get wrong.
//
// Random bytes alone would be rejected at the first field line almost always, so half the work is
// a valid encoding with a few bytes flipped - which is what reaches the string and Huffman paths.
static void FuzzQpackFieldSection(Rng rng, int iteration)
{
    Span<byte> buf = stackalloc byte[256];
    int len;

    if ((iteration & 1) == 0)
    {
        len = rng.Next(0, buf.Length + 1);
        rng.Fill(buf[..len]);
    }
    else
    {
        len = WellFormed(rng, buf);
        int edits = rng.Next(1, 5);
        for (int e = 0; e < edits && len > 0; e++)
        {
            buf[rng.Next(0, len)] = (byte)rng.Next(0, 256);
        }
        if (rng.Next(0, 3) == 0)
        {
            len = rng.Next(0, len + 1);   // truncate: a length that outruns the buffer
        }
    }

    var request = new Http3Request();

    // The contract is false, not an exception. Anything that escapes here is reachable from the
    // wire by any client that can open a request stream.
    Qpack.TryDecodeFieldSection(buf[..len], request);
}

// A minimal field section the decoder accepts: the two-integer prefix, then a handful of indexed
// static-table entries. Not a full encoder - just enough structure to get past the front door.
static int WellFormed(Rng rng, Span<byte> buf)
{
    int o = 0;
    buf[o++] = 0x00;   // Required Insert Count = 0
    buf[o++] = 0x00;   // Delta Base = 0

    int fields = rng.Next(1, 8);
    for (int i = 0; i < fields && o < buf.Length - 1; i++)
    {
        // 1Txxxxxx: indexed field line, T=1 static table, 6-bit index into the static table.
        buf[o++] = (byte)(0xC0 | (byte)rng.Next(0, 62));
    }

    return o;
}

// Called only when something is actually wrong. The message used to be built by the caller on
// every iteration, which meant the fuzzer spent most of its time interpolating strings nobody read
// - millions a second, and enough allocation churn to make the run itself the thing under test.
static void Fail(string what) => throw new InvalidOperationException(what);

// xorshift64*, so a failing run is reproducible from the seed printed at the top of it.
internal sealed class Rng(ulong seed)
{
    private ulong _state = seed == 0 ? 0x9E3779B97F4A7C15ul : seed;

    public ulong Next()
    {
        _state ^= _state >> 12;
        _state ^= _state << 25;
        _state ^= _state >> 27;
        return _state * 0x2545F4914F6CDD1Dul;
    }

    public int Next(int lo, int hi) => lo + (int)(Next() % (ulong)(hi - lo));

    public void Fill(Span<byte> span)
    {
        for (int i = 0; i < span.Length; i++)
        {
            span[i] = (byte)Next();
        }
    }
}
