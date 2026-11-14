using System.Buffers;

namespace Ioxide.Tests;

/// <summary>
/// The edges of the IBufferWriter contract a streamed response writer has to hold: GetSpan and GetMemory hand out at
/// least the hint or throw, and Advance never runs past what was handed out. Each probe stages <see cref="Staged"/>
/// first and says what the writer did, so a test can assert that, and that the staged bytes still go out after it.
/// </summary>
public static class BufferWriterProbes
{
    /// <summary>What each probe stages before it reaches past the block.</summary>
    public static ReadOnlySpan<byte> Staged => "0123456789abcdef"u8;

    /// <summary>
    /// GetSpan, then GetMemory, with a hint of int.MaxValue beside the staged bytes: no block holds that much, so
    /// "refused" for each, or how much was handed out instead.
    /// </summary>
    public static string Overreach(IBufferWriter<byte> writer)
    {
        writer.Write(Staged);
        string span = Asked(() => writer.GetSpan(int.MaxValue).Length);
        string memory = Asked(() => writer.GetMemory(int.MaxValue).Length);
        return $"GetSpan {span}, GetMemory {memory}";
    }

    /// <summary>An Advance of int.MaxValue past a span handed out beside the staged bytes: "refused", or "advanced".</summary>
    public static string Overrun(IBufferWriter<byte> writer)
    {
        writer.Write(Staged);
        writer.GetSpan(1);
        try
        {
            writer.Advance(int.MaxValue);
            return "advanced";
        }
        catch (InvalidOperationException)
        {
            return "refused";
        }
    }

    private static string Asked(Func<int> ask)
    {
        try
        {
            return $"handed out {ask()} bytes";
        }
        catch (OutOfMemoryException)
        {
            return "refused";
        }
    }
}
