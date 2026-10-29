using System.Reflection;
using System.Runtime.InteropServices;
using ioxide.tls;

namespace Ioxide.Tests;

/// <summary>
/// The ALPN select callback against offers no handshake can deliver (#427). BoringSSL validates the
/// ClientHello's list while parsing it, so a truncated or empty entry never reaches the callback; only a
/// direct call reaches its bound. It is called through the pointer BoringSSL is given, so its own fault
/// handling is part of what runs.
/// </summary>
/// <remarks>
/// AlpnNegotiationTests in the Tls suite drives the selection helper by reflection, with truncated
/// entries that never have the length of the protocol the server speaks, so they are declined with or
/// without the bound. Here the cut entry has h2's length, and the byte just past the list completes it.
/// </remarks>
internal static unsafe class AlpnSelectTests
{
    // The server's lists, laid out as BuildAlpnWire lays them out: a length byte, then the name.
    private static readonly byte[] H2 = [2, (byte)'h', (byte)'2'];
    private static readonly byte[] H2ThenHttp11 = [2, (byte)'h', (byte)'2', 8, .. "http/1.1"u8.ToArray()];

    // Nothing selected: the callback left its sentinels untouched.
    private static readonly (int, long, int) Declined = (BoringSsl.SSL_TLSEXT_ERR_NOACK, -1, 0xEE);

    public static void Register(Runner runner)
    {
        runner.Test("tls alpn: control: a well-formed offer negotiates, pointing at the name inside the client's list", () =>
        {
            // h2 second, behind a protocol the server does not speak.
            Assert.Equal((BoringSsl.SSL_TLSEXT_ERR_OK, 5L, 2), Select(H2, [3, (byte)'f', (byte)'o', (byte)'o', 2, (byte)'h', (byte)'2'], 7));
        });

        runner.Test("tls alpn: an offer entry cut off by the end of the list is never matched, and the entries before it still are", () =>
        {
            // h2's length with only its 'h' inside the list: the '2' lies just past the end.
            Assert.Equal(Declined, Select(H2, [2, (byte)'h', (byte)'2'], 2));

            // The same cut entry behind one the server also speaks. The scan for h2 stops at the cut, so
            // the server's next choice is still found ahead of it; a scan that ran into the cut instead
            // would fault the callback, which then declines the whole offer.
            Assert.Equal((BoringSsl.SSL_TLSEXT_ERR_OK, 1L, 8), Select(H2ThenHttp11, [8, .. "http/1.1"u8.ToArray(), 2, (byte)'h', (byte)'2'], 11));
        });

        runner.Test("tls alpn: an empty offer entry is skipped, neither matched nor looped on", () =>
        {
            Assert.Equal(Declined, Select(H2, [0, 0, 0], 3));
            Assert.Equal((BoringSsl.SSL_TLSEXT_ERR_OK, 2L, 2), Select(H2, [0, 2, (byte)'h', (byte)'2'], 4));
            Assert.Equal(Declined, Select(H2, [], 0));
        }, timeoutMs: 10_000);
    }

    /// <summary>
    /// The callback's answer for the first <paramref name="length"/> bytes of <paramref name="offer"/>,
    /// and what it left in *out, as an offset into the offer, and *out_len.
    /// </summary>
    private static (int Answer, long Selected, int Length) Select(byte[] server, byte[] offer, int length)
    {
        var callback = (delegate* unmanaged<nint, nint, nint, nint, uint, nint, int>)Callback().MethodHandle.GetFunctionPointer();

        GCHandle wire = GCHandle.Alloc(server);
        byte* offered = (byte*)NativeMemory.Alloc((nuint)Math.Max(offer.Length, 1));
        try
        {
            offer.CopyTo(new Span<byte>(offered, offer.Length));
            nint selected = -1;
            byte selectedLength = 0xEE;

            int answer = callback(0, (nint)(&selected), (nint)(&selectedLength), (nint)offered, (uint)length, GCHandle.ToIntPtr(wire));
            return (answer, selected == -1 ? -1 : selected - (nint)offered, selectedLength);
        }
        finally
        {
            NativeMemory.Free(offered);
            wire.Free();
        }
    }

    private static MethodInfo Callback()
        => typeof(TlsService).GetMethod("AlpnSelectCallback", BindingFlags.NonPublic | BindingFlags.Static)
           ?? throw new Exception("TlsService.AlpnSelectCallback not found - the callback moved; move this test with it");
}
