using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using ioxide.httpclient;

namespace Ioxide.Tests;

/// <summary>
/// What the HTTP/1.1 client's two growing buffers do at the sizes an int and an array stop at. A real response
/// would take gigabytes of memory, so these start from the state one reaches, in memory never touched.
/// </summary>
internal static unsafe class HttpClientGrowthTests
{
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_arena")]
    private static extern ref byte[] Arena(HttpClientResponse response);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_arenaUsed")]
    private static extern ref int ArenaUsed(HttpClientResponse response);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_options")]
    private static extern ref HttpClientOptions Options(HttpClientConnection connection);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_receive")]
    private static extern ref nint Receive(HttpClientConnection connection);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_receiveCapacity")]
    private static extern ref int ReceiveCapacity(HttpClientConnection connection);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_received")]
    private static extern ref int Received(HttpClientConnection connection);

    [UnsafeAccessor(UnsafeAccessorKind.Method, Name = "EnsureReceiveSpace")]
    private static extern void EnsureReceiveSpace(HttpClientConnection connection);

    public static void Register(Runner runner)
    {
        runner.Test("httpclient: a response past what one array holds fails as an HttpClientException, renting nothing more", () =>
        {
            using var response = new HttpClientResponse();
            Arena(response) = GC.AllocateUninitializedArray<byte>(Array.MaxLength);
            ArenaUsed(response) = Array.MaxLength - 1;

            long before = GC.GetAllocatedBytesForCurrentThread();
            Assert.Throws<HttpClientException>(() => response.Append(new byte[2]), "too large for one array");

            long allocated = GC.GetAllocatedBytesForCurrentThread() - before;
            Assert.True(allocated < 1024 * 1024, $"allocated {allocated} bytes on the way to failing");
            Assert.Equal(Array.MaxLength - 1, response.ArenaLength);
        });

        runner.Test("httpclient: control: a response that exactly fills one array still grows to it", () =>
        {
            using var response = new HttpClientResponse();
            Arena(response) = GC.AllocateUninitializedArray<byte>(Array.MaxLength - 1);
            ArenaUsed(response) = Array.MaxLength - 1;

            (int offset, int length) = response.Append("x"u8);

            Assert.Equal(Array.MaxLength - 1, offset);
            Assert.Equal(1, length);
            Assert.Equal(Array.MaxLength, Arena(response).Length);
            Assert.Equal((byte)'x', Arena(response)[offset]);
        });

        runner.Test("httpclient: the receive buffer doubling past 1 GiB stops at the limit, which then fails by name", () =>
        {
            var connection = (HttpClientConnection)RuntimeHelpers.GetUninitializedObject(typeof(HttpClientConnection));
            Options(connection) = new HttpClientOptions { MaxResponseBytes = int.MaxValue };
            Receive(connection) = (nint)NativeMemory.Alloc(16);
            ReceiveCapacity(connection) = 1 << 30;
            Received(connection) = 1 << 30;

            try
            {
                EnsureReceiveSpace(connection);
                Assert.Equal(int.MaxValue, ReceiveCapacity(connection));

                Received(connection) = int.MaxValue;
                Assert.Throws<HttpClientException>(() => EnsureReceiveSpace(connection), "MaxResponseBytes");
            }
            finally
            {
                NativeMemory.Free((void*)Receive(connection));
            }
        });

        runner.Test("httpclient: control: a limit of exactly 1 GiB stops the receive buffer there", () =>
        {
            var connection = (HttpClientConnection)RuntimeHelpers.GetUninitializedObject(typeof(HttpClientConnection));
            Options(connection) = new HttpClientOptions { MaxResponseBytes = 1 << 30 };
            Receive(connection) = (nint)NativeMemory.Alloc(16);
            ReceiveCapacity(connection) = 1 << 30;
            Received(connection) = 1 << 30;

            try
            {
                Assert.Throws<HttpClientException>(() => EnsureReceiveSpace(connection), "MaxResponseBytes");
            }
            finally
            {
                NativeMemory.Free((void*)Receive(connection));
            }
        });
    }
}
