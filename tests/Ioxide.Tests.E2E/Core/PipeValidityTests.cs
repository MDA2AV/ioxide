using System.IO.Pipelines;
using System.Net.Sockets;
using ioxide;

namespace Ioxide.Tests;

/// <summary>
/// <see cref="TcpConnectionPipeReader.IsValid"/> and <see cref="TcpConnectionPipeWriter.IsValid"/>. A TcpConnection is
/// pooled, so code that keeps an adapter past DecRef calls them to tell whether the connection is still its client's.
/// </summary>
internal static class PipeValidityTests
{
    public static void Register(Runner runner)
    {
        runner.Test("tcp: a pipe reader and writer are valid in the connection's life they were made in, and a kept one is not in the next", () =>
        {
            var outcome = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            TcpConnection? firstObject = null;
            TcpConnectionPipeReader? keptReader = null;
            TcpConnectionPipeWriter? keptWriter = null;

            int port = TestServer.Start(async (_, conn) =>
            {
                var reader = new TcpConnectionPipeReader(conn);
                var writer = new TcpConnectionPipeWriter(conn);
                try
                {
                    ReadResult result = await reader.ReadAsync();
                    if (result.Buffer.IsEmpty && result.IsCompleted)
                    {
                        return;   // the harness probe
                    }
                    reader.AdvanceTo(result.Buffer.End);

                    if (!reader.IsValid() || !writer.IsValid())
                    {
                        outcome.TrySetResult("a new reader or writer is not valid on its own connection");
                    }
                    else if (firstObject is null)
                    {
                        (firstObject, keptReader, keptWriter) = (conn, reader, writer);
                    }
                    else if (!ReferenceEquals(firstObject, conn))
                    {
                        outcome.TrySetResult("the pool did not hand on the same object, so this proves nothing");
                    }
                    else
                    {
                        outcome.TrySetResult(!keptReader!.IsValid() && !keptWriter!.IsValid()
                            ? "ok"
                            : "a kept reader or writer is still valid in the connection's next life");
                    }
                }
                finally
                {
                    reader.Complete();
                    writer.Complete();
                    conn.DecRef();
                }
            });

            using (var first = new TcpClient { ReceiveTimeout = 3_000 })
            {
                first.Connect("127.0.0.1", port);
                first.GetStream().Write("A"u8);
                Assert.Equal(0, first.GetStream().Read(new byte[16]));   // the handler let go, so the server closed
            }
            Thread.Sleep(100);   // its connection goes back to the pool

            using var second = new TcpClient();
            second.Connect("127.0.0.1", port);
            second.GetStream().Write("B"u8);

            Assert.True(outcome.Task.Wait(5_000), "the second handler never reported");
            Assert.Equal("ok", outcome.Task.Result);
        });
    }
}
