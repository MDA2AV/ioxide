using System.Text;
using ioxide;
using ioxide.redis;

namespace Ioxide.Tests;

/// <summary>
/// The pipelined send buffer, driven through a scripted ring so the order of appends and send
/// completions is exact rather than left to the network.
/// </summary>
internal static class RedisSendBufferTests
{
    private const int SendBufferSize = 512 * 1024;   // RedisConnection's fixed send buffer

    public static void Register(Runner runner)
    {
        // A command is appended while every send is still in flight, so the buffer never empties out on its own.
        runner.Test("redis: a connection whose sends never fully drain still reuses its send buffer", () =>
        {
            var ring = new ScriptedRing();
            RedisConnection connection = RedisConnection.ConnectAsync(ring, new RedisOptions()).GetAwaiter().GetResult();

            try
            {
                byte[] ping = Encoding.ASCII.GetBytes("*1\r\n$4\r\nPING\r\n");
                ValueTask<RespValue> previous = connection.ExecuteAsync("PING");
                int commands = 1;

                while (ring.Sent.Length < 4L * SendBufferSize)
                {
                    ValueTask<RespValue> next = connection.ExecuteAsync("PING");
                    commands++;
                    if (next.IsFaulted)
                    {
                        throw new Exception($"command {commands} was refused with {ring.Sent.Length} bytes sent: {Error(next)}");
                    }

                    ring.CompleteSend();
                    ring.Reply("+PONG\r\n"u8);
                    ExpectPong(previous, commands - 1);
                    previous = next;
                }

                ring.CompleteSend();
                ring.Reply("+PONG\r\n"u8);
                ExpectPong(previous, commands);

                byte[] wire = ring.Sent.ToArray();
                Assert.Equal((long)commands * ping.Length, wire.LongLength);
                for (int at = 0; at < wire.Length; at += ping.Length)
                {
                    Assert.True(wire.AsSpan(at, ping.Length).SequenceEqual(ping), $"the bytes sent at {at} are not the next PING");
                }
            }
            finally
            {
                connection.Dispose();
            }
        });
    }

    private static void ExpectPong(ValueTask<RespValue> command, int number)
    {
        if (!command.IsCompletedSuccessfully || command.Result.AsString() != "PONG")
        {
            throw new Exception($"command {number} was not answered PONG: {Error(command)}");
        }
    }

    private static string Error(ValueTask<RespValue> command)
        => command.IsFaulted ? command.AsTask().Exception!.InnerException!.Message : "still pending";

    /// <summary>
    /// A ring that completes a connect at once and holds every send and recv until the test
    /// completes it. Completions run inline on the test thread, the way a reactor runs them.
    /// </summary>
    private sealed unsafe class ScriptedRing : IRingHost
    {
        private (nint Buffer, int Length, IRingCompletion Completion)? _send;
        private (nint Buffer, int Length, IRingCompletion Completion)? _recv;

        /// <summary>Every byte the connection has sent, in order.</summary>
        public MemoryStream Sent { get; } = new();

        public void SubmitConnect(int fd, nint sockaddr, int sockaddrLen, IRingCompletion completion) => completion.Complete(0);

        public void SubmitSend(int fd, nint buffer, int length, IRingCompletion completion) => _send = (buffer, length, completion);

        public void SubmitRecv(int fd, nint buffer, int length, IRingCompletion completion) => _recv = (buffer, length, completion);

        /// <summary>Completes the send in flight in full; the connection may submit its next one before this returns.</summary>
        public void CompleteSend()
        {
            (nint buffer, int length, IRingCompletion completion) = _send ?? throw new Exception("no send in flight");
            _send = null;
            Sent.Write(new ReadOnlySpan<byte>((void*)buffer, length));
            completion.Complete(length);
        }

        /// <summary>Delivers <paramref name="reply"/> to the recv in flight.</summary>
        public void Reply(ReadOnlySpan<byte> reply)
        {
            (nint buffer, int length, IRingCompletion completion) = _recv ?? throw new Exception("no recv in flight");
            _recv = null;
            reply.CopyTo(new Span<byte>((void*)buffer, length));
            completion.Complete(reply.Length);
        }

        public void SubmitRead(int fd, nint buffer, int length, long offset, IRingCompletion completion) => throw new NotSupportedException();

        public void SubmitWrite(int fd, nint buffer, int length, long offset, IRingCompletion completion) => throw new NotSupportedException();

        // The test owns the clock: a timeout is accepted and never expires.
        public void SubmitTimeout(long nanoseconds, IRingCompletion completion)
        {
        }
    }
}
