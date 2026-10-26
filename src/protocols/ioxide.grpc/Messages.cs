using System.Buffers;
using System.Buffers.Binary;
using Grpc.Core;

namespace ioxide.grpc;

/// <summary>
/// Serializes one message straight into the response body: the 5-byte prefix, then the payload. A
/// marshaller that states its length first (Google.Protobuf's does) writes into the body itself,
/// with no copy; one that does not is buffered once to learn it.
/// </summary>
/// <remarks>One per thread, reused: a marshaller runs synchronously and never serializes another message meanwhile.</remarks>
internal sealed class MessageWriter : SerializationContext, IBufferWriter<byte>
{
    [ThreadStatic] private static MessageWriter? t_cached;

    private IBufferWriter<byte> _body = null!;
    private int _declared;
    private int _written;
    private bool _direct;
    private bool _done;
    private ArrayBufferWriter<byte>? _spill;

    /// <summary>True once any byte of the message has reached the body, so a failure past it tears the message.</summary>
    internal bool Started { get; private set; }

    internal static MessageWriter Rent(IBufferWriter<byte> body)
    {
        MessageWriter writer = t_cached ?? new MessageWriter();
        t_cached = null;
        writer._body = body;
        writer._declared = -1;
        writer._written = 0;
        writer._direct = false;
        writer._done = false;
        writer.Started = false;
        return writer;
    }

    internal void Return()
    {
        _body = null!;

        // Kept for the next message on this thread, unless one large message would pin its buffer here for good.
        if (_spill is { Capacity: > 64 * 1024 })
        {
            _spill = null;
        }
        _spill?.ResetWrittenCount();
        t_cached = this;
    }

    public override void SetPayloadLength(int payloadLength) => _declared = payloadLength;

    public override IBufferWriter<byte> GetBufferWriter()
    {
        if (_direct)
        {
            return this;
        }

        if (_declared >= 0 && _spill is not { WrittenCount: > 0 })
        {
            WritePrefix(_declared);
            _direct = true;
            return this;
        }

        return _spill ??= new ArrayBufferWriter<byte>();
    }

    public override void Complete(byte[] payload)
    {
        if (_declared >= 0 && _declared != payload.Length)
        {
            throw new InvalidOperationException($"The serializer declared {_declared} bytes and produced {payload.Length}.");
        }
        WritePrefix(payload.Length);
        Copy(payload);
        _done = true;
    }

    public override void Complete()
    {
        if (_direct)
        {
            if (_written != _declared)
            {
                throw new InvalidOperationException($"The serializer declared {_declared} bytes and wrote {_written}.");
            }
        }
        else
        {
            ReadOnlySpan<byte> payload = _spill is null ? default : _spill.WrittenSpan;
            WritePrefix(payload.Length);
            Copy(payload);
        }
        _done = true;
    }

    /// <summary>The marshaller returned; a context it never completed is a serializer that wrote nothing usable.</summary>
    internal void Finish()
    {
        if (!_done)
        {
            throw new InvalidOperationException("The serializer did not complete the message.");
        }
    }

    // IBufferWriter for the direct path: the body's own memory, counted so the prefix can be checked.
    public Memory<byte> GetMemory(int sizeHint = 0) => _body.GetMemory(sizeHint);

    public Span<byte> GetSpan(int sizeHint = 0) => _body.GetSpan(sizeHint);

    public void Advance(int count)
    {
        _body.Advance(count);
        _written += count;
    }

    private void WritePrefix(int length)
    {
        Span<byte> prefix = _body.GetSpan(GrpcProtocol.PrefixLength);
        prefix[0] = 0;   // never compressed
        BinaryPrimitives.WriteUInt32BigEndian(prefix[1..], (uint)length);
        _body.Advance(GrpcProtocol.PrefixLength);
        Started = true;
    }

    private void Copy(ReadOnlySpan<byte> payload)
    {
        while (!payload.IsEmpty)
        {
            Span<byte> destination = _body.GetSpan(Math.Min(payload.Length, 16 * 1024));
            int take = Math.Min(destination.Length, payload.Length);
            payload[..take].CopyTo(destination);
            _body.Advance(take);
            payload = payload[take..];
        }
    }
}

/// <summary>Hands one received payload to a marshaller, as the contiguous memory it already sits in.</summary>
/// <remarks>One per thread, reused, for the same reason as <see cref="MessageWriter"/>.</remarks>
internal sealed class MessageReader : DeserializationContext
{
    [ThreadStatic] private static MessageReader? t_cached;

    private ReadOnlyMemory<byte> _payload;

    internal static T Deserialize<T>(Marshaller<T> marshaller, ReadOnlyMemory<byte> payload)
    {
        MessageReader reader = t_cached ?? new MessageReader();
        t_cached = null;
        reader._payload = payload;
        try
        {
            return marshaller.ContextualDeserializer(reader);
        }
        finally
        {
            reader._payload = default;
            t_cached = reader;
        }
    }

    public override int PayloadLength => _payload.Length;

    public override byte[] PayloadAsNewBuffer() => _payload.ToArray();

    public override ReadOnlySequence<byte> PayloadAsReadOnlySequence() => new(_payload);
}
