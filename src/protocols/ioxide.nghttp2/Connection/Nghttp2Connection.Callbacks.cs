using System.Runtime.InteropServices;

namespace ioxide.nghttp2;

/// <summary>
/// The nghttp2 callback surface. Every one of these runs INSIDE <c>ih2_read</c>, which is the whole
/// reason they only ever record: dispatching a handler here would let it submit a response and
/// re-enter the session while <c>nghttp2_session_mem_recv</c> is still on the stack. Requests are
/// deposited in <c>_readyThisPass</c> and dispatched by the loop once the native call unwinds.
///
/// Nothing here may throw either. These are <c>[UnmanagedCallersOnly]</c>, so an exception would
/// cross native frames and take the process down rather than fail one request. Each body is
/// guarded, and the fault lands on _failed, which the loops act on once the native call unwinds
/// and which still sends GOAWAY on the way out.
/// </summary>
public sealed partial class Nghttp2Connection
{
    private static unsafe Nghttp2Connection From(void* user)
        => (Nghttp2Connection)GCHandle.FromIntPtr((nint)user).Target!;

    /// <summary>
    /// Records a fault and fails the connection. Teardown cannot happen here - the session is on
    /// the stack below.
    /// </summary>
    private static unsafe void Fault(void* user, Exception e)
    {
        try
        {
            Nghttp2Connection connection = From(user);
            connection._callbackFault ??= e;
            connection._failed = true;
            Console.Error.WriteLine($"[ioxide.nghttp2] callback faulted, failing the connection: {e}");
        }
        catch
        {
            // Guarded too: resolving the connection or formatting the message can throw, and that
            // throw would be the process.
        }
    }

    [UnmanagedCallersOnly]
    private static unsafe void CallbackBeginHeaders(void* user, int streamId)
    {
        try
        {
            Nghttp2Connection connection = From(user);

            // A trailer section on a stream we are already assembling arrives here a second time; keep
            // the request we have rather than replacing it and losing everything accumulated.
            if (!connection._pending.ContainsKey(streamId))
            {
                connection._pending[streamId] = new PendingRequest { StreamId = streamId };
            }
        }
        catch (Exception e)
        {
            Fault(user, e);
        }
    }

    [UnmanagedCallersOnly]
    private static unsafe void CallbackHeader(void* user, int streamId, byte* name, nuint nameLength,
        byte* value, nuint valueLength)
    {
        try
        {
            Nghttp2Connection connection = From(user);

            // A dispatched request's trailers are dropped: its arena backs memories a handler holds.
            if (!connection._pending.TryGetValue(streamId, out PendingRequest? pending) || pending.BodyReader is not null)
            {
                return;
            }

            var fieldName = new ReadOnlySpan<byte>(name, (int)nameLength);
            var fieldValue = new ReadOnlySpan<byte>(value, (int)valueLength);

            // Pseudo-headers are the request line, not field lines - lifted out so a handler reading
            // Headers never has to skip them.
            if (fieldName.Length > 0 && fieldName[0] == (byte)':')
            {
                (int Offset, int Length) range = pending.Append(fieldValue);

                if (fieldName.SequenceEqual(":method"u8))         pending.Method = range;
                else if (fieldName.SequenceEqual(":path"u8))      pending.Path = range;
                else if (fieldName.SequenceEqual(":scheme"u8))    pending.Scheme = range;
                else if (fieldName.SequenceEqual(":authority"u8)) pending.Authority = range;
                return;
            }

            (int Offset, int Length) nameRange = pending.Append(fieldName);
            (int Offset, int Length) valueRange = pending.Append(fieldValue);
            pending.AddField(nameRange, valueRange);
        }
        catch (Exception e)
        {
            Fault(user, e);
        }
    }

    [UnmanagedCallersOnly]
    private static unsafe void CallbackEndHeaders(void* user, int streamId)
    {
        try
        {
            // A buffered request is not dispatchable until the stream ends, because a body may still
            // follow. A streamed one is dispatched here, once: trailers end a header block too.
            Nghttp2Connection connection = From(user);
            if (connection._options.StreamRequestBodies &&
                connection._pending.TryGetValue(streamId, out PendingRequest? pending) && pending.BodyReader is null)
            {
                pending.BodyReader = new Nghttp2BodyReader(connection, streamId);
                connection._readyThisPass.Add(pending);
            }
        }
        catch (Exception e)
        {
            Fault(user, e);
        }
    }

    [UnmanagedCallersOnly]
    private static unsafe void CallbackData(void* user, int streamId, byte* data, nuint dataLength)
    {
        try
        {
            Nghttp2Connection connection = From(user);
            if (connection._options.StreamRequestBodies)
            {
                // Each byte handed out here is credited exactly once: by the reader as its handler
                // takes it, or right now when no handler ever will.
                if (!connection._pending.TryGetValue(streamId, out PendingRequest? streamed) ||
                    streamed.BodyReader?.Push(new ReadOnlySpan<byte>(data, (int)dataLength)) != true)
                {
                    connection.CreditBody(streamId, (int)dataLength);
                }
                return;
            }

            if (connection._pending.TryGetValue(streamId, out PendingRequest? pending) && !pending.Overflowed)
            {
                if (pending.BodyLength + (long)dataLength > connection._options.MaxRequestBytes)
                {
                    // Left pending, so a trailer later in this read cannot start a fresh request on the stream.
                    pending.Overflowed = true;
                    connection._readyThisPass.Add(pending);
                    return;
                }
                pending.AppendBody(new ReadOnlySpan<byte>(data, (int)dataLength));
            }
        }
        catch (Exception e)
        {
            Fault(user, e);
        }
    }

    [UnmanagedCallersOnly]
    private static unsafe void CallbackEndStream(void* user, int streamId)
    {
        try
        {
            Nghttp2Connection connection = From(user);

            // An overflowed request is in _readyThisPass already, waiting for its reset, and a
            // streamed one was dispatched at its headers.
            if (connection._pending.Remove(streamId, out PendingRequest? pending))
            {
                if (pending.BodyReader is not null)
                {
                    pending.BodyReader.End();
                }
                else if (!pending.Overflowed)
                {
                    connection._readyThisPass.Add(pending);
                }
            }
        }
        catch (Exception e)
        {
            Fault(user, e);
        }
    }

    [UnmanagedCallersOnly]
    private static unsafe void CallbackStreamError(void* user, int streamId, uint errorCode)
    {
        try
        {
            Nghttp2Connection connection = From(user);

            // The peer gave up on this stream (RST_STREAM, or the connection is going away). Drop what
            // was assembled; there is nobody left to answer. A streamed body's handler may still be
            // running on its arena, so only the body ends here and the handler retires the rest.
            if (connection._pending.Remove(streamId, out PendingRequest? pending))
            {
                if (pending.BodyReader is not null)
                {
                    pending.BodyReader.Abort();
                }
                else
                {
                    pending.Dispose();
                }
            }
            if (connection._writers.TryGetValue(streamId, out Nghttp2ResponseWriter? writer))
            {
                writer.OnPeerReset();   // a response in flight: its handler learns at the next flush
            }
            _ = errorCode;
        }
        catch (Exception e)
        {
            Fault(user, e);
        }
    }
}
