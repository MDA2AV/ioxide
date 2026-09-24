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
            if (!connection._pending.TryGetValue(streamId, out PendingRequest? pending))
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
            // Nothing to do: the request is not dispatchable until the stream ends, because a body may
            // still follow. Registered so the shim's callback table is fully populated.
            _ = user;
            _ = streamId;
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
            if (connection._pending.TryGetValue(streamId, out PendingRequest? pending))
            {
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
            if (connection._pending.Remove(streamId, out PendingRequest? pending))
            {
                connection._readyThisPass.Add(pending);
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
            // was assembled; there is nobody left to answer.
            if (connection._pending.Remove(streamId, out PendingRequest? pending))
            {
                pending.Dispose();
            }
            _ = errorCode;
        }
        catch (Exception e)
        {
            Fault(user, e);
        }
    }
}
