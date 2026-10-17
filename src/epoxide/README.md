# epoxide

ioxide's shared-nothing, thread-per-core runtime on **epoll** instead of io_uring.

One reactor per core: its own thread, its own epoll set, its own `SO_REUSEPORT` listener and
connections. Handlers start on the reactor and resume inline there, exactly as in ioxide - and the
API is ioxide's: `Reactor`, `TcpConnection`, `TcpConnectionPipeReader`/`Writer`, `TcpConnectionStream`,
`TlsService`.

The difference is who may touch a connection. An io_uring ring has a single issuer, so ioxide hands
every operation from another thread to the reactor. epoll has no such rule - a read is a `recv`, a
flush is a `send` - so in epoxide **any thread** reads and writes a connection directly:

```csharp
reactor.TcpHandle = async (r, conn) =>
{
    var reader = new TcpConnectionPipeReader(conn);
    var writer = new TcpConnectionPipeWriter(conn);
    try
    {
        // Off to the thread pool - and the connection keeps working from there.
        await Task.Delay(1).ConfigureAwait(false);

        ReadResult result = await reader.ReadAsync();   // recv, on this thread
        reader.AdvanceTo(result.Buffer.End);
        writer.Write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"u8);
        await writer.FlushAsync();                      // send, on this thread
    }
    finally
    {
        reader.Complete();
        conn.DecRef();
    }
};
```

Only a read with nothing to read, or a flush the socket cannot take yet, waits on the reactor: it
parks, and the reactor finishes the recv or send at the next readiness edge and resumes the caller -
inline when the caller is on that reactor, on the caller's own context or the thread pool when not.
Outbound connections (`Reactor.ConnectAsync`) work the same way from any thread.

TLS terminates on the same bundled BoringSSL ioxide ships (`libioxide_boringssl.so`), with the same
optional kernel TLS offload.

Linux only. MIT.
