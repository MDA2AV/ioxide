using System.Text;
using System.Runtime.InteropServices;
using ioxide;
using ioxide.file;
using ioxide.tls;
using ioxide.utils;

namespace Ioxide.Tests;

/// <summary>Server-side HTTP helpers for the test handlers (local copy so the suite depends only on the modules).</summary>
public static class Wire
{
    public static string ReadPath(TcpConnection conn, RecvSnapshot snapshot)
    {
        string path = "/";

        while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
        {
            if (item.HasBuffer)
            {
                if (path == "/")
                {
                    path = ParsePath(item.AsSpan());
                }

                conn.ReturnBuffer(in item);
            }
        }

        return path;
    }

    /// <summary>
    /// Write a response, encrypting it when the connection has a TLS session that is not using
    /// kTLS. Pass null for a plaintext connection.
    ///
    /// The session has to be threaded through because the correct call depends on it: with kTLS
    /// the kernel produces the records so plaintext goes straight to the connection, and without
    /// it a bare conn.Write puts CLEARTEXT on a socket the peer is reading as TLS.
    /// </summary>
    public static void Write(TcpConnection conn, int status, string body, TlsSession? tls = null)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(
            $"HTTP/1.1 {status} X\r\nContent-Type: text/plain\r\nContent-Length: {body.Length}\r\n\r\n{body}");

        if (tls is null)
        {
            conn.Write(bytes);
        }
        else
        {
            tls.Write(conn, bytes);
        }
    }

    private static string ParsePath(ReadOnlySpan<byte> request)
    {
        int firstSpace = request.IndexOf((byte)' ');
        if (firstSpace < 0)
        {
            return "/";
        }

        ReadOnlySpan<byte> rest = request[(firstSpace + 1)..];
        int secondSpace = rest.IndexOf((byte)' ');
        ReadOnlySpan<byte> target = secondSpace > 0 ? rest[..secondSpace] : rest;
        return Encoding.ASCII.GetString(target);
    }
}

/// <summary>The per-module test handlers, each routing that module's feature surface by path.</summary>
public static class Handlers
{
    // core: echo "ok" - exercises accept, the buffer-ring recv, send, and the keep-alive read loop.
    public static async Task Raw(Reactor r, TcpConnection conn)
    {
        try
        {
            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();
                Wire.ReadPath(conn, snapshot);
                Wire.Write(conn, 200, "ok");
                await conn.FlushAsync();

                if (snapshot.IsClosed)
                {
                    return;
                }

                conn.ResetRead();
            }
        }
        finally
        {
            conn.DecRef();
        }
    }

    // pg: /add/N (int param), /rows (streaming), /bad (server error, caught), else SELECT 42.

    // pg with a query longer than the (short) command timeout - for the timeout test.

    // redis: /incr (RESP integer), /pipe (SET+INCR+GET in one round trip), else SET then GET.

    // file: read the current file off the ring by path and frame a response; 404 on miss.
    public static async Task Files(Reactor r, TcpConnection conn)
    {
        StaticAssets assets = r.GetService<StaticAssets>();
        RingPool<AssetReader> readers = r.GetService<RingPool<AssetReader>>();

        try
        {
            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();
                string path = Wire.ReadPath(conn, snapshot);

                using (StaticAssets.Lease lease = assets.Acquire())
                {
                    if (lease.TryGet(path, out AssetCache.Asset asset))
                    {
                        await SendAssetAsync(conn, readers, asset.Fd, (int)asset.Length);
                    }
                    else
                    {
                        Wire.Write(conn, 404, "missing");
                        await conn.FlushAsync();
                    }
                }

                if (snapshot.IsClosed)
                {
                    return;
                }

                conn.ResetRead();
            }
        }
        finally
        {
            conn.DecRef();
        }
    }

    // Read the whole (test-sized) file off the ring into one buffer, then frame a plain response.
    private static async Task SendAssetAsync(TcpConnection conn, RingPool<AssetReader> readers, int fd, int length)
    {
        AssetReader reader = await readers.RentAsync();
        try
        {
            int n = await reader.ReadAsync(fd, offset: 0);
            if (n < 0)
            {
                Wire.Write(conn, 500, "read-error");
                await conn.FlushAsync();
                return;
            }

            conn.Write(Encoding.ASCII.GetBytes(
                $"HTTP/1.1 200 X\r\nContent-Type: text/plain\r\nContent-Length: {n}\r\n\r\n"));
            WriteNative(conn, reader.Buffer, n);
            await conn.FlushAsync();
        }
        finally
        {
            readers.Return(reader);
        }
    }

    // file (slab path): serve the same lookup, but read the file STRAIGHT INTO the write slab via the
    // core TcpConnection.ReadFileAsync (the cleartext fast path) - no reader buffer, no pool, header +
    // body in one flush. This is the end-to-end coverage for that core API.
    public static async Task FilesSlab(Reactor r, TcpConnection conn)
    {
        StaticAssets assets = r.GetService<StaticAssets>();

        try
        {
            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();
                string path = Wire.ReadPath(conn, snapshot);

                using (StaticAssets.Lease lease = assets.Acquire())
                {
                    if (lease.TryGet(path, out AssetCache.Asset asset))
                    {
                        conn.Write(Encoding.ASCII.GetBytes(
                            $"HTTP/1.1 200 X\r\nContent-Type: text/plain\r\nContent-Length: {asset.Length}\r\n\r\n"));
                        int n = await conn.ReadFileAsync(asset.Fd, (int)asset.Length, fileOffset: 0);
                        conn.AdvanceWrite(n);
                        await conn.FlushAsync();
                    }
                    else
                    {
                        Wire.Write(conn, 404, "missing");
                        await conn.FlushAsync();
                    }
                }

                if (snapshot.IsClosed)
                {
                    return;
                }

                conn.ResetRead();
            }
        }
        finally
        {
            conn.DecRef();
        }
    }

    // Answers with the authenticated identity, or "anonymous". Reading it is the whole point of
    // the feature: a server that can only enforce cannot authorise.
    public static Task TlsIdentity(Reactor reactor, TcpConnection connection)
        => Identity(reactor, connection, static s => s.PeerSubject);

    // The same, reporting the structural CN - the value an application is meant to authorize on.
    public static Task TlsCommonName(Reactor reactor, TcpConnection connection)
        => Identity(reactor, connection, static s => s.PeerCommonName);

    private static async Task Identity(Reactor reactor, TcpConnection connection,
        Func<TlsSession, string?> report)
    {
        TlsSession? session = null;
        try
        {
            session = await reactor.GetService<TlsService>()!.AcceptAsync(connection);

            while (true)
            {
                RecvSnapshot snapshot = await connection.ReadAsync();
                if (snapshot.IsClosed)
                {
                    return;
                }

                string subject = report(session) ?? "anonymous";
                byte[] body = Encoding.ASCII.GetBytes(subject);

                session.Write(connection, Encoding.ASCII.GetBytes(
                    $"HTTP/1.1 200 OK\r\ncontent-length: {body.Length}\r\n\r\n{subject}"));

                await connection.FlushAsync();
                connection.ResetRead();
            }
        }
        finally
        {
            session?.Dispose();
            connection.DecRef();
        }
    }

    /// <summary>Answers with the client's verified identity, so authentication can be seen.</summary>
    public static async Task TlsIdentitySendFirst(Reactor reactor, TcpConnection connection)
    {
        TlsSession? session = null;

        try
        {
            session = await reactor.GetService<TlsService>()!.AcceptAsync(connection);

            // The first request routinely rides in with the handshake's final flight - a TLS 1.3
            // client sends it immediately after Finished, and those bytes are already decrypted and
            // gone from the socket by the time AcceptAsync returns. Answering it BEFORE parking on
            // a read is what the send-first loop means; waiting first hangs, because the bytes
            // being waited for already arrived.
            if (!session.DrainPlaintext().IsEmpty)
            {
                session.Write(connection, IdentityBytes(session));
                await connection.FlushAsync();
            }

            // No ResetRead above: that belongs to a read that was actually issued, and calling it
            // for one that never happened leaves the connection's read state describing a read
            // nobody made.
            while (true)
            {
                RecvSnapshot snapshot = await connection.ReadAsync();

                if (snapshot.IsClosed)
                {
                    return;
                }

                byte[] who = System.Text.Encoding.ASCII.GetBytes(session.PeerSubject ?? "anonymous");
                byte[] head = System.Text.Encoding.ASCII.GetBytes(
                    $"HTTP/1.1 200 OK\r\ncontent-length: {who.Length}\r\n\r\n");

                session.Write(connection, [.. head, .. who]);

                await connection.FlushAsync();
                connection.ResetRead();
            }
        }
        finally
        {
            session?.Dispose();
            connection.DecRef();
        }
    }

    /// <summary>The identity response: who the client proved itself to be.</summary>
    private static byte[] IdentityBytes(TlsSession session)
    {
        byte[] who = System.Text.Encoding.ASCII.GetBytes(session.PeerSubject ?? "anonymous");
        byte[] head = System.Text.Encoding.ASCII.GetBytes(
            $"HTTP/1.1 200 OK\r\ncontent-length: {who.Length}\r\n\r\n");

        return [.. head, .. who];
    }

    /// <summary>
    /// Completes the handshake and answers, so a connection is not torn down before the client has
    /// read the certificate. What it serves does not matter here - the certificate does.
    /// </summary>
    public static async Task TlsSendFirst(Reactor reactor, TcpConnection connection)
    {
        TlsSession? session = null;

        try
        {
            session = await reactor.GetService<TlsService>()!.AcceptAsync(connection);

            // The first request routinely rides in with the handshake's final flight - a TLS 1.3
            // client sends it immediately after Finished, and those bytes are already decrypted and
            // gone from the socket by the time AcceptAsync returns. Answering it BEFORE parking on
            // a read is what the send-first loop means; waiting first hangs, because the bytes
            // being waited for already arrived.
            if (!session.DrainPlaintext().IsEmpty)
            {
                session.Write(connection, SendFirstResponse);
                await connection.FlushAsync();
            }

            // No ResetRead above: that belongs to a read that was actually issued, and calling it
            // for one that never happened leaves the connection's read state describing a read
            // nobody made.
            while (true)
            {
                RecvSnapshot snapshot = await connection.ReadAsync();

                if (snapshot.IsClosed)
                {
                    return;
                }

                session.Write(connection, "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok"u8.ToArray());

                await connection.FlushAsync();
                connection.ResetRead();
            }
        }
        finally
        {
            session?.Dispose();
            connection.DecRef();
        }
    }

    private static readonly byte[] SendFirstResponse = "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok"u8.ToArray();

    public static async Task Tls(Reactor r, TcpConnection conn)
    {
        TlsSession? tls = null;
        var carry = new List<byte>();

        try
        {
            tls = await r.GetService<TlsService>().AcceptAsync(conn);

            while (true)
            {
                RecvSnapshot snapshot = await conn.ReadAsync();

                while (conn.TryGetItem(snapshot, out SpscRecvRing.Item item))
                {
                    if (item.HasBuffer)
                    {
                        AppendPlaintext(tls, item, carry);
                        conn.ReturnBuffer(in item);
                    }
                }

                // Answer per REQUEST, not per decrypt. Those are the same thing only while a
                // client sends each request in one TLS record - split one across records and
                // "some plaintext arrived" fires once per record, so one request draws several
                // responses. TLS reassembly is not the issue: BoringSSL yields nothing until a
                // record is whole. Framing above it is ours, exactly as in the plaintext path.
                int responded = 0;
                int idx;
                while ((idx = CollectionsMarshal.AsSpan(carry).IndexOf("\r\n\r\n"u8)) >= 0)
                {
                    carry.RemoveRange(0, idx + 4);
                    responded++;
                }

                for (int i = 0; i < responded; i++)
                {
                    Wire.Write(conn, 200, "tls-ok", tls);
                }

                if (responded > 0)
                {
                    await conn.FlushAsync();
                }

                if (snapshot.IsClosed || tls.Closed)
                {
                    return;
                }

                conn.ResetRead();
            }
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"[tls-test] handler: {e.Message}");
        }
        finally
        {
            tls?.Dispose();
            conn.DecRef();
        }
    }

    private static unsafe void AppendPlaintext(TlsSession tls, in SpscRecvRing.Item item, List<byte> carry)
    {
        carry.AddRange(tls.Decrypt(item.Ptr, item.Len).ToArray());
    }

    // Copy native memory (a ring-read buffer) through the write slab.
    private static unsafe void WriteNative(TcpConnection conn, nint data, int length)
    {
        conn.Write(new ReadOnlySpan<byte>((void*)data, length));
    }
}
