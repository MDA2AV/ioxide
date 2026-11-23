using System.Runtime.InteropServices;
using System.Text;
using epoxide;
using epoxide.tls;
using epoxide.utils;

namespace Epoxide.Tests;

/// <summary>
/// The TLS half of the harness's <see cref="Wire"/>, kept with the TLS suite so the harness needs no
/// TLS. A class of its own rather than a partial <c>Wire</c>: a partial type does not span
/// assemblies, and a second <c>Wire</c> here would hide the harness's.
/// </summary>
public static class TlsWire
{
    /// <summary>
    /// Write a response, encrypting it when the connection has a TLS session that is not using
    /// kTLS. Pass null for a plaintext connection.
    ///
    /// The session has to be threaded through because the correct call depends on it: with kTLS
    /// the kernel produces the records so plaintext goes straight to the connection, and without
    /// it a bare conn.Write puts CLEARTEXT on a socket the peer is reading as TLS.
    /// </summary>
    public static void Write(TcpConnection conn, int status, string body, TlsSession? tls)
    {
        byte[] bytes = Wire.Response(status, body);

        if (tls is null)
        {
            conn.Write(bytes);
        }
        else
        {
            tls.Write(conn, bytes);
        }
    }
}

/// <summary>
/// The TLS handlers of ioxide's harness, which epoxide's keeps out of its TLS-free harness - here,
/// and linked into the chaos suite, which serves TLS too.
/// </summary>
public static class TlsHandlers
{
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

            while (true)
            {
                RecvSnapshot snapshot = await connection.ReadAsync();

                if (snapshot.IsClosed)
                {
                    return;
                }

                session.Write(connection, IdentityBytes(session));

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
        byte[] who = Encoding.ASCII.GetBytes(session.PeerSubject ?? "anonymous");
        byte[] head = Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\ncontent-length: {who.Length}\r\n\r\n");

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

            // As in TlsIdentitySendFirst: the first request may already be decrypted.
            if (!session.DrainPlaintext().IsEmpty)
            {
                session.Write(connection, SendFirstResponse);
                await connection.FlushAsync();
            }

            while (true)
            {
                RecvSnapshot snapshot = await connection.ReadAsync();

                if (snapshot.IsClosed)
                {
                    return;
                }

                session.Write(connection, SendFirstResponse);

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
                    TlsWire.Write(conn, 200, "tls-ok", tls);
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
}
