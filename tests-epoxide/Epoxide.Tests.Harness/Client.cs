using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Epoxide.Tests;

/// <summary>A minimal HTTP/1.1 client over a raw socket (and over TLS), used to drive the servers.</summary>
public static class Client
{
    public static (int Status, string Body) Get(int port, string path, int timeoutMs = 6000)
    {
        using var client = new TcpClient();
        client.Connect("127.0.0.1", port);
        client.ReceiveTimeout = timeoutMs;

        NetworkStream stream = client.GetStream();
        Send(stream, path);
        return ReadResponse(stream);
    }

    public static (int Status, string Body) GetTls(int port, string path, int timeoutMs = 6000)
    {
        using var client = new TcpClient();
        client.Connect("127.0.0.1", port);
        client.ReceiveTimeout = timeoutMs;

        using var ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: false, (_, _, _, _) => true);
        ssl.AuthenticateAsClient(new SslClientAuthenticationOptions
        {
            TargetHost = "localhost",
            EnabledSslProtocols = SslProtocols.Tls13,
        });

        Send(ssl, path);
        return ReadResponse(ssl);
    }

    /// <summary>
    /// Handshakes asking for one host by name, and reports the certificate the server answered
    /// with - which is the whole observable effect of SNI selection.
    /// </summary>
    /// <param name="host">
    /// Sent as the SNI extension. Null sends none at all, which is how "a client that does not
    /// speak SNI gets the default certificate" is driven - SslStream omits the extension for an
    /// empty target host, as an IP literal is not a legal SNI value.
    /// </param>
    public static string ServerCertificateSubject(int port, string? host, int timeoutMs = 6000)
    {
        using var client = new TcpClient();
        client.Connect("127.0.0.1", port);
        client.ReceiveTimeout = timeoutMs;

        using var ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: false, (_, _, _, _) => true);

        ssl.AuthenticateAsClient(new SslClientAuthenticationOptions
        {
            TargetHost = host ?? string.Empty,
            EnabledSslProtocols = SslProtocols.Tls13,
        });

        return ssl.RemoteCertificate?.Subject ?? "<none>";
    }

    /// <summary>
    /// Asks for one host by name and then USES the connection: reports the certificate served, the
    /// ALPN agreed, and the answer to a request over it.
    /// </summary>
    /// <remarks>
    /// The request is the point. Reading the certificate proves only that selection picked the
    /// right one - a host context missing something the connection needs afterwards, its keylog
    /// callback under kTLS being the real example, hands back a perfect certificate on a connection
    /// that then dies. Only asking it for something catches that.
    /// </remarks>
    public static (string Subject, string Alpn, int Status, string Body) GetTlsSni(
        int port, string path, string? host, string[]? alpn = null, int timeoutMs = 6000)
    {
        using var client = new TcpClient();
        client.Connect("127.0.0.1", port);
        client.ReceiveTimeout = timeoutMs;

        using var ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: false, (_, _, _, _) => true);

        var options = new SslClientAuthenticationOptions
        {
            TargetHost = host ?? string.Empty,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
        };

        if (alpn is not null)
        {
            options.ApplicationProtocols = [.. alpn.Select(a => new SslApplicationProtocol(a))];
        }

        ssl.AuthenticateAsClient(options);

        string subject = ssl.RemoteCertificate?.Subject ?? "<none>";
        string negotiated = ssl.NegotiatedApplicationProtocol.Protocol.Length == 0
            ? ""
            : ssl.NegotiatedApplicationProtocol.ToString();

        Send(ssl, path);
        (int status, string body) = ReadResponse(ssl);

        return (subject, negotiated, status, body);
    }

    /// <summary>
    /// Like <see cref="GetTls"/>, but presenting a client certificate - mutual TLS. Pass null to
    /// present none, which is how "the server demanded one and we had nothing" is driven.
    /// </summary>
    /// <remarks>
    /// SslStream is the client here on purpose: a passing test means epoxide's server agrees with an
    /// independent implementation rather than only with itself. A refused handshake surfaces as an
    /// <see cref="AuthenticationException"/> or an <see cref="IOException"/> depending on which side
    /// noticed first, so callers assert on "it threw" rather than on which one.
    /// </remarks>
    /// <param name="host">
    /// The name to ask for, sent as SNI. Defaults to the name the default certificate carries; pass
    /// another to drive a client certificate and a named host TOGETHER, which is what proves that
    /// selecting a certificate by name cannot also select its way out of client verification.
    /// </param>
    /// <summary>
    /// How an attempt to be served ended. The distinction is the point: a test asserting "the
    /// server refused this client" is satisfied, by a bare try/catch, by the server hanging, by the
    /// server crashing, and by the port being bound by something else entirely - so the assertion
    /// passes while the behaviour it names is broken.
    /// </summary>
    public enum TlsOutcome
    {
        /// <summary>Served. The handshake completed and the request was answered.</summary>
        Served,

        /// <summary>Refused with a TLS alert. The only outcome that means the server said no.</summary>
        Refused,

        /// <summary>Went away without an alert - dropped, reset, or the far side died.</summary>
        Dropped,

        /// <summary>Nothing came back in time. A server that hangs has not refused anything.</summary>
        TimedOut,
    }

    /// <summary>
    /// Attempts a full TLS request and classifies the outcome instead of merely reporting that
    /// something threw.
    /// </summary>
    /// <remarks>
    /// The request matters, and is not incidental. Under TLS 1.3 the client's Certificate is sent
    /// after the server's Finished, so a server rejecting it has nothing left to interrupt -
    /// AuthenticateAsClient returns happily and the alert only arrives when the client next reads.
    /// A helper that watched the handshake alone would report every rejected client certificate as
    /// a success.
    /// </remarks>
    public static TlsOutcome TryGetTls(int port, string path, string? certPath, string? keyPath,
        int timeoutMs = 6000, string host = "localhost")
    {
        try
        {
            (int status, _) = GetTlsClientCert(port, path, certPath, keyPath, timeoutMs, host);
            return status > 0 ? TlsOutcome.Served : TlsOutcome.Dropped;
        }
        catch (AuthenticationException)
        {
            return TlsOutcome.Refused;
        }
        catch (Exception e) when (e is IOException && Inner<AuthenticationException>(e) is not null)
        {
            return TlsOutcome.Refused;
        }
        catch (Exception e) when (Inner<SocketException>(e) is { SocketErrorCode: SocketError.TimedOut })
        {
            return TlsOutcome.TimedOut;
        }
        catch (IOException)
        {
            return TlsOutcome.Dropped;
        }
        catch (Exception e) when (e.Message.Contains("closed before headers", StringComparison.Ordinal))
        {
            return TlsOutcome.Dropped;
        }

        static T? Inner<T>(Exception e) where T : Exception
        {
            for (Exception? at = e; at is not null; at = at.InnerException)
            {
                if (at is T match)
                {
                    return match;
                }
            }
            return null;
        }
    }

    public static (int Status, string Body) GetTlsClientCert(
        int port, string path, string? certPath, string? keyPath, int timeoutMs = 6000,
        string host = "localhost")
    {
        using var client = new TcpClient();
        client.Connect("127.0.0.1", port);
        client.ReceiveTimeout = timeoutMs;

        var certificates = new X509CertificateCollection();
        if (certPath is not null && keyPath is not null)
        {
            using X509Certificate2 pem = X509Certificate2.CreateFromPemFile(certPath, keyPath);

            // SslStream on Linux needs the key associated through a PFX round-trip; a PEM-built
            // certificate carries it in a form the handshake will not use directly.
            certificates.Add(X509CertificateLoader.LoadPkcs12(pem.Export(X509ContentType.Pfx), null));
        }

        using var ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: false, (_, _, _, _) => true);
        ssl.AuthenticateAsClient(new SslClientAuthenticationOptions
        {
            TargetHost = host,
            EnabledSslProtocols = SslProtocols.Tls13,
            ClientCertificates = certificates,
        });

        Send(ssl, path);
        return ReadResponse(ssl);
    }

    /// <summary>
    /// Split ONE request across several TLS records - each SslStream.Write emits its own complete
    /// record - and report how many responses came back.
    ///
    /// This is the other fragmentation axis and the one that actually distinguishes handlers.
    /// A record split across TCP is all-or-nothing: BoringSSL yields nothing until it is whole, so
    /// even a handler that answers per decrypt sees exactly one decrypt. Split the REQUEST across
    /// records and each one decrypts on its own, so answering per decrypt answers several times.
    /// </summary>
    public static int CountTlsResponsesForMultiRecordRequest(int port, string path, int records,
        int settleMs = 1200, int timeoutMs = 15000)
    {
        using var client = new TcpClient();
        client.NoDelay = true;
        client.Connect("127.0.0.1", port);
        client.ReceiveTimeout = timeoutMs;

        using var ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: true, (_, _, _, _) => true);
        ssl.AuthenticateAsClient(new SslClientAuthenticationOptions
        {
            TargetHost = "localhost",
            EnabledSslProtocols = SslProtocols.Tls13,
        });

        byte[] request = Encoding.ASCII.GetBytes($"GET {path} HTTP/1.1\r\nHost: test\r\n\r\n");
        int piece = Math.Max(1, request.Length / records);

        for (int offset = 0; offset < request.Length; offset += piece)
        {
            ssl.Write(request, offset, Math.Min(piece, request.Length - offset));
            ssl.Flush();
            Thread.Sleep(30);   // let each record be its own recv on the server
        }

        Thread.Sleep(settleMs);
        client.ReceiveTimeout = 600;

        var seen = new System.Text.StringBuilder();
        byte[] buffer = new byte[8192];
        try
        {
            while (true)
            {
                int n = ssl.Read(buffer, 0, buffer.Length);
                if (n <= 0) break;
                seen.Append(Encoding.ASCII.GetString(buffer, 0, n));
            }
        }
        catch (IOException)
        {
        }

        int count = 0, at = 0;
        string text = seen.ToString();
        while ((at = text.IndexOf("HTTP/1.1 200", at, StringComparison.Ordinal)) >= 0)
        {
            count++;
            at += 12;
        }
        return count;
    }

    /// <summary>
    /// Like <see cref="GetTlsSplitRecords"/>, but reports how many complete responses came back for
    /// ONE request. A handler that answers per decrypt rather than per request replies more than
    /// once when the request arrives in pieces.
    /// </summary>
    public static int CountTlsResponsesForSplitRequest(int port, string path, int chunk,
        int settleMs = 1200, int timeoutMs = 15000)
    {
        using var client = new TcpClient();
        client.NoDelay = true;
        client.Connect("127.0.0.1", port);
        client.ReceiveTimeout = timeoutMs;

        using var chunking = new ChunkingStream(client.GetStream(), chunk);
        using var ssl = new SslStream(chunking, leaveInnerStreamOpen: true, (_, _, _, _) => true);
        ssl.AuthenticateAsClient(new SslClientAuthenticationOptions
        {
            TargetHost = "localhost",
            EnabledSslProtocols = SslProtocols.Tls13,
        });

        Send(ssl, path);

        // Let every response the server intends to send arrive before counting.
        Thread.Sleep(settleMs);
        client.ReceiveTimeout = 600;

        var seen = new System.Text.StringBuilder();
        byte[] buffer = new byte[8192];
        try
        {
            while (true)
            {
                int n = ssl.Read(buffer, 0, buffer.Length);
                if (n <= 0) break;
                seen.Append(Encoding.ASCII.GetString(buffer, 0, n));
            }
        }
        catch (IOException)
        {
            // read timeout - everything the server sent is already in `seen`
        }

        int count = 0, at = 0;
        while ((at = seen.ToString().IndexOf("HTTP/1.1 200", at, StringComparison.Ordinal)) >= 0)
        {
            count++;
            at += 12;
        }
        return count;
    }

    /// <summary>
    /// Send a request over TLS whose <b>TLS records are split across TCP writes</b>.
    ///
    /// The distinction matters and is easy to get wrong: SslStream.Write emits one COMPLETE record
    /// per call, so chunking at the SslStream level only produces many small whole records - which
    /// exercises nothing, because every recv then carries entire records. Chunking must happen
    /// BELOW TLS, so a single record arrives in pieces and the server has to hold partial record
    /// state across recvs. With chunk = 1 every byte of every record is its own TCP write.
    /// </summary>
    public static (int Status, string Body) GetTlsSplitRecords(int port, string path, int chunk,
        int timeoutMs = 15000)
    {
        using var client = new TcpClient();
        client.NoDelay = true;
        client.Connect("127.0.0.1", port);
        client.ReceiveTimeout = timeoutMs;

        using var chunking = new ChunkingStream(client.GetStream(), chunk);
        using var ssl = new SslStream(chunking, leaveInnerStreamOpen: true, (_, _, _, _) => true);
        ssl.AuthenticateAsClient(new SslClientAuthenticationOptions
        {
            TargetHost = "localhost",
            EnabledSslProtocols = SslProtocols.Tls13,
        });

        Send(ssl, path);
        return ReadResponse(ssl);
    }

    /// <summary>Splits every write into <paramref name="chunk"/>-byte writes, each flushed.</summary>
    private sealed class ChunkingStream(Stream inner, int chunk) : Stream
    {
        public override void Write(byte[] buffer, int offset, int count)
            => Write(buffer.AsSpan(offset, count));

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            for (int i = 0; i < buffer.Length; i += chunk)
            {
                inner.Write(buffer.Slice(i, Math.Min(chunk, buffer.Length - i)));
                inner.Flush();

                // The pause is the point, not politeness. TCP_NODELAY stops the SENDER batching,
                // but the receiver still coalesces whatever has arrived into one recv - so without
                // a gap the server drains the whole record in a single completion and never holds
                // partial state. Sleeping lets the reactor's recv land mid-record, which is the
                // only thing that exercises reassembly.
                if (i + chunk < buffer.Length)
                {
                    Thread.Sleep(1);
                }
            }
        }

        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
        public override void Flush() => inner.Flush();
        public override bool CanRead => inner.CanRead;
        public override bool CanWrite => inner.CanWrite;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }

    /// <summary>
    /// Complete a TLS handshake, then write bytes that are not a valid TLS record. The server's
    /// decrypt must surface that as a FAULT rather than as "the record is incomplete, wait for
    /// more" - a corrupted stream that looks like a quiet connection leaves the reader hanging on
    /// one that is never going to recover.
    /// </summary>
    public static void SendTlsGarbageAfterHandshake(int port, int timeoutMs = 6000)
    {
        using var client = new TcpClient();
        client.Connect("127.0.0.1", port);
        client.ReceiveTimeout = timeoutMs;

        using var ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: false, (_, _, _, _) => true);
        ssl.AuthenticateAsClient(new SslClientAuthenticationOptions
        {
            TargetHost = "localhost",
            EnabledSslProtocols = SslProtocols.Tls13,
        });

        // Underneath the SslStream, straight onto the socket: a record header claiming a content
        // type and version no TLS 1.3 peer will accept, followed by noise.
        NetworkStream raw = client.GetStream();
        byte[] bogus = [0x17, 0x03, 0x03, 0x00, 0x10, .. Enumerable.Repeat((byte)0xAB, 16)];
        raw.Write(bogus);
        raw.Flush();

        // Let the server read and fault before the socket closes under it, so what it reports is
        // the bad record rather than the disconnect.
        Thread.Sleep(500);
    }

    // Several requests over one connection (lock-step), to exercise the handler's keep-alive loop.
    public static List<(int Status, string Body)> GetKeepAlive(int port, string path, int count, int timeoutMs = 6000)
    {
        using var client = new TcpClient();
        client.Connect("127.0.0.1", port);
        client.ReceiveTimeout = timeoutMs;

        NetworkStream stream = client.GetStream();
        var results = new List<(int, string)>(count);
        for (int i = 0; i < count; i++)
        {
            Send(stream, path);
            results.Add(ReadResponse(stream));
        }

        return results;
    }

    public static void Send(Stream stream, string path)
    {
        stream.Write(Encoding.ASCII.GetBytes($"GET {path} HTTP/1.1\r\nHost: test\r\n\r\n"));
    }

    // Read the status line and the Content-Length body in full.
    public static (int Status, string Body) ReadResponse(Stream stream)
    {
        var buffer = new byte[64 * 1024];
        int filled = 0;
        int headerEnd = -1;

        while (headerEnd < 0)
        {
            int n = stream.Read(buffer, filled, buffer.Length - filled);
            if (n <= 0)
            {
                throw new Exception("connection closed before headers arrived");
            }

            filled += n;
            headerEnd = new ReadOnlySpan<byte>(buffer, 0, filled).IndexOf("\r\n\r\n"u8);
        }

        string head = Encoding.ASCII.GetString(buffer, 0, headerEnd);
        int status = int.Parse(head.AsSpan(9, 3));   // "HTTP/1.1 NNN ..."
        int contentLength = ContentLength(head);
        int bodyStart = headerEnd + 4;

        while (filled - bodyStart < contentLength)
        {
            int n = stream.Read(buffer, filled, buffer.Length - filled);
            if (n <= 0)
            {
                break;
            }
            filled += n;
        }

        string body = Encoding.ASCII.GetString(buffer, bodyStart, Math.Min(contentLength, filled - bodyStart));
        return (status, body);
    }

    private static int ContentLength(string head)
    {
        foreach (string line in head.Split("\r\n"))
        {
            if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
            {
                return int.Parse(line.AsSpan("Content-Length:".Length).Trim());
            }
        }
        return 0;
    }
}
