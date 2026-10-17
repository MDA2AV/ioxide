# TLS

TLS termination for epoxide - ioxide's TLS (`ioxide.tls`), ported to epoll as `epoxide.tls` with
the same API, so code written against ioxide ports by changing the namespace. Part of the `epoxide`
package - there is nothing extra to install, and none of it loads unless you call it. The handshake
runs through BoringSSL, the same `libioxide_boringssl.so` ioxide bundles, over the connection's own
reads and flushes; after it, BoringSSL encrypts and decrypts in both directions by default. Kernel
TLS transmit offload (`TlsOptions.KernelTx`) is opt-in, for the deployments where `sendfile` or NIC
crypto pays for its constraints.

```csharp
reactor.OnStart = r => TlsService.Start(r, new TlsOptions
{
    CertificatePath = "/certs/server.crt",
    KeyPath = "/certs/server.key",
});

reactor.TcpHandle = async (r, conn) =>
{
    try
    {
        TlsSession tls = await r.GetService<TlsService>().AcceptAsync(conn);   // handshake (+ kTLS handoff if opted in)
        await using var pipe = new TlsConnectionDualPipe(conn, tls);           // disposes the session too

        // From here on the connection can move: the read loop on the reactor, the writer on the
        // thread pool, or both off it - full duplex, with nothing handed back to the reactor.
        ReadResult read = await pipe.Input.ReadAsync();
        // ...
    }
    finally
    {
        conn.DecRef();
    }
};
```

Pair with `TcpOptions.ExtraPorts` to terminate TLS on a second port while plaintext stays on the
first.

## How it works

- **By default BoringSSL owns both directions.** Responses go through `TlsSession.Write` (or the
  dual pipe's writer), which encrypts into the connection's write slab; inbound records decrypt
  through `TlsSession.Decrypt`. No kernel module, TLS 1.2 and 1.3, any ciphersuite, session
  resumption available (each reactor issues its own ticket keys, so a ticket resumes on the reactor
  that minted it).
- **Any thread.** A recv and a send are the caller's own syscalls in epoxide, and so is the crypto
  around them: a session's reader and writer may run on two threads at once. An SSL object is not
  thread-safe, so every BoringSSL call on a session takes the session's lock - held only across
  the synchronous crypto, never across an await, and uncontended unless the two directions really
  do overlap. Nothing is posted to the reactor.
- **`KernelTx = true`** hands transmit to the kernel (kTLS TX): the negotiated keys are programmed
  into the socket and the connection's ordinary sends carry plaintext the kernel turns into
  records. `TlsSession.Write` stays correct - it writes plaintext straight to the connection in
  this mode. The cost: the `tls` kernel module, TLS 1.3 only, one ciphersuite, no resumption. The
  payoff is `sendfile` and NIC offload, not loopback throughput.
- **`KernelRx = true`** (requires `KernelTx`, experimental) hands receive to the kernel as well:
  ordinary recvs return plaintext. A control record from the peer - a close_notify, an alert, a
  KeyUpdate - ends the read side, and `TlsSession.Closed` still tells a close_notify apart; see the
  `TlsOptions.KernelRx` doc.
- **The handshake** rides the connection like any other I/O: BoringSSL drives memory BIOs, the
  service pumps ciphertext through the connection's reads and flushes. `AcceptAsync` can be awaited
  from any thread and resumes where its caller belongs.

## Requirements

- **Nothing for TLS itself** - BoringSSL ships in the package as `libioxide_boringssl.so`
  (linux-x64), built by `scripts/build-boringssl-native.sh` from a pinned commit.
- **Linux `tls` kernel module** - only for the kTLS opt-in (`modprobe tls`; standard on mainstream
  distros).

Ships in `epoxide`. MIT.
