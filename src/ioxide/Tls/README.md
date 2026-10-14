# TLS

TLS termination for [ioxide](https://github.com/MDA2AV/ioxide). Part of the `ioxide` package -
there is nothing extra to install, and none of it loads unless you call it. The handshake runs
through BoringSSL, which ships inside the package, over the reactor's ring; after it, BoringSSL
encrypts and decrypts in both directions by default. Kernel TLS transmit offload (`TlsOptions.KernelTx`) is opt-in, for the
deployments where `sendfile` or NIC crypto pays for its constraints.

```csharp
reactor.OnStart = r => TlsService.Start(r, new TlsOptions
{
    CertificatePath = "/certs/server.crt",
    KeyPath = "/certs/server.key",
});

reactor.Handle = async (r, conn) =>
{
    TlsSession? tls = null;
    if (conn.ListenerPort == 8443)
        tls = await r.GetService<TlsService>().AcceptAsync(conn);   // handshake (+ kTLS handoff if opted in)

    // The first request can arrive with the handshake's final flight:
    if (tls != null) Feed(tls.DrainPlaintext());

    // ... send-first loop: respond to buffered requests before parking on a read ...
    // outbound goes through tls.Write(conn, bytes) - correct in either backend;
    // inbound decrypts via tls.Decrypt(ptr, len)
};
```

Pair with `ServerConfig.ExtraPorts` to terminate TLS on a second port while plaintext stays on
the first.

## How it works

- **By default BoringSSL owns both directions.** Responses go through `TlsSession.Write`, which
  encrypts into the connection's write slab; inbound records decrypt through
  `TlsSession.Decrypt`. No kernel module, TLS 1.2 and 1.3, any ciphersuite, session resumption
  available (each reactor issues its own ticket keys, so a ticket resumes on the reactor that
  minted it).
- **`KernelTx = true`** hands transmit to the kernel (kTLS TX): the negotiated keys are
  programmed into the socket and the reactor's ordinary io_uring sends carry plaintext the
  kernel turns into records. `TlsSession.Write` stays correct - it writes plaintext straight to
  the connection in this mode. The cost: the `tls` kernel module, TLS 1.3 only, one ciphersuite,
  no resumption. The payoff is `sendfile` and NIC offload, not loopback throughput.
- **`KernelRx = true`** (requires `KernelTx`, experimental) hands receive to the kernel as well;
  see the `TlsOptions.KernelRx` doc for why it is a research toggle.
- **The handshake** rides the ring like any other I/O: BoringSSL drives memory BIOs, the service
  pumps ciphertext through the connection's recv/send. Resumes inline on the reactor.

## Requirements

- **Nothing for TLS itself** - BoringSSL ships in the package as `libioxide_boringssl.so`
  (linux-x64), built by `scripts/build-boringssl-native.sh` from a pinned commit.
- **Linux `tls` kernel module** - only for the kTLS opt-in (`modprobe tls`; standard on
  mainstream distros).

Ships in `ioxide`. MIT.
