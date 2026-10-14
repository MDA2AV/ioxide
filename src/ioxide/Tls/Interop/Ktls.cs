using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace ioxide.tls;

/// <summary>
/// Kernel TLS transmit offload: derive the TLS 1.3 record keys from the server traffic secret
/// (HKDF-Expand-Label) and program them into the socket. After this, plain io_uring sends carry
/// plaintext and the kernel produces the records.
/// </summary>
internal static unsafe class Ktls
{
    private const int SOL_TCP = 6;
    private const int TCP_ULP = 31;
    private const int SOL_TLS = 282;
    private const int TLS_TX = 1;
    private const int TLS_RX = 2;
    private const int TLS_SET_RECORD_TYPE = 1;
    private const int TLS_GET_RECORD_TYPE = 2;
    private const ushort TLS_1_3_VERSION = 0x0304;
    private const ushort TLS_CIPHER_AES_GCM_128 = 51;
    private const byte TLS_RECORD_TYPE_ALERT = 21;
    private const int MSG_PEEK = 0x2;
    private const int MSG_NOSIGNAL = 0x4000;
    private const int MSG_DONTWAIT = 0x40;

    [DllImport("libc", SetLastError = true)]
    private static extern int setsockopt(int fd, int level, int optname, void* optval, uint optlen);

    [DllImport("libc", SetLastError = true)]
    private static extern nint sendmsg(int fd, Msghdr* msg, int flags);

    [DllImport("libc", SetLastError = true)]
    private static extern nint recvmsg(int fd, Msghdr* msg, int flags);

    /// <summary>tls12_crypto_info_aes_gcm_128 - the layout the kernel expects (40 bytes).</summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct CryptoInfoAesGcm128
    {
        public ushort Version;
        public ushort CipherType;
        public fixed byte Iv[8];
        public fixed byte Key[16];
        public fixed byte Salt[4];
        public fixed byte RecSeq[8];
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Iovec
    {
        public nint Base;
        public nuint Len;
    }

    // Linux x86-64 Msghdr (msg_namelen is followed by 4 bytes of padding before msg_iov).
    [StructLayout(LayoutKind.Sequential)]
    private struct Msghdr
    {
        public nint Name;
        public uint NameLen;
        public uint Pad;
        public nint Iov;
        public nuint IovLen;
        public nint Control;
        public nuint ControlLen;
        public int Flags;
    }

    /// <summary>
    /// Enable kTLS RX with keys derived from the TLS 1.3 <b>client</b> traffic secret, so the kernel
    /// decrypts inbound records and an ordinary recv returns plaintext.
    /// </summary>
    /// <param name="recordSequence">
    /// How many application-data records the client has already sent that BoringSSL consumed during
    /// the handshake. This is the one thing that cannot be guessed: the sequence number is part of
    /// the AEAD nonce, so starting the kernel at the wrong one makes every record fail to
    /// authenticate. The client's first request routinely rides in with its Finished flight, and
    /// those records are gone from the socket by the time we get here.
    /// </param>
    public static void EnableRx(int fd, byte[] clientTrafficSecret, ulong recordSequence)
        => Program(fd, TLS_RX, "TLS_RX", clientTrafficSecret, recordSequence, installUlp: false);

    /// <summary>Enable kTLS TX with keys derived from the TLS 1.3 server traffic secret.</summary>
    /// <remarks>
    /// Runs first. TX installs the TCP_ULP that RX then rides on, and a socket with RX enabled and
    /// TX not would send cleartext.
    /// </remarks>
    public static void EnableTx(int fd, byte[] serverTrafficSecret)
        // Record sequence 0: session tickets are disabled under kTLS, so no server record went out
        // under the application traffic key before the handoff.
        => Program(fd, TLS_TX, "TLS_TX", serverTrafficSecret, recordSequence: 0, installUlp: true);

    /// <summary>
    /// Whether the record a kTLS RX socket holds next is the peer's close_notify. A plain recv stops
    /// at a non-data record with EIO and leaves it queued; this reads it with the control message
    /// that carries its type, and leaves it there.
    /// </summary>
    public static bool PeekCloseNotify(int fd)
    {
        byte* alert = stackalloc byte[2];

        const int cmsgSpace = 24;   // CMSG_SPACE(1)
        byte* control = stackalloc byte[cmsgSpace];
        new Span<byte>(control, cmsgSpace).Clear();

        var iov = new Iovec { Base = (nint)alert, Len = 2 };
        var msg = new Msghdr
        {
            Iov = (nint)(&iov),
            IovLen = 1,
            Control = (nint)control,
            ControlLen = cmsgSpace,
        };

        if (recvmsg(fd, &msg, MSG_PEEK | MSG_DONTWAIT) != 2)
        {
            return false;
        }

        return *(int*)(control + 8) == SOL_TLS                 // cmsg_level
            && *(int*)(control + 12) == TLS_GET_RECORD_TYPE    // cmsg_type
            && control[16] == TLS_RECORD_TYPE_ALERT            // CMSG_DATA[0]: the record's type
            && alert[1] == 0;                                  // description: close_notify
    }

    /// <summary>
    /// Derives the AES-128-GCM key material from a TLS 1.3 traffic secret and programs it into one
    /// direction of the socket.
    /// </summary>
    /// <remarks>
    /// One body for both directions, because they only ever differed in three things: which
    /// direction to program, whether the record sequence is non-zero, and whether TCP_ULP has to be
    /// installed first. Everything else - the two HKDF expansions, the layout of the crypto info,
    /// and above all the zeroing of every copy of the key material in the finally - was written
    /// twice, which is one place too many for a routine that handles keys.
    /// </remarks>
    private static void Program(int fd, int optname, string what, byte[] trafficSecret,
        ulong recordSequence, bool installUlp)
    {
        byte[] key = ExpandLabel(trafficSecret, "key", 16);
        byte[] nonce = ExpandLabel(trafficSecret, "iv", 12);

        var info = new CryptoInfoAesGcm128
        {
            Version = TLS_1_3_VERSION,
            CipherType = TLS_CIPHER_AES_GCM_128,
        };

        try
        {
            for (int i = 0; i < 16; i++) info.Key[i] = key[i];
            for (int i = 0; i < 4; i++) info.Salt[i] = nonce[i];      // nonce[0..4]
            for (int i = 0; i < 8; i++) info.Iv[i] = nonce[4 + i];    // nonce[4..12]

            // Big-endian, like everything else on the wire.
            for (int i = 0; i < 8; i++)
            {
                info.RecSeq[i] = (byte)(recordSequence >> ((7 - i) * 8));
            }

            if (installUlp)
            {
                ReadOnlySpan<byte> ulp = "tls"u8;
                fixed (byte* p = ulp)
                {
                    if (setsockopt(fd, SOL_TCP, TCP_ULP, p, 3) != 0)
                    {
                        throw new IOException(
                            $"kTLS: TCP_ULP failed (errno {Marshal.GetLastPInvokeError()}); is the 'tls' kernel module available?");
                    }
                }
            }

            if (setsockopt(fd, SOL_TLS, optname, &info, (uint)sizeof(CryptoInfoAesGcm128)) != 0)
            {
                throw new IOException($"kTLS: {what} failed (errno {Marshal.GetLastPInvokeError()})");
            }
        }
        finally
        {
            // The keys are in the kernel now - don't leave copies on the heap/stack.
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(trafficSecret);
            CryptoInfoAesGcm128* ip = &info;
            CryptographicOperations.ZeroMemory(new Span<byte>(ip, sizeof(CryptoInfoAesGcm128)));
        }
    }

    /// <summary>
    /// Best-effort TLS 1.3 close_notify over kTLS: a {warning, close_notify} alert sent as a control
    /// message (SOL_TLS / TLS_SET_RECORD_TYPE = alert). Non-fatal - on a clean server-side close it
    /// lets the peer distinguish a real end-of-stream from a truncation; the peer may already be gone.
    /// </summary>
    public static void SendCloseNotify(int fd)
    {
        byte* alert = stackalloc byte[2];
        alert[0] = 1;   // level: warning
        alert[1] = 0;   // description: close_notify

        const int cmsgLen = 17;     // CMSG_LEN(1):   sizeof(cMsghdr=16) + 1
        const int cmsgSpace = 24;   // CMSG_SPACE(1): align8(16) + align8(1)
        byte* control = stackalloc byte[cmsgSpace];
        new Span<byte>(control, cmsgSpace).Clear();
        *(nuint*)(control + 0) = cmsgLen;               // cmsg_len
        *(int*)(control + 8) = SOL_TLS;                 // cmsg_level
        *(int*)(control + 12) = TLS_SET_RECORD_TYPE;    // cmsg_type
        control[16] = TLS_RECORD_TYPE_ALERT;            // CMSG_DATA[0]: this record is an alert

        var iov = new Iovec { Base = (nint)alert, Len = 2 };
        var msg = new Msghdr
        {
            Iov = (nint)(&iov),
            IovLen = 1,
            Control = (nint)control,
            ControlLen = cmsgSpace,
            Flags = 0,
        };
        sendmsg(fd, &msg, MSG_NOSIGNAL | MSG_DONTWAIT);
    }

    /// <summary>RFC 8446 HKDF-Expand-Label with an empty context.</summary>
    private static byte[] ExpandLabel(byte[] secret, string label, int length)
    {
        string full = "tls13 " + label;
        var info = new byte[2 + 1 + full.Length + 1];
        info[0] = (byte)(length >> 8);
        info[1] = (byte)length;
        info[2] = (byte)full.Length;
        for (int i = 0; i < full.Length; i++) info[3 + i] = (byte)full[i];
        info[^1] = 0;   // empty context

        return HKDF.Expand(HashAlgorithmName.SHA256, secret, length, info);
    }
}
