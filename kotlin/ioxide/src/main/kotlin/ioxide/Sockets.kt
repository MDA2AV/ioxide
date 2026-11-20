package ioxide

/** The socket calls made outside the ring: listeners, options, and the bound port. */
internal object Sockets {
    const val AF_INET = 2
    const val SOCK_STREAM = 1
    const val SOCK_NONBLOCK = 0x800
    const val SOCK_CLOEXEC = 0x80000
    const val SOL_SOCKET = 1
    const val SO_REUSEADDR = 2
    const val SO_SNDBUF = 7
    const val SO_RCVBUF = 8
    const val SO_KEEPALIVE = 9
    const val SO_REUSEPORT = 15
    const val IPPROTO_TCP = 6
    const val TCP_NODELAY = 1
    const val SHUT_RD = 0
    const val SHUT_WR = 1
    const val SHUT_RDWR = 2
    const val MSG_NOSIGNAL = 0x4000
    const val MSG_WAITALL = 0x100
    const val MSG_PEEK = 0x2
    const val MSG_DONTWAIT = 0x40

    private const val SOCKADDR_IN_SIZE = 16

    fun setInt(fd: Int, level: Int, name: Int, value: Int): Int {
        val p = Native.malloc(4)
        try {
            putInt(p, value)
            return Native.setsockopt(fd, level, name, p, 4)
        } finally {
            Native.free(p)
        }
    }

    /**
     * A listening IPv4 TCP socket on 0.0.0.0:[port] (0 picks one; see [localPort]). SO_REUSEPORT lets every
     * reactor bind its own listener on the same port, the kernel spreading connections across them; accepted
     * sockets inherit TCP_NODELAY from it.
     */
    fun listen(port: Int, backlog: Int, reusePort: Boolean = true): Int {
        val fd = Native.socket(AF_INET, SOCK_STREAM or SOCK_CLOEXEC, 0)
        check(fd >= 0) { "socket failed with errno ${-fd}" }

        val addr = Native.malloc(SOCKADDR_IN_SIZE.toLong())
        try {
            setInt(fd, SOL_SOCKET, SO_REUSEADDR, 1)
            if (reusePort) setInt(fd, SOL_SOCKET, SO_REUSEPORT, 1)
            setInt(fd, IPPROTO_TCP, TCP_NODELAY, 1)

            zeroMemory(addr, SOCKADDR_IN_SIZE.toLong())
            putShort(addr, AF_INET.toShort())
            putShort(addr + 2, Integer.reverseBytes(port shl 16).toShort())   // htons
            val rc = Native.bind(fd, addr, SOCKADDR_IN_SIZE)
            if (rc < 0) {
                Native.close(fd)
                throw IllegalStateException("bind(0.0.0.0:$port) failed with errno ${-rc}")
            }
            val lrc = Native.listen(fd, backlog)
            if (lrc < 0) {
                Native.close(fd)
                throw IllegalStateException("listen(0.0.0.0:$port) failed with errno ${-lrc}")
            }
            return fd
        } finally {
            Native.free(addr)
        }
    }

    /** The port a socket is bound to. */
    fun localPort(fd: Int): Int {
        val addr = Native.malloc(SOCKADDR_IN_SIZE.toLong() + 4)
        try {
            putInt(addr + SOCKADDR_IN_SIZE, SOCKADDR_IN_SIZE)
            val rc = Native.getsockname(fd, addr, addr + SOCKADDR_IN_SIZE)
            check(rc == 0) { "getsockname failed with errno ${-rc}" }
            val be = getShort(addr + 2).toInt() and 0xFFFF
            return ((be and 0xFF) shl 8) or (be ushr 8)
        } finally {
            Native.free(addr)
        }
    }
}
