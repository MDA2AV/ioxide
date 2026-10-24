package ioxide

import ioxide.Reactor.Companion.KIND_CANCEL
import ioxide.Reactor.Companion.KIND_TCP_ACCEPT
import ioxide.Reactor.Companion.KIND_TCP_RECV
import ioxide.Reactor.Companion.KIND_TCP_SEND
import ioxide.Reactor.Companion.tag

/**
 * A reactor's TCP side: SO_REUSEPORT listeners with multishot accept, the shared provided-buffer group every
 * connection's multishot recv draws from, the fd-indexed connection table, and the send and teardown paths.
 * Reactor thread only, except [returnBuffer].
 */
internal class TcpTransport(val reactor: Reactor, private val config: ServerConfig, private val options: TcpOptions) {
    private val sendOpFlags = if (options.sendWaitAll) Sockets.MSG_WAITALL else 0

    // ---- Listeners --------------------------------------------------------------------------------------

    // -1, not 0: opening can throw partway, and the teardown that follows must not close stdin.
    private var listenFds = IntArray(0)
    internal var listenPorts = IntArray(0)
        private set

    fun openListeners() {
        val ports = intArrayOf(options.port) + options.extraPorts
        listenFds = IntArray(ports.size) { -1 }
        listenPorts = ports.copyOf()
        for (i in ports.indices) {
            listenFds[i] = Sockets.listen(ports[i], options.listenBacklog)
            if (ports[i] == 0) listenPorts[i] = Sockets.localPort(listenFds[i])
        }
    }

    fun armAccepts() {
        for (fd in listenFds) submitAccept(fd)
    }

    fun closeListeners() {
        for (fd in listenFds) if (fd >= 0) Native.close(fd)
    }

    private fun portOf(listenFd: Int): Int {
        for (i in listenFds.indices) if (listenFds[i] == listenFd) return listenPorts[i]
        return listenPorts[0]
    }

    // ---- Shared provided-buffer group -------------------------------------------------------------------

    private var bufRing: BufferRing? = null

    // Set by every buffer return, so the loop re-arms recvs parked on -ENOBUFS - including when the return
    // happened inline during dispatch, before the batch's trailing ENOBUFS was even seen.
    private var buffersReturned = false

    // Off-reactor returns; the reactor stages them all, then publishes the tail once.
    private val returnQ = MpscLongQueue(1 shl 14)

    fun initBufferRing() {
        bufRing = BufferRing(reactor.ring, BGID, config.recvSlots, config.recvBufferSize)
    }

    fun returnBuffer(bid: Int) {
        if (reactor.onReactorThread) {
            returnBufferDirect(bid)
            return
        }
        while (!returnQ.offer(bid.toLong())) Thread.onSpinWait()
        // Without the wake a queued return waits for an unrelated CQE; if the group drains meanwhile, recvs
        // fail with ENOBUFS.
        reactor.wake()
    }

    fun returnBufferDirect(bid: Int) {
        val ring = bufRing!!
        ring.add(bid)
        ring.publish()
        buffersReturned = true
    }

    fun drainReturnQ() {
        var bid = returnQ.poll()
        if (bid < 0) return
        val ring = bufRing!!
        while (bid >= 0) {
            ring.add(bid.toInt())
            bid = returnQ.poll()
        }
        ring.publish()
        buffersReturned = true
    }

    // ---- Connection table -------------------------------------------------------------------------------

    // Indexed by fd: dense small ints, an array beats a map per CQE.
    private var connections = arrayOfNulls<TcpConnection>(4096)
    private val pool = ArrayDeque<TcpConnection>()

    fun connAt(fd: Int, gen: Int): TcpConnection? {
        val conns = connections
        val conn = if (fd >= 0 && fd < conns.size) conns[fd] else null
        return if (conn != null && (conn.generation and 0xFFFF) == gen) conn else null
    }

    private fun track(fd: Int, conn: TcpConnection) {
        if (fd >= connections.size) {
            var length = connections.size
            while (length <= fd) length *= 2
            connections = connections.copyOf(length)
        }
        connections[fd] = conn
    }

    // ---- Submissions ------------------------------------------------------------------------------------

    private fun submitAccept(listenFd: Int) {
        IoUring.prep(
            reactor.getSqeOrFlush(), IoUring.OP_ACCEPT, listenFd, 0L, 0, 0L, tag(KIND_TCP_ACCEPT, 0, listenFd),
            ioprio = IoUring.ACCEPT_MULTISHOT, opFlags = Sockets.SOCK_CLOEXEC,
        )
    }

    private fun submitRecv(fd: Int, gen: Int) {
        IoUring.prep(
            reactor.getSqeOrFlush(), IoUring.OP_RECV, fd, 0L, 0, 0L, tag(KIND_TCP_RECV, gen, fd),
            flags = IoUring.IOSQE_BUFFER_SELECT, ioprio = IoUring.RECV_MULTISHOT, bufIndex = BGID,
        )
    }

    private fun submitSend(fd: Int, gen: Int, address: Long, length: Int, flags: Int) {
        IoUring.prep(
            reactor.getSqeOrFlush(), IoUring.OP_SEND, fd, address, length, 0L, tag(KIND_TCP_SEND, gen, fd),
            opFlags = flags,
        )
    }

    // By exact user_data, so a dead connection's multishot recv can neither keep taking buffers nor race the
    // fd's next tenant.
    private fun submitCancel(target: Long) {
        IoUring.prep(reactor.getSqeOrFlush(), IoUring.OP_ASYNC_CANCEL, -1, target, 0, 0L, tag(KIND_CANCEL, 0, 0))
    }

    // The connection's flush, straight to the SQ: it leaves with the reactor's next enter.
    fun submitFlush(conn: TcpConnection) {
        if (!conn.claimFlush()) return   // released before it reached the kernel
        submitSend(conn.clientFd, conn.generation and 0xFFFF, conn.writeBuffer, conn.writeInFlight, conn.sendFlags)
    }

    // ---- Accept -----------------------------------------------------------------------------------------

    // Listeners whose accept stopped for lack of descriptors or memory; the sweep re-arms them each tick.
    private val acceptPaused = ArrayList<Int>()
    private var acceptPauseReported = false

    fun onAccept(listenFd: Int, res: Int, flags: Int) {
        val more = flags and IoUring.CQE_F_MORE != 0

        if (res >= 0) {
            acceptPauseReported = false

            val conn = pool.removeLastOrNull()?.setFd(res)
                ?: TcpConnection(this, res, options.writeSlabSize, options.recvQueueEntries)

            track(res, conn)
            conn.initRefs()
            conn.listenerPort = portOf(listenFd)
            conn.sendFlags = sendOpFlags
            submitRecv(res, conn.generation and 0xFFFF)

            // Inline, until its first suspension: the recv above is not submitted yet, so its first read parks.
            reactor.startHandler(conn)
        } else if (res == -Native.EMFILE || res == -Native.ENFILE || res == -Native.ENOBUFS || res == -Native.ENOMEM) {
            // The connection stays in the backlog, so an accept re-armed now fails again at once and spins the
            // reactor; once a tick instead, reported once until an accept succeeds.
            if (!acceptPauseReported) {
                acceptPauseReported = true
                System.err.println("[r${reactor.id}] accept failed ($res): out of file descriptors or memory, retrying every ${Reactor.TICK_MS} ms")
            }
            if (!more) acceptPaused.add(listenFd)
            return
        } else {
            System.err.println("[r${reactor.id}] accept error: $res")
        }

        if (!more) submitAccept(listenFd)
    }

    // ---- Receive ----------------------------------------------------------------------------------------

    // Connections whose multishot recv ended on -ENOBUFS, packed gen << 32 | fd.
    private val recvStarved = ArrayList<Long>()

    fun onRecv(fd: Int, gen: Int, res: Int, flags: Int) {
        val hasBuf = flags and IoUring.CQE_F_BUFFER != 0
        val bid = if (hasBuf) flags ushr IoUring.CQE_BUFFER_SHIFT else -1

        val conn = connAt(fd, gen)

        if (res == -Native.ENOBUFS) {
            // The group ran dry, not a peer error: the multishot ended, so park the connection until buffers
            // come back.
            if (conn != null) {
                conn.readParkedMs = reactor.nowMs   // the peer sent; the wait is ours, so the clock restarts
                recvStarved.add((gen.toLong() shl 32) or (fd.toLong() and 0xFFFF_FFFFL))
            }
            return
        }

        if (res <= 0) {
            // Peer EOF or recv error: the reactor owns teardown.
            if (hasBuf) returnBufferDirect(bid)
            if (conn != null) closeFromRecv(conn, fd)
            return
        }

        if (conn == null) {
            // A stale CQE from the fd's previous tenant.
            if (hasBuf) returnBufferDirect(bid)
            return
        }

        val address = if (hasBuf) bufRing!!.bufferAddr(bid) else 0L
        if (!conn.complete(res, bid, address)) {
            closeFromRecvOverflow(conn, fd, gen)
            return
        }

        if (flags and IoUring.CQE_F_MORE == 0) submitRecv(fd, gen)
    }

    // Once per loop pass, and only when a buffer came back since the last one, so a parked connection
    // cannot spin the loop.
    fun rearmStarvedRecvs() {
        if (recvStarved.isEmpty() || !buffersReturned) return
        buffersReturned = false

        for (packed in recvStarved) {
            val fd = packed.toInt()
            val gen = (packed ushr 32).toInt()
            if (connAt(fd, gen) != null) submitRecv(fd, gen)
        }
        recvStarved.clear()
    }

    // Recv-side teardown. With a send in the kernel the reactor keeps its ref and the table slot, so the slab
    // cannot be recycled under it; finishSend lets go.
    private fun closeFromRecv(conn: TcpConnection, fd: Int) {
        conn.suppressFin()

        if (conn.flushSubmitted) {
            conn.closeAfterSend = true
            conn.markClosed()
            return
        }

        connections[fd] = null
        conn.markClosed()
        conn.releaseReactorRef()
    }

    // The multishot recv is still armed, so it is cancelled too.
    private fun closeFromRecvOverflow(conn: TcpConnection, fd: Int, gen: Int) {
        submitCancel(tag(KIND_TCP_RECV, gen, fd))
        closeFromRecv(conn, fd)
    }

    // ---- Send -------------------------------------------------------------------------------------------

    fun onSend(fd: Int, gen: Int, res: Int) {
        val conn = connAt(fd, gen) ?: return   // stale: never touch the fd's new tenant

        var sent = res
        if (sent <= 0) {
            // Failed: nothing more goes out.
            submitCancel(tag(KIND_TCP_RECV, gen, fd))   // the multishot recv is still armed
            conn.closeAfterSend = true
            conn.suppressFin()
            conn.markClosed()
            conn.writeInFlight = conn.writeHead
            sent = 0
        }
        conn.writeHead += sent

        if (conn.writeHead < conn.writeInFlight) {
            // Partial send (rare with MSG_WAITALL): resubmit the rest.
            submitSend(fd, gen, conn.writeBuffer + conn.writeHead, conn.writeInFlight - conn.writeHead, conn.sendFlags)
            return
        }

        finishSend(conn, fd)
    }

    // The kernel is done with the slab: complete the flush, then any teardown that waited for it.
    private fun finishSend(conn: TcpConnection, fd: Int) {
        conn.completeFlush()

        if (conn.closeAfterSend) {
            connections[fd] = null
            conn.releaseReactorRef()
        }
    }

    // ---- Recycle ----------------------------------------------------------------------------------------

    private val scratchItem = RecvItem()

    // At refcount 0, on the reactor thread.
    fun recycle(conn: TcpConnection) {
        val fd = conn.clientFd
        conn.markClosed()
        submitCancel(tag(KIND_TCP_RECV, conn.generation and 0xFFFF, fd))   // before clear() bumps the generation

        // Before drainRecv, which only sees what is still queued: an adapter that pulled buffers out holds
        // the only record of them.
        conn.releaseHeldRecvBuffers()
        conn.drainRecv(scratchItem)

        Native.close(fd)
        conn.clear()

        if (pool.size < options.poolMax) pool.addLast(conn) else conn.dispose()
    }

    // ---- Sweep ------------------------------------------------------------------------------------------

    /**
     * The clocks on a connection's lifecycle, once a tick: a connection waiting on a silent peer is reaped,
     * and so is one whose send the peer stopped draining; a FIN left behind a flush goes out.
     */
    fun sweep() {
        for (listenFd in acceptPaused) submitAccept(listenFd)
        acceptPaused.clear()

        val now = Clock.monotonicMs()
        val conns = connections
        for (fd in conns.indices) {
            val conn = conns[fd] ?: continue
            if (conn.sweepClosed) continue

            // Sending, so not waiting on the peer: only the send clock applies.
            if (conn.flushOutstanding) {
                conn.flushSeenMs = now
                if (options.sendTimeoutMs > 0 && now - conn.flushArmedMs > options.sendTimeoutMs) sweepClose(conn)
                continue
            }

            // A FIN left behind a flush - by a handler that let go, or by shutdownWrite - goes now.
            if ((conn.handlerReleased || conn.finWanted) && !conn.finWasSent) conn.sendFin()

            if (options.readTimeoutMs > 0) {
                val since = conn.waitingOnPeerSince()
                if (since >= 0 && now - since > options.readTimeoutMs) sweepClose(conn)
            }
        }
    }

    // shutdown() is what the peer sees, and also what releases the connection: it ends the recv a silent
    // peer never completes, or the send a stalled one holds, and those completions run the teardown that
    // gets the refcount right once the kernel is done with the slab. markClosed wakes a parked read now.
    private fun sweepClose(conn: TcpConnection) {
        conn.sweepClosed = true
        conn.suppressFin()   // this shutdown is the FIN
        Native.shutdown(conn.clientFd, Sockets.SHUT_RDWR)
        conn.markClosed()
    }

    // ---- Teardown ---------------------------------------------------------------------------------------

    // Live connections' sockets are closed, never their objects: a handler may still write to them.
    fun closeAcceptedSockets() {
        val conns = connections
        for (fd in conns.indices) {
            val conn = conns[fd] ?: continue
            // A handler letting go later must not shut down whatever socket gets the number next.
            conn.suppressFin()
            Native.close(fd)
            conns[fd] = null
        }
    }

    // Before the ring's descriptor is closed: unregistering is synchronous, closing is not.
    fun unregisterBufferRing() {
        bufRing?.unregister()
    }

    // After the ring is closed: the kernel can no longer write into these.
    fun freeMemory() {
        while (true) pool.removeLastOrNull()?.dispose() ?: break
        bufRing?.close()
        bufRing = null
    }

    companion object {
        const val BGID = 1
    }
}
