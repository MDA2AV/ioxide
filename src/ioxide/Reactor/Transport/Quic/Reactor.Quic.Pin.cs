using static ioxide.Native;

namespace ioxide;

/// <summary>
/// Ends the cross-reactor forwarding a migrated client would otherwise pay forever: the owning
/// reactor claims the peer's new address with a socket <c>connect()</c>ed to it, which outranks the
/// wildcard binds in the kernel's lookup, so the datagrams arrive here directly.
///
/// <c>connect()</c> on a datagram socket sends nothing - it is a local declaration - and a connected
/// socket takes no part in reuseport selection, so no other peer moves (measured: eight, none did).
///
/// It cannot bootstrap itself: this reactor only learns the new address from a datagram, and the
/// datagrams are going elsewhere. Forwarding delivers the first one. See Reactor.Quic.Forward.cs.
/// </summary>
public sealed unsafe partial class Reactor
{
    /// <summary>
    /// Ceiling on concurrent claims: each costs a descriptor, and ngtcp2 adopts a path before it
    /// finishes validating it, so a forged datagram can reach here. Past it, forwarding continues.
    /// </summary>
    private const int QuicMaxPinnedPeers = 512;

    private int  _quicServingFd = -1;   // the wildcard QUIC socket; pins are only made against it
    private int  _quicPinsOpen;
    private long _quicPinsCreated;

    /// <summary>Peers currently claimed by a socket of this reactor's own.</summary>
    public int QuicPinsOpen => Volatile.Read(ref _quicPinsOpen);

    /// <summary>Claims opened since startup - one per address a connection moved to.</summary>
    public long QuicPinsCreated => Volatile.Read(ref _quicPinsCreated);

    /// <summary>
    /// Claim <paramref name="conn"/>'s current peer address, replacing any earlier claim. Called
    /// from the reactor's sweep, NOT from the engine's path-change report: a path is reported many
    /// times while ngtcp2 validates it, alternating between the old address and the one being
    /// probed, and claiming each report churns sockets and drops queued datagrams. By the next
    /// sweep the address has settled, and a repeat of one already claimed costs nothing. Reactor thread only, and quietly does
    /// nothing whenever the claim would be pointless or impossible - a connection that never moved,
    /// a single-reactor server, a client-side connection on its own socket, or the ceiling reached.
    /// </summary>
    internal void QuicPinPeer(QuicConnection conn)
    {
        // Not under KernelFilter - the kernel already routes by connection id there.
        if (_quicOptions is not { PinMigratedPeers: true, Routing: QuicRouting.Forward } options ||
            !conn.PeerAddressMoved ||
            ShardCount <= 1 ||
            _quicServingFd < 0 ||
            conn.SocketFd != _quicServingFd ||
            conn.PeerAddr == 0 || conn.PeerAddrLen <= 0)
        {
            return;
        }

        // Already claimed: leave it. Rebuilding would close a socket with datagrams queued on it.
        ReadOnlySpan<byte> current = new((void*)conn.PeerAddr, conn.PeerAddrLen);
        if (conn.PinSlot >= 0 &&
            conn.PinnedAddrLen == conn.PeerAddrLen &&
            current.SequenceEqual(conn.PinnedAddr.AsSpan(0, conn.PinnedAddrLen)))
        {
            return;
        }

        QuicUnpinPeer(conn);   // the old claim names somewhere the peer no longer is

        if (_quicPinsOpen >= QuicMaxPinnedPeers)
        {
            return;   // keep forwarding: slower, correct, bounded
        }

        // A failed claim must never propagate: this runs from the sweep, where a throw would take
        // the ticker down. Not claiming only costs a hop.
        int fd;
        try
        {
            fd = OpenUdpSocket(options.Port, _config.DualStack, _udp.Gro, _udp.SocketBufferBytes,
                               conn.PeerAddr, conn.PeerAddrLen);
        }
        catch (InvalidOperationException)
        {
            return;   // could not bind again: forwarding continues
        }

        if (fd < 0)
        {
            return;   // already claimed, or the kernel refused: forwarding continues
        }

        conn.PinSlot = UdpAdoptSocket(fd, options.Port);

        // What was claimed, so the check above can recognise a repeat.
        current.CopyTo(conn.PinnedAddr);
        conn.PinnedAddrLen = conn.PeerAddrLen;

        _quicPinsOpen++;
        _quicPinsCreated++;
    }

    /// <summary>
    /// Drop this connection's claim. The slot becomes reusable only once the kernel's last
    /// completion for it arrives, so a stale completion is never read as a new socket's traffic.
    /// </summary>
    internal void QuicUnpinPeer(QuicConnection conn)
    {
        int slot = conn.PinSlot;
        if (slot < 0)
        {
            return;
        }

        conn.PinSlot = -1;
        conn.PinnedAddrLen = 0;

        if ((uint)slot >= (uint)_udpFds.Length || _udpFds[slot] < 0)
        {
            return;
        }

        int fd = _udpFds[slot];
        _udpFds[slot] = -1;   // released before the close, so no re-arm can race the fd away
        SubmitCancel(Tag(KindUdpRecv, 0, slot));   // the armed receive holds the socket open past close()
        close(fd);
        _quicPinsOpen--;
    }

    /// <summary>
    /// Add an open socket to the fd table and arm it, reusing a drained slot when one is free.
    /// </summary>
    private int UdpAdoptSocket(int fd, ushort port)
    {
        int index;
        if (_udpFreeSlots.Count > 0)
        {
            index = _udpFreeSlots.Pop();
            _udpFds[index]     = fd;
            _udpFdPorts[index] = port;
        }
        else
        {
            // Indices stay stable (completions carry theirs in user_data), so growing the tables
            // cannot disturb multishots already armed.
            index       = _udpFds.Length;
            _udpFds     = [.. _udpFds, fd];
            _udpFdPorts = [.. _udpFdPorts, port];
        }

        ArmUdpRecv(index);
        return index;
    }
}
