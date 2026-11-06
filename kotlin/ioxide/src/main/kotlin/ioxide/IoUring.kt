package ioxide

/** include/uapi/linux/io_uring.h: the opcodes, flags and struct offsets this port reads and writes. */
internal object IoUring {
    const val OP_NOP = 0
    const val OP_POLL_ADD = 6
    const val OP_SENDMSG = 9
    const val OP_TIMEOUT = 11
    const val OP_TIMEOUT_REMOVE = 12
    const val OP_ACCEPT = 13
    const val OP_ASYNC_CANCEL = 14
    const val OP_CLOSE = 19
    const val OP_READ = 22
    const val OP_WRITE = 23
    const val OP_SEND = 26
    const val OP_RECV = 27
    const val OP_SHUTDOWN = 34
    const val OP_SEND_ZC = 47

    // sqe->flags
    const val IOSQE_FIXED_FILE = 1 shl 0
    const val IOSQE_IO_LINK = 1 shl 2
    const val IOSQE_ASYNC = 1 shl 4
    const val IOSQE_BUFFER_SELECT = 1 shl 5
    const val IOSQE_CQE_SKIP_SUCCESS = 1 shl 6

    // sqe->ioprio for accept and recv/send
    const val ACCEPT_MULTISHOT = 1 shl 0
    const val RECVSEND_POLL_FIRST = 1 shl 0
    const val RECV_MULTISHOT = 1 shl 1

    // sqe->poll32_events
    const val POLL_ADD_MULTI = 1 shl 0
    const val POLLIN = 0x0001

    // cqe->flags
    const val CQE_F_BUFFER = 1 shl 0
    const val CQE_F_MORE = 1 shl 1
    const val CQE_F_SOCK_NONEMPTY = 1 shl 2
    const val CQE_F_NOTIF = 1 shl 3
    const val CQE_F_BUF_MORE = 1 shl 4
    const val CQE_BUFFER_SHIFT = 16

    // io_uring_enter flags
    const val ENTER_GETEVENTS = 1 shl 0
    const val ENTER_EXT_ARG = 1 shl 3
    const val ENTER_REGISTERED_RING = 1 shl 4

    // io_uring_setup flags
    const val SETUP_CQSIZE = 1 shl 3
    const val SETUP_SUBMIT_ALL = 1 shl 7
    const val SETUP_SINGLE_ISSUER = 1 shl 12
    const val SETUP_DEFER_TASKRUN = 1 shl 13
    const val SETUP_NO_SQARRAY = 1 shl 16

    const val FEAT_SINGLE_MMAP = 1 shl 0

    // sq ring flags
    const val SQ_CQ_OVERFLOW = 1 shl 1

    // io_uring_register opcodes
    const val REGISTER_RING_FDS = 20
    const val UNREGISTER_RING_FDS = 21
    const val REGISTER_PBUF_RING = 22
    const val UNREGISTER_PBUF_RING = 23

    // provided-buffer ring registration flags (io_uring_buf_reg.flags)
    const val IOU_PBUF_RING_INC = 2

    const val OFF_SQ_RING = 0L
    const val OFF_SQES = 0x10000000L

    const val SQE_SIZE = 64
    const val CQE_SIZE = 16

    // struct io_uring_params (120 bytes)
    const val PARAMS_SIZE = 120L
    const val P_SQ_ENTRIES = 0L
    const val P_CQ_ENTRIES = 4L
    const val P_FLAGS = 8L
    const val P_FEATURES = 20L
    const val P_SQ_OFF = 40L    // struct io_sqring_offsets: head tail ring_mask ring_entries flags dropped array resv1 user_addr
    const val P_CQ_OFF = 80L    // struct io_cqring_offsets: head tail ring_mask ring_entries overflow cqes flags resv1 user_addr

    // struct io_uring_buf (16 bytes) inside a provided-buffer ring; the ring's tail overlays bufs[0].resv.
    const val BUF_SIZE = 16
    const val BUF_RING_TAIL = 14L

    // struct io_uring_buf_reg (40 bytes)
    const val BUF_REG_SIZE = 40L

    // struct io_uring_rsrc_update (16 bytes): offset u32, resv u32, data u64
    const val RSRC_UPDATE_SIZE = 16L

    // struct io_uring_getevents_arg (24 bytes): sigmask u64, sigmask_sz u32, min_wait_usec u32, ts u64
    const val GETEVENTS_ARG_SIZE = 24L

    /**
     * Fills all 64 bytes of an SQE in eight stores: whatever an earlier use left there is overwritten,
     * so nothing needs zeroing first. [off] is `off`/`addr2`, [opFlags] the per-opcode flags word
     * (msg_flags, accept_flags, poll32_events, timeout_flags...), [bufIndex] `buf_index`/`buf_group`.
     */
    fun prep(
        sqe: Long, opcode: Int, fd: Int, addr: Long, len: Int, off: Long, userData: Long,
        flags: Int = 0, ioprio: Int = 0, opFlags: Int = 0, bufIndex: Int = 0, fileIndex: Int = 0,
    ) {
        putLong(sqe, (opcode and 0xFF).toLong() or ((flags and 0xFF).toLong() shl 8) or
            ((ioprio and 0xFFFF).toLong() shl 16) or (fd.toLong() shl 32))
        putLong(sqe + 8, off)
        putLong(sqe + 16, addr)
        putLong(sqe + 24, (len.toLong() and 0xFFFF_FFFFL) or (opFlags.toLong() shl 32))
        putLong(sqe + 32, userData)
        putLong(sqe + 40, (bufIndex and 0xFFFF).toLong() or (fileIndex.toLong() shl 32))
        putLong(sqe + 48, 0L)
        putLong(sqe + 56, 0L)
    }
}
