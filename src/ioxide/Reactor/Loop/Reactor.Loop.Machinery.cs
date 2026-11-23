using System.Runtime.CompilerServices;
using static ioxide.Native;

namespace ioxide;

public sealed unsafe partial class Reactor
{
    // Cancel by exact user_data so a dead connection's multishot recv can't keep
    // consuming buffers or race the slot's next tenant.
    private void SubmitCancel(ulong targetUserData)
    {
        IoUringSqe* sqe = GetSqeOrFlush();
        Unsafe.InitBlockUnaligned(sqe, 0, 64);
        sqe->opcode    = IORING_OP_ASYNC_CANCEL;
        sqe->fd        = -1;
        sqe->addr      = targetUserData;
        sqe->user_data = Tag(KindCancel, 0, 0);
    }

}
