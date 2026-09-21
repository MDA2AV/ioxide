using System.Runtime.InteropServices;

namespace ioxide;

/// <summary>
/// File ABI: open/size for ring-native file clients (the reads themselves go through the ring;
/// these are one-time, at open).
/// </summary>
public static unsafe partial class Native {
    public const int O_RDONLY = 0;
    private const int SEEK_SET = 0;
    private const int SEEK_END = 2;

    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    public static extern int open([MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags, int mode);

    [DllImport("libc", SetLastError = true)]
    public static extern long lseek(int fd, long offset, int whence);

    /// <summary>
    /// File size via seek-to-end (positional ring reads never use the file position).
    /// </summary>
    public static long FileLength(int fd)
    {
        long end = lseek(fd, 0, SEEK_END);
        lseek(fd, 0, SEEK_SET);
        return end;
    }
}
