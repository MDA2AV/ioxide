using static ioxide.Native;

namespace ioxide.file;

/// <summary>
/// A file whose reads run on the host's ring: opened once (blocking), then each read is an
/// IORING_OP_READ at an offset, resumed inline. One read in flight at a time; for per-reactor
/// concurrency over a directory, pool <see cref="AssetReader"/>s over an <see cref="AssetCache"/>.
/// </summary>
public sealed class RingFile : IDisposable
{
    private readonly IRingHost _host;
    private readonly RingOpSource _read = new();
    private int _disposed;

    public int Fd { get; }

    public long Length { get; }

    private RingFile(IRingHost host, int fd, long length)
    {
        _host = host;
        Fd = fd;
        Length = length;
    }

    /// <summary>Open <paramref name="path"/> read-only. Blocking open, one-time.</summary>
    public static RingFile Open(IRingHost host, string path)
    {
        int fd = open(path, O_RDONLY | O_CLOEXEC, 0);

        if (fd < 0)
        {
            throw new InvalidOperationException($"Could not open '{path}'.");
        }

        return new RingFile(host, fd, FileLength(fd));
    }

    /// <summary>
    /// Read up to <paramref name="length"/> bytes into native memory at
    /// <paramref name="destination"/>, starting at <paramref name="offset"/> in the file. The
    /// result is the number of bytes read (0 at end of file) or a negative errno.
    /// </summary>
    public ValueTask<int> ReadAsync(nint destination, int length, long offset)
    {
        ValueTask<int> pending = _read.Prepare();
        _host.SubmitRead(Fd, destination, length, offset, _read);
        return pending;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            close(Fd);
        }
    }
}
