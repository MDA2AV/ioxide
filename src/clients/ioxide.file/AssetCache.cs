using System.Buffers;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ioxide.file;

/// <summary>
/// An immutable snapshot of a directory, keyed by URL path: one open descriptor plus the length per
/// file, opened once and shared across reactors (reads are positional off the ring, so nothing is
/// locked). No bytes are cached and no HTTP is spoken - a caller looks a path up, reads the file data
/// off the ring, and frames it however it likes. Descriptors are trusted for the snapshot's lifetime;
/// a deploy is picked up by rebuilding the snapshot (<see cref="StaticAssets.Reload"/>), not by
/// re-stat'ing per request. One open descriptor per file - mind RLIMIT_NOFILE.
/// </summary>
public sealed class AssetCache : IDisposable
{
    /// <summary>A pre-opened file: its descriptor, absolute path, and length at snapshot time.</summary>
    public readonly record struct Asset(int Fd, string Path, long Length);

    private readonly Dictionary<string, Asset> _assets;
    private readonly SafeFileHandle[] _handles;
    private const long LiveRef = 1L << 48;   // extra releases or leaked leases need years at 1M/s to drain or overflow it
    private long _refs = LiveRef;   // plus one per lease

    /// <summary>The absolute root directory the cache was built over.</summary>
    public string RootDir { get; }

    /// <summary>How many files were opened.</summary>
    public int Count => _assets.Count;

    public AssetCache(string rootDir)
    {
        RootDir = Path.GetFullPath(rootDir);

        if (!Directory.Exists(RootDir))
        {
            throw new DirectoryNotFoundException(RootDir);
        }

        _assets = new Dictionary<string, Asset>(StringComparer.Ordinal);
        var handles = new List<SafeFileHandle>();

        // Open every file under the root, keyed by its URL path relative to the root. The managed
        // handle is held for the cache's lifetime so the raw fd stays valid.
        //
        // Skip symlinks (files and directories): a symlink could resolve outside the root, so not
        // following them blocks traversal/escape. With RecurseSubdirectories, a skipped (symlinked)
        // directory is also not descended into.
        var walk = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            AttributesToSkip = FileAttributes.ReparsePoint | FileAttributes.Hidden | FileAttributes.System,
        };
        foreach (string path in Directory.EnumerateFiles(RootDir, "*", walk))
        {
            SafeFileHandle handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            handles.Add(handle);

            int fd = (int)handle.DangerousGetHandle();
            string key = "/" + Path.GetRelativePath(RootDir, path).Replace('\\', '/');

            _assets[key] = new Asset(fd, path, RandomAccess.GetLength(handle));
        }

        _handles = handles.ToArray();
    }

    /// <summary>Look up a pre-opened asset by URL path; false if there's no such file.</summary>
    public bool TryGet(string urlPath, out Asset asset) => _assets.TryGetValue(urlPath, out asset);

    /// <summary>
    /// Span-based lookup for the hot path - resolves the request target straight from the recv
    /// buffer, with no per-request string allocation.
    /// </summary>
    public bool TryGet(ReadOnlySpan<byte> urlPath, out Asset asset)
    {
        if (urlPath.Length is 0 or > 1024)
        {
            asset = default;
            return false;
        }

        Span<char> chars = stackalloc char[urlPath.Length];
        if (Ascii.ToUtf16(urlPath, chars, out int written) != OperationStatus.Done)
        {
            asset = default;
            return false;   // keys are ASCII URL paths; anything else can't match
        }

        return _assets.GetAlternateLookup<ReadOnlySpan<char>>().TryGetValue(chars[..written], out asset);
    }

    /// <summary>
    /// Take a reference so this snapshot can't be freed while it's in use; false if it's already
    /// being torn down (the caller should re-read the live snapshot). Pair with <see cref="Release"/>.
    /// </summary>
    internal bool TryAddRef()
    {
        long r;
        do
        {
            r = Volatile.Read(ref _refs);
            if (r <= 0)
            {
                return false;   // freed, or below zero after a second Dispose - don't resurrect
            }
        }
        while (Interlocked.CompareExchange(ref _refs, r + 1, r) != r);
        return true;
    }

    /// <summary>Drop a reference; the snapshot is freed when the last one goes.</summary>
    internal void Release()
    {
        if (Interlocked.Decrement(ref _refs) == 0)
        {
            DisposeCore();   // runs once: TryAddRef never lifts a count back off zero
        }
    }

    /// <summary>Drops the "live" reference; the snapshot frees once all outstanding leases release too.</summary>
    public void Dispose()
    {
        if (Interlocked.Add(ref _refs, -LiveRef) == 0)
        {
            DisposeCore();
        }
    }

    private void DisposeCore()
    {
        foreach (SafeFileHandle handle in _handles)
        {
            handle.Dispose();
        }

        _assets.Clear();
    }
}
