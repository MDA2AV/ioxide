namespace ioxide.file;

/// <summary>
/// A reloadable holder around an <see cref="AssetCache"/>: <see cref="Reload"/> builds a fresh
/// snapshot, swaps it atomically, and releases the old one. Handlers always see a whole snapshot,
/// never a mix. Call after a deploy (e.g. SIGHUP).
/// </summary>
/// <remarks>
/// To serve safely across a reload, take a <see cref="Lease"/> with <see cref="Acquire"/> and hold
/// it for the whole request (lookup → ring read → send), and dispose it once: the old snapshot's
/// descriptors are freed only once every lease on it is released, so an in-flight read never hits a
/// closed fd. After <see cref="Dispose"/>, <see cref="Acquire"/> throws and <see cref="Reload"/> does
/// nothing; leases already out keep the last snapshot open until they are released.
/// </remarks>
public sealed class StaticAssets : IDisposable
{
    private readonly string _root;
    private readonly object _reloadLock = new();

    private AssetCache? _cache;   // swapped atomically by Reload(), read with Volatile; null once disposed

    public StaticAssets(string rootDir)
    {
        _root = rootDir;
        _cache = new AssetCache(rootDir);
    }

    public int Count => Live.Count;

    public string RootDir => Live.RootDir;

    private AssetCache Live => Volatile.Read(ref _cache) ?? throw new ObjectDisposedException(nameof(StaticAssets));

    /// <summary>
    /// Lease the live snapshot for the duration of a request. The snapshot it points at stays alive
    /// (descriptors open) until the lease is disposed, even across a concurrent <see cref="Reload"/>,
    /// as long as every lease is disposed once. Dispose it when the response has been fully sent.
    /// </summary>
    /// <exception cref="ObjectDisposedException">This was disposed.</exception>
    public Lease Acquire()
    {
        while (true)
        {
            AssetCache? cache = Volatile.Read(ref _cache);
            ObjectDisposedException.ThrowIf(cache is null, this);
            if (cache.TryAddRef())
            {
                return new Lease(cache);
            }

            // A Reload swaps before it releases, so only the snapshot still live can refuse for good.
            ObjectDisposedException.ThrowIf(cache == Volatile.Read(ref _cache), this);
        }
    }

    /// <summary>
    /// Rebuild the snapshot from disk and swap it in atomically, then release the old one (it frees
    /// once all leases on it are dropped). If the rebuild fails, the current snapshot is kept. After
    /// <see cref="Dispose"/> it does nothing, so a reload signalled during shutdown cannot bring the
    /// assets back. Thread-safe.
    /// </summary>
    public void Reload()
    {
        lock (_reloadLock)
        {
            if (_cache is null)
            {
                return;
            }

            AssetCache fresh;
            try
            {
                fresh = new AssetCache(_root);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"[ioxide] asset reload failed, keeping current snapshot: {e.Message}");
                return;
            }

            AssetCache old = Interlocked.Exchange(ref _cache, fresh)!;
            old.Dispose();   // drops the live reference; old frees when outstanding leases release
        }
    }

    /// <summary>
    /// Drop the live snapshot, which frees once the leases on it are released. Idempotent; under the reload lock,
    /// so a reload in progress finishes first and its snapshot is the one dropped.
    /// </summary>
    public void Dispose()
    {
        lock (_reloadLock)
        {
            Interlocked.Exchange(ref _cache, null)?.Dispose();
        }
    }

    /// <summary>
    /// A reference-counted hold on an <see cref="AssetCache"/> snapshot. Look up assets through it
    /// and dispose it once the response is fully sent. Reactor-thread usage is single-owner, but the
    /// underlying refcount is thread-safe against a concurrent <see cref="Reload"/>.
    /// </summary>
    public readonly struct Lease : IDisposable
    {
        private readonly AssetCache _cache;

        internal Lease(AssetCache cache) => _cache = cache;

        /// <summary>Look up a pre-opened asset by URL path.</summary>
        public bool TryGet(string urlPath, out AssetCache.Asset asset) => _cache.TryGet(urlPath, out asset);

        /// <summary>Span-based lookup straight from the recv buffer - no per-request string.</summary>
        public bool TryGet(ReadOnlySpan<byte> urlPath, out AssetCache.Asset asset) => _cache.TryGet(urlPath, out asset);

        public void Dispose() => _cache.Release();
    }
}
