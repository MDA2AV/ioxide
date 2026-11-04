namespace ioxide.file;

/// <summary>
/// A reloadable holder around an <see cref="AssetCache"/>: <see cref="Reload"/> builds a fresh
/// snapshot, swaps it atomically, and releases the old one. Handlers always see a whole snapshot,
/// never a mix. Call after a deploy (e.g. SIGHUP).
/// </summary>
/// <remarks>
/// To serve safely across a reload, take a <see cref="Lease"/> with <see cref="Acquire"/> and hold
/// it for the whole request (lookup → ring read → send): the old snapshot's descriptors are freed
/// only once every lease on it is released, so an in-flight read can never hit a closed fd.
/// </remarks>
public sealed class StaticAssets : IDisposable
{
    private readonly string _root;
    private readonly object _reloadLock = new();

    private AssetCache _cache;   // swapped atomically by Reload(), read with Volatile

    public StaticAssets(string rootDir)
    {
        _root = rootDir;
        _cache = new AssetCache(rootDir);
    }

    public int Count => Volatile.Read(ref _cache).Count;

    public string RootDir => Volatile.Read(ref _cache).RootDir;

    /// <summary>
    /// Lease the live snapshot for the duration of a request. The snapshot it points at stays alive
    /// (descriptors open) until the lease is disposed, even across a concurrent <see cref="Reload"/>.
    /// Dispose it when the response has been fully sent.
    /// </summary>
    /// <exception cref="ObjectDisposedException">This was disposed and its snapshot freed.</exception>
    public Lease Acquire()
    {
        while (true)
        {
            AssetCache cache = Volatile.Read(ref _cache);
            if (cache.TryAddRef())
            {
                return new Lease(cache);
            }

            // Refused. A Reload swaps the live snapshot before releasing the old one, so a refusal from the
            // one still live means Dispose freed it and nothing will replace it; otherwise re-read the live one.
            ObjectDisposedException.ThrowIf(cache == Volatile.Read(ref _cache), this);
        }
    }

    /// <summary>
    /// Rebuild the snapshot from disk and swap it in atomically, then release the old one (it frees
    /// once all leases on it are dropped). If the rebuild fails, the current snapshot is kept.
    /// Thread-safe.
    /// </summary>
    public void Reload()
    {
        lock (_reloadLock)
        {
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

            AssetCache old = Interlocked.Exchange(ref _cache, fresh);
            old.Dispose();   // drops the live reference; old frees when outstanding leases release
        }
    }

    public void Dispose() => Volatile.Read(ref _cache).Dispose();

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
