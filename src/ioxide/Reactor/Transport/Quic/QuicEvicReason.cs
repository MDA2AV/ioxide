namespace ioxide;

/// <summary>Why the transport dropped a connection it was tracking.</summary>
public enum QuicEvictReason
{
    ReadTimeout,
    ReactorShutdown,

    /// <summary>
    /// The connection's own timer threw, so the transport dropped it rather than re-firing the
    /// same fault on every pass. Distinct from the other two because nothing asked for it and the
    /// connection may be in any state - an engine binding should tear down what it holds and not
    /// assume a clean close is possible.
    /// </summary>
    TimerFault,
}
