using System.IO.Pipelines;

namespace ioxide;

public sealed class TcpConnectionDualPipe : IDuplexPipe
{
    private readonly TcpConnectionPipeReader _input;

    public PipeReader Input => _input;
    public PipeWriter Output { get; }

    public TcpConnectionDualPipe(TcpConnection connection)
    {
        ArgumentNullException.ThrowIfNull(connection);
        _input = new TcpConnectionPipeReader(connection);
        Output = new TcpConnectionPipeWriter(connection);
    }

    /// <summary>
    /// Whether the connection is still in the life this pipe was made for. Connections are pooled: once this is
    /// false, the connection has ended and may already be serving another client.
    /// </summary>
    public bool IsValid() => _input.IsValid();
}
