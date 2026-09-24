using System.IO.Pipelines;

namespace ioxide;

public sealed class TcpConnectionDualPipe : IDuplexPipe
{
    public PipeReader Input { get; }
    public PipeWriter Output { get; }

    public TcpConnectionDualPipe(TcpConnection connection)
    {
        ArgumentNullException.ThrowIfNull(connection);
        Input = new TcpConnectionPipeReader(connection);
        Output = new TcpConnectionPipeWriter(connection);
    }
}
