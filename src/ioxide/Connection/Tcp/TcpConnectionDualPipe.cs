using System.IO.Pipelines;

namespace ioxide;

public sealed class TcpConnectionDualPipe : ITcpConnectionPipe
{
    public PipeReader Input { get; }
    public PipeWriter Output { get; }
    public TcpConnection Connection { get; }

    public TcpConnectionDualPipe(TcpConnection connection)
    {
        ArgumentNullException.ThrowIfNull(connection);
        Connection = connection;
        Input = new TcpConnectionPipeReader(connection);
        Output = new TcpConnectionPipeWriter(connection);
    }
}
