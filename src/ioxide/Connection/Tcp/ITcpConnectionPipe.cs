using System.IO.Pipelines;

namespace ioxide;

/// <summary>A duplex pipe that names its connection, e.g. so HTTP/2 can suspend its read timeout.</summary>
public interface ITcpConnectionPipe : IDuplexPipe
{
    TcpConnection Connection { get; }
}
