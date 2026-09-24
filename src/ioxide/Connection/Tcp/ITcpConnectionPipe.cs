using System.IO.Pipelines;

namespace ioxide;

/// <summary>
/// A duplex pipe over one accepted <see cref="TcpConnection"/>. A protocol layer handed only the
/// pipe reaches the connection through this - to suspend its read timeout while it owes a
/// response, for one (see <see cref="TcpConnection.SuspendReadTimeout"/>).
/// </summary>
public interface ITcpConnectionPipe : IDuplexPipe
{
    /// <summary>The connection the pipe reads from and writes to.</summary>
    TcpConnection Connection { get; }
}
