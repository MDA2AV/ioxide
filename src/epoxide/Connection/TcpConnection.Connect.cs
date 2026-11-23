using System.Net.Sockets;

namespace epoxide;

/// <summary>
/// An outbound connection's connect: the socket is registered on its reactor with the connect still
/// in progress, and the first writable edge settles it. From then on it is the same connection an
/// accept produces - pipes, streams and TLS work on it unchanged.
/// </summary>
public sealed unsafe partial class TcpConnection
{
    // 1 while a connect is in progress: the next writable edge settles it rather than a flush.
    private int _connecting;
    private TaskCompletionSource<TcpConnection>? _connectResult;

    internal void BeginConnect(TaskCompletionSource<TcpConnection> result)
    {
        _connectResult = result;
        Volatile.Write(ref _connecting, 1);
    }

    // The caller is told some other way; nothing is left for an edge or a close to settle.
    internal void CancelConnect()
    {
        Volatile.Write(ref _connecting, 0);
        _connectResult = null;
    }

    // Writable while connecting: SO_ERROR says how the connect ended. Reactor thread.
    private void OnConnectReady()
    {
        int error = 0;
        uint length = sizeof(int);
        if (Native.getsockopt(ClientFd, Native.SOL_SOCKET, Native.SO_ERROR, &error, &length) < 0)
        {
            error = Native.Errno;
        }

        if (error == 0)
        {
            TaskCompletionSource<TcpConnection>? result = _connectResult;
            _connectResult = null;
            Volatile.Write(ref _connecting, 0);

            // The edge that settled the connect says nothing about a flush: the first one just tries.
            result?.TrySetResult(this);
            return;
        }

        FailConnect(new SocketException((int)Native.ToSocketError(error)));
    }

    // From MarkClosed: the reactor ended a connection whose connect never settled.
    private void FailParkedConnect()
    {
        if (Volatile.Read(ref _connecting) != 0)
        {
            FailConnect(new SocketException((int)SocketError.OperationAborted));
        }
    }

    // Nobody ever received this connection, so the caller's ref is let go here, with the reactor's.
    private void FailConnect(Exception error)
    {
        if (Interlocked.Exchange(ref _connecting, 0) == 0)
        {
            return;
        }

        TaskCompletionSource<TcpConnection>? result = _connectResult;
        _connectResult = null;

        SuppressFin();
        Volatile.Write(ref _closed, 1);
        Interlocked.Exchange(ref _handlerRefReleased, 1);
        ReleaseReactorRef();             // the caller's ref: refcounting does not tell the two apart
        _reactor.CloseFromReactor(this); // the reactor's, unless MarkClosed came from there already

        result?.TrySetException(error);
    }
}
