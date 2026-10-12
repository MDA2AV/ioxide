using System.Net;
using System.Net.Sockets;

namespace Ioxide.Tests;

/// <summary>
/// A loopback server that misbehaves on purpose, for the far end of a protocol client: each
/// connection it accepts runs a script on a thread of its own, which speaks just enough of the
/// protocol and then sends the offending bytes or goes silent. Disposing it closes the listener
/// and every connection it accepted.
/// </summary>
public sealed class FakeServer : IDisposable
{
    private readonly Socket _listener;
    private readonly Action<int, Socket> _script;
    private readonly List<Socket> _accepted = [];
    private readonly Lock _lock = new();
    private bool _disposed;

    /// <summary>The port it listens on, on 127.0.0.1.</summary>
    public int Port { get; }

    /// <param name="script">
    /// Run once per accepted connection, with its index (0 for the first) and its socket. A script
    /// that returns leaves the connection open until the server is disposed.
    /// </param>
    public FakeServer(Action<int, Socket> script)
    {
        _script = script;
        _listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        _listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        _listener.Listen(16);
        Port = ((IPEndPoint)_listener.LocalEndPoint!).Port;

        new Thread(AcceptLoop) { IsBackground = true, Name = $"fake-server-{Port}" }.Start();
    }

    /// <summary>Reads exactly <paramref name="count"/> bytes, or throws if the peer closes first.</summary>
    public static byte[] Receive(Socket socket, int count)
    {
        var buffer = new byte[count];
        for (int filled = 0; filled < count;)
        {
            int n = socket.Receive(buffer, filled, count - filled, SocketFlags.None);
            if (n == 0)
            {
                throw new IOException($"the peer closed after {filled} of {count} bytes");
            }

            filled += n;
        }

        return buffer;
    }

    private void AcceptLoop()
    {
        for (int index = 0; ; index++)
        {
            Socket accepted;
            try
            {
                accepted = _listener.Accept();
            }
            catch (Exception)
            {
                return;   // disposed
            }

            lock (_lock)
            {
                if (_disposed)
                {
                    accepted.Dispose();
                    return;
                }

                _accepted.Add(accepted);
            }

            int which = index;
            new Thread(() =>
            {
                try
                {
                    _script(which, accepted);
                }
                catch (Exception)
                {
                    // The client hung up mid-script, or Dispose closed the socket under it.
                }
            })
            { IsBackground = true, Name = $"fake-server-{Port}-{which}" }.Start();
        }
    }

    public void Dispose()
    {
        lock (_lock)
        {
            _disposed = true;
            foreach (Socket socket in _accepted)
            {
                socket.Dispose();
            }

            _accepted.Clear();
        }

        _listener.Dispose();
    }
}
