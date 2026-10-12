using System.Security.Cryptography;
using System.Text;

namespace ioxide.pg;

/// <summary>
/// SCRAM-SHA-256 client (RFC 7677, no channel binding) - the auth method the official postgres
/// images use when a password is set. Pure computation; the connection drives the message
/// exchange.
/// </summary>
internal sealed class PgScram
{
    // PBKDF2 runs on the reactor thread, so the server's count is how long the reactor stops: about 0.2 s here.
    private const int MaxIterations = 1_000_000;

    private readonly string _password;
    private readonly string _clientNonce;
    private string _clientFirstBare = "";
    private string _serverFirst = "";
    private byte[] _saltedPassword = [];

    public PgScram(string password)
    {
        _password = password;
        _clientNonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(18));
    }

    /// <summary>client-first-message, sent inside SASLInitialResponse.</summary>
    public string ClientFirst()
    {
        _clientFirstBare = $"n=,r={_clientNonce}";
        return "n,," + _clientFirstBare;   // gs2 header: no channel binding
    }

    /// <summary>Consume server-first-message, produce client-final-message (with proof).</summary>
    public string ClientFinal(string serverFirst)
    {
        _serverFirst = serverFirst;

        string? serverNonce = null, saltB64 = null;
        int iterations = 0;
        foreach (string part in serverFirst.Split(','))
        {
            if (part.StartsWith("r=")) serverNonce = part[2..];
            else if (part.StartsWith("s=")) saltB64 = part[2..];
            else if (part.StartsWith("i=")) iterations = int.Parse(part[2..]);
        }

        if (serverNonce == null || saltB64 == null || iterations <= 0)
            throw new PgException("SCRAM: malformed server-first message");
        if (iterations > MaxIterations)
            throw new PgException($"SCRAM: the server asks for {iterations} iterations, more than the {MaxIterations} this client allows");
        if (!serverNonce.StartsWith(_clientNonce))
            throw new PgException("SCRAM: server nonce does not extend the client nonce");

        _saltedPassword = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(_password),
            Convert.FromBase64String(saltB64),
            iterations,
            HashAlgorithmName.SHA256,
            32);

        string clientFinalNoProof = $"c=biws,r={serverNonce}";   // biws = base64("n,,")
        string authMessage = $"{_clientFirstBare},{_serverFirst},{clientFinalNoProof}";

        byte[] clientKey = HMACSHA256.HashData(_saltedPassword, "Client Key"u8.ToArray());
        byte[] storedKey = SHA256.HashData(clientKey);
        byte[] clientSignature = HMACSHA256.HashData(storedKey, Encoding.UTF8.GetBytes(authMessage));

        var proof = new byte[32];
        for (int i = 0; i < 32; i++)
        {
            proof[i] = (byte)(clientKey[i] ^ clientSignature[i]);
        }

        _authMessage = authMessage;
        return $"{clientFinalNoProof},p={Convert.ToBase64String(proof)}";
    }

    private string _authMessage = "";

    /// <summary>Verify the server signature from AuthenticationSASLFinal ("v=...").</summary>
    public void VerifyServerFinal(string serverFinal)
    {
        string? v = null;
        foreach (string part in serverFinal.Split(','))
        {
            if (part.StartsWith("v=")) v = part[2..];
        }
        if (v == null)
            throw new PgException("SCRAM: server-final missing verifier");

        byte[] serverKey = HMACSHA256.HashData(_saltedPassword, "Server Key"u8.ToArray());
        byte[] expected = HMACSHA256.HashData(serverKey, Encoding.UTF8.GetBytes(_authMessage));

        if (!CryptographicOperations.FixedTimeEquals(expected, Convert.FromBase64String(v)))
            throw new PgException("SCRAM: server signature verification failed");
    }
}
