namespace Shared.Crypto;

/// <summary>
/// Convenience wrapper for generating and working with Ed25519 key pairs.
/// </summary>
public sealed class Ed25519KeyPair : IDisposable
{
    private readonly Ed25519PrivateKey _privateKey;
    private readonly Ed25519PublicKey _publicKey;
    private bool _disposed;

    private Ed25519KeyPair(Ed25519PrivateKey privateKey, Ed25519PublicKey publicKey)
    {
        _privateKey = privateKey;
        _publicKey = publicKey;
    }

    /// <summary>
    /// Generates a new random Ed25519 key pair.
    /// </summary>
    public static Ed25519KeyPair Generate()
    {
        var privateKey = Ed25519PrivateKey.Generate();
        var publicKey = privateKey.GetPublicKey();
        return new Ed25519KeyPair(privateKey, publicKey);
    }

    /// <summary>
    /// Loads a key pair from a private key.
    /// </summary>
    public static Ed25519KeyPair FromPrivateKey(Ed25519PrivateKey privateKey)
    {
        var publicKey = privateKey.GetPublicKey();
        return new Ed25519KeyPair(privateKey, publicKey);
    }

    /// <summary>
    /// Loads a key pair from raw private key bytes.
    /// </summary>
    public static Ed25519KeyPair FromPrivateKeyBytes(ReadOnlySpan<byte> seed)
    {
        var privateKey = Ed25519PrivateKey.FromBytes(seed);
        var publicKey = privateKey.GetPublicKey();
        return new Ed25519KeyPair(privateKey, publicKey);
    }

    /// <summary>
    /// The public key (safe to share).
    /// </summary>
    public Ed25519PublicKey PublicKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _publicKey;
        }
    }

    /// <summary>
    /// The private key (keep secret).
    /// </summary>
    public Ed25519PrivateKey PrivateKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _privateKey;
        }
    }

    /// <summary>
    /// Signs data with the private key.
    /// </summary>
    public Ed25519Signature Sign(ReadOnlySpan<byte> data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _privateKey.Sign(data);
    }

    /// <summary>
    /// Verifies a signature with the public key.
    /// </summary>
    public bool Verify(ReadOnlySpan<byte> data, Ed25519Signature signature)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _publicKey.Verify(data, signature);
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _privateKey.Dispose();
            _disposed = true;
        }
    }
}
