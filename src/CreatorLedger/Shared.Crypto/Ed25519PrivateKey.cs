using NSec.Cryptography;
using System.Security.Cryptography;

namespace Shared.Crypto;

/// <summary>
/// Ed25519 private key for signing. Handle with care.
/// Does NOT expose ToString() to prevent accidental logging.
/// </summary>
public sealed class Ed25519PrivateKey : IDisposable
{
    public const int ByteLength = 32;

    private byte[]? _seed;
    private bool _disposed;

    private Ed25519PrivateKey(byte[] seed)
    {
        if (seed.Length != ByteLength)
            throw new ArgumentException($"Ed25519 private key seed must be exactly {ByteLength} bytes", nameof(seed));

        _seed = seed;
    }

    /// <summary>
    /// Generates a new random Ed25519 private key.
    /// </summary>
    public static Ed25519PrivateKey Generate()
    {
        var seed = new byte[ByteLength];
        RandomNumberGenerator.Fill(seed);
        return new Ed25519PrivateKey(seed);
    }

    /// <summary>
    /// Creates a private key from raw seed bytes.
    /// </summary>
    public static Ed25519PrivateKey FromBytes(ReadOnlySpan<byte> seed)
    {
        if (seed.Length != ByteLength)
            throw new ArgumentException($"Ed25519 private key seed must be exactly {ByteLength} bytes", nameof(seed));

        return new Ed25519PrivateKey(seed.ToArray());
    }

    /// <summary>
    /// Returns the raw 32-byte seed. Use for secure storage only.
    /// </summary>
    public ReadOnlySpan<byte> AsBytes()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _seed!;
    }

    /// <summary>
    /// Derives the public key from this private key.
    /// </summary>
    public Ed25519PublicKey GetPublicKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var algorithm = SignatureAlgorithm.Ed25519;
        using var key = Key.Import(algorithm, _seed!, KeyBlobFormat.RawPrivateKey);
        return Ed25519PublicKey.FromNSec(key.PublicKey);
    }

    /// <summary>
    /// Signs data with this private key.
    /// </summary>
    public Ed25519Signature Sign(ReadOnlySpan<byte> data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var algorithm = SignatureAlgorithm.Ed25519;
        using var key = Key.Import(algorithm, _seed!, KeyBlobFormat.RawPrivateKey);
        var signature = algorithm.Sign(key, data);
        return Ed25519Signature.FromBytes(signature);
    }

    /// <summary>
    /// Securely clears the private key from memory.
    /// </summary>
    public void Dispose()
    {
        if (!_disposed && _seed is not null)
        {
            CryptographicOperations.ZeroMemory(_seed);
            _seed = null;
            _disposed = true;
        }
    }
}
