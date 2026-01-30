using NSec.Cryptography;

namespace Shared.Crypto;

/// <summary>
/// Ed25519 public key for signature verification.
/// </summary>
public sealed class Ed25519PublicKey : IEquatable<Ed25519PublicKey>
{
    public const int ByteLength = 32;
    public const string Prefix = "ed25519:";

    private readonly byte[] _bytes;

    private Ed25519PublicKey(byte[] bytes)
    {
        if (bytes.Length != ByteLength)
            throw new ArgumentException($"Ed25519 public key must be exactly {ByteLength} bytes", nameof(bytes));

        _bytes = bytes;
    }

    internal static Ed25519PublicKey FromNSec(PublicKey key)
    {
        return new Ed25519PublicKey(key.Export(KeyBlobFormat.RawPublicKey));
    }

    /// <summary>
    /// Parses a public key from the wire format: "ed25519:&lt;base64&gt;"
    /// </summary>
    public static Ed25519PublicKey Parse(string encoded)
    {
        if (!TryParse(encoded, out var result) || result is null)
            throw new FormatException($"Invalid Ed25519 public key format: {encoded}");
        return result;
    }

    /// <summary>
    /// Tries to parse a public key from the wire format: "ed25519:&lt;base64&gt;"
    /// </summary>
    public static bool TryParse(string? encoded, out Ed25519PublicKey? result)
    {
        result = null;

        if (string.IsNullOrEmpty(encoded) || !encoded.StartsWith(Prefix, StringComparison.Ordinal))
            return false;

        try
        {
            var base64 = encoded[Prefix.Length..];
            var bytes = Convert.FromBase64String(base64);

            if (bytes.Length != ByteLength)
                return false;

            result = new Ed25519PublicKey(bytes);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>
    /// Creates a public key from raw bytes.
    /// </summary>
    public static Ed25519PublicKey FromBytes(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != ByteLength)
            throw new ArgumentException($"Ed25519 public key must be exactly {ByteLength} bytes", nameof(bytes));

        return new Ed25519PublicKey(bytes.ToArray());
    }

    /// <summary>
    /// Returns the raw 32-byte public key.
    /// </summary>
    public ReadOnlySpan<byte> AsBytes() => _bytes;

    /// <summary>
    /// Verifies a signature against this public key.
    /// </summary>
    public bool Verify(ReadOnlySpan<byte> data, Ed25519Signature signature)
    {
        var algorithm = SignatureAlgorithm.Ed25519;

        if (!PublicKey.TryImport(algorithm, _bytes, KeyBlobFormat.RawPublicKey, out var nsecKey) || nsecKey is null)
            return false;

        return algorithm.Verify(nsecKey, data, signature.AsBytes());
    }

    /// <summary>
    /// Returns the wire format: "ed25519:&lt;base64&gt;"
    /// </summary>
    public override string ToString()
    {
        return Prefix + Convert.ToBase64String(_bytes);
    }

    public bool Equals(Ed25519PublicKey? other)
    {
        if (other is null)
            return false;
        return _bytes.AsSpan().SequenceEqual(other._bytes);
    }

    public override bool Equals(object? obj) => obj is Ed25519PublicKey other && Equals(other);

    public override int GetHashCode()
    {
        if (_bytes.Length < 4)
            return 0;
        return BitConverter.ToInt32(_bytes, 0);
    }

    public static bool operator ==(Ed25519PublicKey? left, Ed25519PublicKey? right)
    {
        if (left is null)
            return right is null;
        return left.Equals(right);
    }

    public static bool operator !=(Ed25519PublicKey? left, Ed25519PublicKey? right) => !(left == right);
}
