namespace Shared.Crypto;

/// <summary>
/// Ed25519 signature (64 bytes).
/// </summary>
public readonly struct Ed25519Signature : IEquatable<Ed25519Signature>
{
    public const int ByteLength = 64;

    private readonly byte[] _bytes;

    private Ed25519Signature(byte[] bytes)
    {
        if (bytes.Length != ByteLength)
            throw new ArgumentException($"Ed25519 signature must be exactly {ByteLength} bytes", nameof(bytes));

        _bytes = bytes;
    }

    /// <summary>
    /// Creates a signature from raw bytes.
    /// </summary>
    public static Ed25519Signature FromBytes(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != ByteLength)
            throw new ArgumentException($"Ed25519 signature must be exactly {ByteLength} bytes", nameof(bytes));

        return new Ed25519Signature(bytes.ToArray());
    }

    /// <summary>
    /// Parses a signature from base64.
    /// </summary>
    public static Ed25519Signature Parse(string base64)
    {
        if (!TryParse(base64, out var result))
            throw new FormatException($"Invalid Ed25519 signature format: {base64}");
        return result;
    }

    /// <summary>
    /// Tries to parse a signature from base64.
    /// </summary>
    public static bool TryParse(string? base64, out Ed25519Signature result)
    {
        result = default;

        if (string.IsNullOrEmpty(base64))
            return false;

        try
        {
            var bytes = Convert.FromBase64String(base64);

            if (bytes.Length != ByteLength)
                return false;

            result = new Ed25519Signature(bytes);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>
    /// Returns the raw 64-byte signature.
    /// </summary>
    public ReadOnlySpan<byte> AsBytes() => _bytes ?? [];

    /// <summary>
    /// Returns the base64 representation.
    /// </summary>
    public override string ToString()
    {
        if (_bytes is null)
            return string.Empty;

        return Convert.ToBase64String(_bytes);
    }

    public bool Equals(Ed25519Signature other)
    {
        if (_bytes is null && other._bytes is null)
            return true;
        if (_bytes is null || other._bytes is null)
            return false;
        return _bytes.AsSpan().SequenceEqual(other._bytes);
    }

    public override bool Equals(object? obj) => obj is Ed25519Signature other && Equals(other);

    public override int GetHashCode()
    {
        if (_bytes is null || _bytes.Length < 4)
            return 0;
        return BitConverter.ToInt32(_bytes, 0);
    }

    public static bool operator ==(Ed25519Signature left, Ed25519Signature right) => left.Equals(right);
    public static bool operator !=(Ed25519Signature left, Ed25519Signature right) => !left.Equals(right);
}
