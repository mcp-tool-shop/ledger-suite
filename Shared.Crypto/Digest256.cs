using System.Security.Cryptography;

namespace Shared.Crypto;

/// <summary>
/// Generic SHA-256 digest for event chains, ledger roots, and other non-content hashing.
/// Semantically distinct from <see cref="ContentHash"/> which is specifically for asset content.
/// </summary>
public readonly struct Digest256 : IEquatable<Digest256>, IComparable<Digest256>
{
    public const int ByteLength = 32;

    private readonly byte[] _bytes;

    private Digest256(byte[] bytes)
    {
        if (bytes.Length != ByteLength)
            throw new ArgumentException($"Digest256 must be exactly {ByteLength} bytes", nameof(bytes));

        _bytes = bytes;
    }

    /// <summary>
    /// The zero digest, used as the initial "previous hash" in a chain.
    /// </summary>
    public static Digest256 Zero => new(new byte[ByteLength]);

    /// <summary>
    /// Computes the SHA-256 digest of the given data.
    /// </summary>
    public static Digest256 Compute(ReadOnlySpan<byte> data)
    {
        var hash = new byte[ByteLength];
        SHA256.HashData(data, hash);
        return new Digest256(hash);
    }

    /// <summary>
    /// Computes the SHA-256 digest of UTF-8 encoded text.
    /// Useful for hashing canonical JSON.
    /// </summary>
    public static Digest256 ComputeUtf8(string text)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(text);
        return Compute(bytes);
    }

    /// <summary>
    /// Parses a lowercase hex string into a Digest256.
    /// </summary>
    public static Digest256 Parse(string hex)
    {
        if (!TryParse(hex, out var result))
            throw new FormatException($"Invalid Digest256 hex string: {hex}");
        return result;
    }

    /// <summary>
    /// Tries to parse a hex string into a Digest256.
    /// </summary>
    public static bool TryParse(string? hex, out Digest256 result)
    {
        result = default;

        if (string.IsNullOrEmpty(hex) || hex.Length != ByteLength * 2)
            return false;

        var bytes = new byte[ByteLength];

        for (int i = 0; i < ByteLength; i++)
        {
            if (!TryParseHexByte(hex.AsSpan(i * 2, 2), out bytes[i]))
                return false;
        }

        result = new Digest256(bytes);
        return true;
    }

    private static bool TryParseHexByte(ReadOnlySpan<char> hex, out byte value)
    {
        value = 0;
        if (hex.Length != 2)
            return false;

        if (!TryParseHexNibble(hex[0], out var high) || !TryParseHexNibble(hex[1], out var low))
            return false;

        value = (byte)((high << 4) | low);
        return true;
    }

    private static bool TryParseHexNibble(char c, out int value)
    {
        if (c >= '0' && c <= '9')
        {
            value = c - '0';
            return true;
        }
        if (c >= 'a' && c <= 'f')
        {
            value = c - 'a' + 10;
            return true;
        }
        if (c >= 'A' && c <= 'F')
        {
            value = c - 'A' + 10;
            return true;
        }
        value = 0;
        return false;
    }

    /// <summary>
    /// Creates a Digest256 from raw bytes.
    /// </summary>
    public static Digest256 FromBytes(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != ByteLength)
            throw new ArgumentException($"Digest256 must be exactly {ByteLength} bytes", nameof(bytes));

        return new Digest256(bytes.ToArray());
    }

    /// <summary>
    /// Returns the raw 32-byte digest.
    /// </summary>
    public ReadOnlySpan<byte> AsBytes() => _bytes ?? [];

    /// <summary>
    /// Returns the canonical lowercase hex representation.
    /// </summary>
    public override string ToString()
    {
        if (_bytes is null)
            return new string('0', ByteLength * 2);

        return Convert.ToHexString(_bytes).ToLowerInvariant();
    }

    public bool Equals(Digest256 other)
    {
        if (_bytes is null && other._bytes is null)
            return true;
        if (_bytes is null || other._bytes is null)
            return false;
        return _bytes.AsSpan().SequenceEqual(other._bytes);
    }

    public override bool Equals(object? obj) => obj is Digest256 other && Equals(other);

    public override int GetHashCode()
    {
        if (_bytes is null || _bytes.Length < 4)
            return 0;
        return BitConverter.ToInt32(_bytes, 0);
    }

    public int CompareTo(Digest256 other)
    {
        var a = _bytes ?? [];
        var b = other._bytes ?? [];
        return a.AsSpan().SequenceCompareTo(b);
    }

    public static bool operator ==(Digest256 left, Digest256 right) => left.Equals(right);
    public static bool operator !=(Digest256 left, Digest256 right) => !left.Equals(right);
    public static bool operator <(Digest256 left, Digest256 right) => left.CompareTo(right) < 0;
    public static bool operator >(Digest256 left, Digest256 right) => left.CompareTo(right) > 0;
    public static bool operator <=(Digest256 left, Digest256 right) => left.CompareTo(right) <= 0;
    public static bool operator >=(Digest256 left, Digest256 right) => left.CompareTo(right) >= 0;
}
