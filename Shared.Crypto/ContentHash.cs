using System.Security.Cryptography;

namespace Shared.Crypto;

/// <summary>
/// SHA-256 hash of asset content bytes.
/// Semantically distinct from <see cref="Digest256"/> which is used for event chains.
/// </summary>
public readonly struct ContentHash : IEquatable<ContentHash>, IComparable<ContentHash>
{
    public const int ByteLength = 32;

    private readonly byte[] _bytes;

    private ContentHash(byte[] bytes)
    {
        if (bytes.Length != ByteLength)
            throw new ArgumentException($"ContentHash must be exactly {ByteLength} bytes", nameof(bytes));

        _bytes = bytes;
    }

    /// <summary>
    /// Computes the SHA-256 hash of the given content.
    /// </summary>
    public static ContentHash Compute(ReadOnlySpan<byte> content)
    {
        var hash = new byte[ByteLength];
        SHA256.HashData(content, hash);
        return new ContentHash(hash);
    }

    /// <summary>
    /// Computes the SHA-256 hash of content from a stream.
    /// </summary>
    public static ContentHash Compute(Stream stream)
    {
        var hash = SHA256.HashData(stream);
        return new ContentHash(hash);
    }

    /// <summary>
    /// Parses a lowercase hex string into a ContentHash.
    /// </summary>
    public static ContentHash Parse(string hex)
    {
        if (!TryParse(hex, out var result))
            throw new FormatException($"Invalid ContentHash hex string: {hex}");
        return result;
    }

    /// <summary>
    /// Tries to parse a lowercase hex string into a ContentHash.
    /// </summary>
    public static bool TryParse(string? hex, out ContentHash result)
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

        result = new ContentHash(bytes);
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
    /// Returns the raw 32-byte hash.
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

    public bool Equals(ContentHash other)
    {
        if (_bytes is null && other._bytes is null)
            return true;
        if (_bytes is null || other._bytes is null)
            return false;
        return _bytes.AsSpan().SequenceEqual(other._bytes);
    }

    public override bool Equals(object? obj) => obj is ContentHash other && Equals(other);

    public override int GetHashCode()
    {
        if (_bytes is null || _bytes.Length < 4)
            return 0;
        return BitConverter.ToInt32(_bytes, 0);
    }

    public int CompareTo(ContentHash other)
    {
        var a = _bytes ?? [];
        var b = other._bytes ?? [];
        return a.AsSpan().SequenceCompareTo(b);
    }

    public static bool operator ==(ContentHash left, ContentHash right) => left.Equals(right);
    public static bool operator !=(ContentHash left, ContentHash right) => !left.Equals(right);
    public static bool operator <(ContentHash left, ContentHash right) => left.CompareTo(right) < 0;
    public static bool operator >(ContentHash left, ContentHash right) => left.CompareTo(right) > 0;
    public static bool operator <=(ContentHash left, ContentHash right) => left.CompareTo(right) <= 0;
    public static bool operator >=(ContentHash left, ContentHash right) => left.CompareTo(right) >= 0;
}
