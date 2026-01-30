namespace CreatorLedger.Domain.Primitives;

/// <summary>
/// Unique identifier for an asset.
/// </summary>
public readonly struct AssetId : IEquatable<AssetId>
{
    private readonly Guid _value;

    private AssetId(Guid value)
    {
        if (value == Guid.Empty)
            throw new DomainException("AssetId cannot be empty");
        _value = value;
    }

    /// <summary>
    /// Creates a new unique AssetId.
    /// </summary>
    public static AssetId New() => new(Guid.NewGuid());

    /// <summary>
    /// Parses an AssetId from its string representation.
    /// </summary>
    public static AssetId Parse(string value)
    {
        if (!TryParse(value, out var result))
            throw new FormatException($"Invalid AssetId: {value}");
        return result;
    }

    /// <summary>
    /// Tries to parse an AssetId from its string representation.
    /// </summary>
    public static bool TryParse(string? value, out AssetId result)
    {
        result = default;

        if (string.IsNullOrWhiteSpace(value))
            return false;

        if (!Guid.TryParse(value, out var guid) || guid == Guid.Empty)
            return false;

        result = new AssetId(guid);
        return true;
    }

    /// <summary>
    /// Creates an AssetId from an existing Guid.
    /// </summary>
    public static AssetId FromGuid(Guid guid) => new(guid);

    /// <summary>
    /// Returns the underlying Guid value.
    /// </summary>
    public Guid ToGuid() => _value;

    public override string ToString() => _value.ToString("D");

    public bool Equals(AssetId other) => _value == other._value;

    public override bool Equals(object? obj) => obj is AssetId other && Equals(other);

    public override int GetHashCode() => _value.GetHashCode();

    public static bool operator ==(AssetId left, AssetId right) => left.Equals(right);

    public static bool operator !=(AssetId left, AssetId right) => !left.Equals(right);
}
