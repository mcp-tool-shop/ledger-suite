namespace CreatorLedger.Domain.Primitives;

/// <summary>
/// Unique identifier for a creator identity.
/// </summary>
public readonly struct CreatorId : IEquatable<CreatorId>
{
    private readonly Guid _value;

    private CreatorId(Guid value)
    {
        if (value == Guid.Empty)
            throw new DomainException("CreatorId cannot be empty");
        _value = value;
    }

    /// <summary>
    /// Creates a new unique CreatorId.
    /// </summary>
    public static CreatorId New() => new(Guid.NewGuid());

    /// <summary>
    /// Parses a CreatorId from its string representation.
    /// </summary>
    public static CreatorId Parse(string value)
    {
        if (!TryParse(value, out var result))
            throw new FormatException($"Invalid CreatorId: {value}");
        return result;
    }

    /// <summary>
    /// Tries to parse a CreatorId from its string representation.
    /// </summary>
    public static bool TryParse(string? value, out CreatorId result)
    {
        result = default;

        if (string.IsNullOrWhiteSpace(value))
            return false;

        if (!Guid.TryParse(value, out var guid) || guid == Guid.Empty)
            return false;

        result = new CreatorId(guid);
        return true;
    }

    /// <summary>
    /// Creates a CreatorId from an existing Guid.
    /// </summary>
    public static CreatorId FromGuid(Guid guid) => new(guid);

    /// <summary>
    /// Returns the underlying Guid value.
    /// </summary>
    public Guid ToGuid() => _value;

    public override string ToString() => _value.ToString("D");

    public bool Equals(CreatorId other) => _value == other._value;

    public override bool Equals(object? obj) => obj is CreatorId other && Equals(other);

    public override int GetHashCode() => _value.GetHashCode();

    public static bool operator ==(CreatorId left, CreatorId right) => left.Equals(right);

    public static bool operator !=(CreatorId left, CreatorId right) => !left.Equals(right);
}
