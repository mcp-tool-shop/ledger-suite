namespace CreatorLedger.Domain.Primitives;

/// <summary>
/// Unique identifier for an attestation.
/// </summary>
public readonly struct AttestationId : IEquatable<AttestationId>
{
    private readonly Guid _value;

    private AttestationId(Guid value)
    {
        if (value == Guid.Empty)
            throw new DomainException("AttestationId cannot be empty");
        _value = value;
    }

    /// <summary>
    /// Creates a new unique AttestationId.
    /// </summary>
    public static AttestationId New() => new(Guid.NewGuid());

    /// <summary>
    /// Parses an AttestationId from its string representation.
    /// </summary>
    public static AttestationId Parse(string value)
    {
        if (!TryParse(value, out var result))
            throw new FormatException($"Invalid AttestationId: {value}");
        return result;
    }

    /// <summary>
    /// Tries to parse an AttestationId from its string representation.
    /// </summary>
    public static bool TryParse(string? value, out AttestationId result)
    {
        result = default;

        if (string.IsNullOrWhiteSpace(value))
            return false;

        if (!Guid.TryParse(value, out var guid) || guid == Guid.Empty)
            return false;

        result = new AttestationId(guid);
        return true;
    }

    /// <summary>
    /// Creates an AttestationId from an existing Guid.
    /// </summary>
    public static AttestationId FromGuid(Guid guid) => new(guid);

    /// <summary>
    /// Returns the underlying Guid value.
    /// </summary>
    public Guid ToGuid() => _value;

    public override string ToString() => _value.ToString("D");

    public bool Equals(AttestationId other) => _value == other._value;

    public override bool Equals(object? obj) => obj is AttestationId other && Equals(other);

    public override int GetHashCode() => _value.GetHashCode();

    public static bool operator ==(AttestationId left, AttestationId right) => left.Equals(right);

    public static bool operator !=(AttestationId left, AttestationId right) => !left.Equals(right);
}
