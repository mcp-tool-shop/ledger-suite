namespace CreatorLedger.Domain.Primitives;

/// <summary>
/// Unique identifier for a ledger event.
/// </summary>
public readonly struct EventId : IEquatable<EventId>
{
    private readonly Guid _value;

    private EventId(Guid value)
    {
        if (value == Guid.Empty)
            throw new DomainException("EventId cannot be empty");
        _value = value;
    }

    /// <summary>
    /// Creates a new unique EventId.
    /// </summary>
    public static EventId New() => new(Guid.NewGuid());

    /// <summary>
    /// Parses an EventId from its string representation.
    /// </summary>
    public static EventId Parse(string value)
    {
        if (!TryParse(value, out var result))
            throw new FormatException($"Invalid EventId: {value}");
        return result;
    }

    /// <summary>
    /// Tries to parse an EventId from its string representation.
    /// </summary>
    public static bool TryParse(string? value, out EventId result)
    {
        result = default;

        if (string.IsNullOrWhiteSpace(value))
            return false;

        if (!Guid.TryParse(value, out var guid) || guid == Guid.Empty)
            return false;

        result = new EventId(guid);
        return true;
    }

    /// <summary>
    /// Creates an EventId from an existing Guid.
    /// </summary>
    public static EventId FromGuid(Guid guid) => new(guid);

    /// <summary>
    /// Returns the underlying Guid value.
    /// </summary>
    public Guid ToGuid() => _value;

    public override string ToString() => _value.ToString("D");

    public bool Equals(EventId other) => _value == other._value;

    public override bool Equals(object? obj) => obj is EventId other && Equals(other);

    public override int GetHashCode() => _value.GetHashCode();

    public static bool operator ==(EventId left, EventId right) => left.Equals(right);

    public static bool operator !=(EventId left, EventId right) => !left.Equals(right);
}
