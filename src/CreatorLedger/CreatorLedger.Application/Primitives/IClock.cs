namespace CreatorLedger.Application.Primitives;

/// <summary>
/// Abstraction for getting current time. Enables deterministic testing.
/// </summary>
public interface IClock
{
    /// <summary>
    /// Gets the current UTC time.
    /// </summary>
    DateTimeOffset UtcNow { get; }
}

/// <summary>
/// System clock implementation that returns actual time.
/// </summary>
public sealed class SystemClock : IClock
{
    public static readonly SystemClock Instance = new();

    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}
