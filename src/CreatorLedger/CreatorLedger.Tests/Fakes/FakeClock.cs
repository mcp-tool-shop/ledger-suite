using CreatorLedger.Application.Primitives;

namespace CreatorLedger.Tests.Fakes;

/// <summary>
/// Fake clock for deterministic testing.
/// </summary>
public sealed class FakeClock : IClock
{
    private DateTimeOffset _now;

    public FakeClock(DateTimeOffset? initialTime = null)
    {
        _now = initialTime ?? new DateTimeOffset(2024, 6, 15, 12, 0, 0, TimeSpan.Zero);
    }

    public DateTimeOffset UtcNow => _now;

    public void Advance(TimeSpan duration)
    {
        _now = _now.Add(duration);
    }

    public void SetTime(DateTimeOffset time)
    {
        if (time.Offset != TimeSpan.Zero)
            throw new ArgumentException("Time must be UTC");
        _now = time;
    }
}
