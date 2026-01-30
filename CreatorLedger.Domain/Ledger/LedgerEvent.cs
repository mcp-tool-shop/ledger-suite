using CreatorLedger.Domain.Primitives;
using Shared.Crypto;

namespace CreatorLedger.Domain.Ledger;

/// <summary>
/// Base class for all ledger events. Events form an append-only chain.
/// </summary>
public abstract class LedgerEvent
{
    public EventId Id { get; }
    public DateTimeOffset OccurredAtUtc { get; }
    public Digest256 PreviousEventHash { get; }

    protected LedgerEvent(EventId id, DateTimeOffset occurredAtUtc, Digest256 previousEventHash)
    {
        if (occurredAtUtc.Offset != TimeSpan.Zero)
            throw new DomainException("OccurredAtUtc must be UTC (offset must be zero)");

        Id = id;
        OccurredAtUtc = occurredAtUtc;
        PreviousEventHash = previousEventHash;
    }

    /// <summary>
    /// Returns the event type identifier for serialization.
    /// </summary>
    public abstract string EventType { get; }
}
