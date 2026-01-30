using CreatorLedger.Domain.Primitives;
using Shared.Crypto;

namespace CreatorLedger.Domain.Ledger.Events;

/// <summary>
/// Event recording that a new creator identity was created.
/// </summary>
public sealed class CreatorCreatedEvent : LedgerEvent
{
    public const string TypeName = "creator_created";

    public override string EventType => TypeName;

    public CreatorId CreatorId { get; }
    public Ed25519PublicKey PublicKey { get; }
    public string? DisplayName { get; }

    public CreatorCreatedEvent(
        EventId id,
        DateTimeOffset occurredAtUtc,
        Digest256 previousEventHash,
        CreatorId creatorId,
        Ed25519PublicKey publicKey,
        string? displayName)
        : base(id, occurredAtUtc, previousEventHash)
    {
        if (publicKey is null)
            throw new DomainException("PublicKey is required");

        CreatorId = creatorId;
        PublicKey = publicKey;
        DisplayName = displayName;
    }
}
