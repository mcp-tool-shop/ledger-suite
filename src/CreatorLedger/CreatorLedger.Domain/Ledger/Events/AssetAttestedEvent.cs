using CreatorLedger.Domain.Primitives;
using Shared.Crypto;

namespace CreatorLedger.Domain.Ledger.Events;

/// <summary>
/// Event recording that an asset was attested by a creator.
/// </summary>
public sealed class AssetAttestedEvent : LedgerEvent
{
    public const string TypeName = "asset_attested";

    public override string EventType => TypeName;

    public AttestationId AttestationId { get; }
    public AssetId AssetId { get; }
    public ContentHash ContentHash { get; }
    public CreatorId CreatorId { get; }
    public Ed25519Signature Signature { get; }

    public AssetAttestedEvent(
        EventId id,
        DateTimeOffset occurredAtUtc,
        Digest256 previousEventHash,
        AttestationId attestationId,
        AssetId assetId,
        ContentHash contentHash,
        CreatorId creatorId,
        Ed25519Signature signature)
        : base(id, occurredAtUtc, previousEventHash)
    {
        if (contentHash == default)
            throw new DomainException("ContentHash cannot be empty");
        if (signature == default)
            throw new DomainException("Signature is required");

        AttestationId = attestationId;
        AssetId = assetId;
        ContentHash = contentHash;
        CreatorId = creatorId;
        Signature = signature;
    }
}
