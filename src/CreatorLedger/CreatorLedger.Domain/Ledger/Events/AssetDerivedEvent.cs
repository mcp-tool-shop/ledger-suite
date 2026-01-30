using CreatorLedger.Domain.Primitives;
using Shared.Crypto;

namespace CreatorLedger.Domain.Ledger.Events;

/// <summary>
/// Event recording that an asset was derived from a parent asset.
/// </summary>
public sealed class AssetDerivedEvent : LedgerEvent
{
    public const string TypeName = "asset_derived";

    public override string EventType => TypeName;

    public AttestationId AttestationId { get; }
    public AssetId AssetId { get; }
    public ContentHash ContentHash { get; }
    public CreatorId CreatorId { get; }
    public Ed25519Signature Signature { get; }

    /// <summary>
    /// The parent asset this was derived from.
    /// </summary>
    public AssetId ParentAssetId { get; }

    /// <summary>
    /// Optional: The specific parent attestation, for precise lineage.
    /// </summary>
    public AttestationId? ParentAttestationId { get; }

    public AssetDerivedEvent(
        EventId id,
        DateTimeOffset occurredAtUtc,
        Digest256 previousEventHash,
        AttestationId attestationId,
        AssetId assetId,
        ContentHash contentHash,
        CreatorId creatorId,
        Ed25519Signature signature,
        AssetId parentAssetId,
        AttestationId? parentAttestationId = null)
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
        ParentAssetId = parentAssetId;
        ParentAttestationId = parentAttestationId;
    }
}
