using CreatorLedger.Domain.Primitives;
using Shared.Crypto;

namespace CreatorLedger.Domain.Attestation;

/// <summary>
/// Entity representing a cryptographic attestation that a creator owns an asset.
/// </summary>
public sealed class AssetAttestation
{
    public AttestationId Id { get; }
    public AssetId AssetId { get; }
    public ContentHash ContentHash { get; }
    public CreatorId CreatorId { get; }
    public DateTimeOffset AttestedAtUtc { get; }
    public Ed25519Signature Signature { get; }

    /// <summary>
    /// Optional: The asset this was derived from.
    /// </summary>
    public AssetId? DerivedFromAssetId { get; }

    /// <summary>
    /// Optional: The specific attestation this was derived from.
    /// Enables precise lineage tracking when an asset has multiple attestations.
    /// </summary>
    public AttestationId? DerivedFromAttestationId { get; }

    private AssetAttestation(
        AttestationId id,
        AssetId assetId,
        ContentHash contentHash,
        CreatorId creatorId,
        DateTimeOffset attestedAtUtc,
        Ed25519Signature signature,
        AssetId? derivedFromAssetId,
        AttestationId? derivedFromAttestationId)
    {
        Id = id;
        AssetId = assetId;
        ContentHash = contentHash;
        CreatorId = creatorId;
        AttestedAtUtc = attestedAtUtc;
        Signature = signature;
        DerivedFromAssetId = derivedFromAssetId;
        DerivedFromAttestationId = derivedFromAttestationId;
    }

    /// <summary>
    /// Creates a new original asset attestation (not derived from another asset).
    /// </summary>
    public static AssetAttestation CreateOriginal(
        AttestationId id,
        AssetId assetId,
        ContentHash contentHash,
        CreatorId creatorId,
        DateTimeOffset attestedAtUtc,
        Ed25519Signature signature)
    {
        ValidateCommon(contentHash, attestedAtUtc, signature);

        return new AssetAttestation(
            id, assetId, contentHash, creatorId, attestedAtUtc, signature,
            derivedFromAssetId: null,
            derivedFromAttestationId: null);
    }

    /// <summary>
    /// Creates a new derived asset attestation (based on another asset).
    /// </summary>
    public static AssetAttestation CreateDerived(
        AttestationId id,
        AssetId assetId,
        ContentHash contentHash,
        CreatorId creatorId,
        DateTimeOffset attestedAtUtc,
        Ed25519Signature signature,
        AssetId derivedFromAssetId,
        AttestationId? derivedFromAttestationId = null)
    {
        ValidateCommon(contentHash, attestedAtUtc, signature);

        return new AssetAttestation(
            id, assetId, contentHash, creatorId, attestedAtUtc, signature,
            derivedFromAssetId,
            derivedFromAttestationId);
    }

    /// <summary>
    /// Reconstitutes an AssetAttestation from persisted data.
    /// Use for loading from storage only.
    /// </summary>
    public static AssetAttestation Reconstitute(
        AttestationId id,
        AssetId assetId,
        ContentHash contentHash,
        CreatorId creatorId,
        DateTimeOffset attestedAtUtc,
        Ed25519Signature signature,
        AssetId? derivedFromAssetId,
        AttestationId? derivedFromAttestationId)
    {
        return new AssetAttestation(
            id, assetId, contentHash, creatorId, attestedAtUtc, signature,
            derivedFromAssetId, derivedFromAttestationId);
    }

    /// <summary>
    /// Returns true if this attestation is for a derived asset.
    /// </summary>
    public bool IsDerived => DerivedFromAssetId.HasValue;

    private static void ValidateCommon(
        ContentHash contentHash,
        DateTimeOffset attestedAtUtc,
        Ed25519Signature signature)
    {
        if (contentHash == default)
            throw new DomainException("ContentHash cannot be empty");

        if (attestedAtUtc.Offset != TimeSpan.Zero)
            throw new DomainException("AttestedAtUtc must be UTC (offset must be zero)");

        if (signature == default)
            throw new DomainException("Signature is required for AssetAttestation");
    }
}
