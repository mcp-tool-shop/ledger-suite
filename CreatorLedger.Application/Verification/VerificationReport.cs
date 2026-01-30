using CreatorLedger.Domain.Primitives;
using CreatorLedger.Domain.Trust;
using Shared.Crypto;

namespace CreatorLedger.Application.Verification;

/// <summary>
/// Detailed verification report explaining the trust level.
///
/// VERIFICATION FACTORS:
/// This report captures three independent verification checks:
///
/// 1. HASH INTEGRITY (HashMatches):
///    - Compares current content hash with attested hash
///    - True = content unchanged since attestation
///    - False = content was modified (Broken trust level)
///
/// 2. SIGNATURE VALIDITY (SignatureValid):
///    - Verifies Ed25519 signature using creator's public key
///    - True = creator actually signed this attestation
///    - False = signature invalid or tampered (Broken trust level)
///
/// 3. ANCHORING STATUS (IsAnchored):
///    - Checks if attestation has external timestamp proof
///    - True = signature provably existed before anchor time (VerifiedOriginal)
///    - False = no temporal proof, only local signature (Signed)
///
/// For derived assets, additionally checks parent chain validity.
/// </summary>
public sealed record VerificationReport
{
    /// <summary>
    /// The calculated trust level. See TrustLevel enum for semantic definitions.
    /// </summary>
    public required TrustLevel TrustLevel { get; init; }

    /// <summary>
    /// Human-readable explanation of the trust level.
    /// Suitable for display to end users.
    /// </summary>
    public required string Reason { get; init; }

    /// <summary>
    /// The asset that was verified.
    /// </summary>
    public required AssetId AssetId { get; init; }

    /// <summary>
    /// The current content hash that was checked.
    /// This is computed from the actual file content at verification time.
    /// </summary>
    public required ContentHash CurrentContentHash { get; init; }

    /// <summary>
    /// The attested content hash (if an attestation exists).
    /// This is the hash that was signed by the creator.
    /// Compare with CurrentContentHash to detect modifications.
    /// </summary>
    public ContentHash? AttestedContentHash { get; init; }

    /// <summary>
    /// The creator who attested the asset (if attestation exists).
    /// </summary>
    public CreatorId? CreatorId { get; init; }

    /// <summary>
    /// The attestation ID (if attestation exists).
    /// </summary>
    public AttestationId? AttestationId { get; init; }

    /// <summary>
    /// Whether the Ed25519 signature verified successfully.
    /// Null if no attestation exists.
    /// False indicates tampering (results in Broken trust level).
    /// </summary>
    public bool? SignatureValid { get; init; }

    /// <summary>
    /// Whether the current content hash matches the attested hash.
    /// Null if no attestation exists.
    /// False indicates content modification (results in Broken trust level).
    /// </summary>
    public bool? HashMatches { get; init; }

    /// <summary>
    /// Parent asset ID if this is a derived asset.
    /// Only present for assets with TrustLevel.Derived.
    /// </summary>
    public AssetId? ParentAssetId { get; init; }

    /// <summary>
    /// Whether the parent chain is valid (for derived assets).
    /// Verifies the entire derivation chain back to an original asset.
    /// </summary>
    public bool? ParentChainValid { get; init; }

    /// <summary>
    /// Whether the asset is anchored to an external timestamping service.
    /// True indicates temporal proof exists (upgrades Signed to VerifiedOriginal).
    /// </summary>
    public bool IsAnchored { get; init; }

    /// <summary>
    /// Blockchain anchor reference (e.g., "ethereum:0xabc123").
    /// Format: "{chain_name}:{transaction_id}"
    /// </summary>
    public string? AnchorInfo { get; init; }
}
