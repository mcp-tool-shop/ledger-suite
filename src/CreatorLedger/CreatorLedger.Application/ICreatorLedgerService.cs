using CreatorLedger.Application.Export;
using CreatorLedger.Application.Verification;
using CreatorLedger.Domain.Primitives;
using CreatorLedger.Domain.Trust;
using Shared.Crypto;

namespace CreatorLedger.Application;

/// <summary>
/// Main facade for the Creator Ledger module.
/// This is the only interface Gallery needs to integrate with.
/// </summary>
public interface ICreatorLedgerService
{
    /// <summary>
    /// Creates a new creator identity with a generated keypair.
    /// </summary>
    /// <param name="displayName">Optional display name for the creator.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The new creator ID and public key.</returns>
    Task<(CreatorId CreatorId, Ed25519PublicKey PublicKey)> CreateIdentityAsync(
        string? displayName = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Attests an original asset (not derived from another).
    /// </summary>
    /// <param name="assetId">The asset to attest.</param>
    /// <param name="contentHash">SHA-256 hash of the asset content.</param>
    /// <param name="creatorId">The creator making the attestation.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The attestation ID.</returns>
    Task<AttestationId> AttestAsync(
        AssetId assetId,
        ContentHash contentHash,
        CreatorId creatorId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Attests a derived asset (based on a parent asset).
    /// </summary>
    /// <param name="assetId">The new derived asset.</param>
    /// <param name="contentHash">SHA-256 hash of the derived asset content.</param>
    /// <param name="creatorId">The creator making the attestation.</param>
    /// <param name="parentAssetId">The parent asset this is derived from.</param>
    /// <param name="parentAttestationId">Optional: specific parent attestation for precise lineage.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The attestation ID.</returns>
    Task<AttestationId> DeriveAsync(
        AssetId assetId,
        ContentHash contentHash,
        CreatorId creatorId,
        AssetId parentAssetId,
        AttestationId? parentAttestationId = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies an asset's trust level.
    /// </summary>
    /// <param name="assetId">The asset to verify.</param>
    /// <param name="currentContentHash">The current SHA-256 hash of the asset.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The trust level.</returns>
    Task<TrustLevel> VerifyAsync(
        AssetId assetId,
        ContentHash currentContentHash,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets a detailed verification report for an asset.
    /// </summary>
    /// <param name="assetId">The asset to verify.</param>
    /// <param name="currentContentHash">The current SHA-256 hash of the asset.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Detailed verification report.</returns>
    Task<VerificationReport> GetVerificationReportAsync(
        AssetId assetId,
        ContentHash currentContentHash,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Exports a proof bundle for an asset.
    /// The proof bundle can verify provenance without database access.
    /// </summary>
    /// <param name="assetId">The asset to export proof for.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A standalone proof bundle.</returns>
    Task<ProofBundle> ExportProofAsync(
        AssetId assetId,
        CancellationToken cancellationToken = default);
}
