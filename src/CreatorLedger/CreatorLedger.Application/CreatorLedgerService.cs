using CreatorLedger.Application.Attestation;
using CreatorLedger.Application.Export;
using CreatorLedger.Application.Identity;
using CreatorLedger.Application.Primitives;
using CreatorLedger.Application.Verification;
using CreatorLedger.Domain.Identity;
using CreatorLedger.Domain.Ledger;
using CreatorLedger.Domain.Primitives;
using CreatorLedger.Domain.Trust;
using Shared.Crypto;

namespace CreatorLedger.Application;

/// <summary>
/// Default implementation of <see cref="ICreatorLedgerService"/>.
/// Wires together the command/query handlers.
/// </summary>
public sealed class CreatorLedgerService : ICreatorLedgerService
{
    private readonly CreateIdentityHandler _createIdentityHandler;
    private readonly AttestAssetHandler _attestAssetHandler;
    private readonly DeriveAssetHandler _deriveAssetHandler;
    private readonly VerifyAssetHandler _verifyAssetHandler;
    private readonly ExportProofBundleHandler _exportProofBundleHandler;

    public CreatorLedgerService(
        IKeyVault keyVault,
        ICreatorIdentityRepository identityRepository,
        ILedgerRepository ledgerRepository,
        IClock clock)
    {
        _createIdentityHandler = new CreateIdentityHandler(
            keyVault, identityRepository, ledgerRepository, clock);

        _attestAssetHandler = new AttestAssetHandler(
            keyVault, identityRepository, ledgerRepository, clock);

        _deriveAssetHandler = new DeriveAssetHandler(
            keyVault, identityRepository, ledgerRepository, clock);

        _verifyAssetHandler = new VerifyAssetHandler(
            ledgerRepository, identityRepository);

        _exportProofBundleHandler = new ExportProofBundleHandler(
            ledgerRepository, identityRepository, clock);
    }

    public async Task<(CreatorId CreatorId, Ed25519PublicKey PublicKey)> CreateIdentityAsync(
        string? displayName = null,
        CancellationToken cancellationToken = default)
    {
        var result = await _createIdentityHandler.HandleAsync(
            new CreateIdentityCommand(displayName),
            cancellationToken);

        return (result.CreatorId, result.PublicKey);
    }

    public async Task<AttestationId> AttestAsync(
        AssetId assetId,
        ContentHash contentHash,
        CreatorId creatorId,
        CancellationToken cancellationToken = default)
    {
        var result = await _attestAssetHandler.HandleAsync(
            new AttestAssetCommand(assetId, contentHash, creatorId),
            cancellationToken);

        return result.AttestationId;
    }

    public async Task<AttestationId> DeriveAsync(
        AssetId assetId,
        ContentHash contentHash,
        CreatorId creatorId,
        AssetId parentAssetId,
        AttestationId? parentAttestationId = null,
        CancellationToken cancellationToken = default)
    {
        var result = await _deriveAssetHandler.HandleAsync(
            new DeriveAssetCommand(assetId, contentHash, creatorId, parentAssetId, parentAttestationId),
            cancellationToken);

        return result.AttestationId;
    }

    public async Task<TrustLevel> VerifyAsync(
        AssetId assetId,
        ContentHash currentContentHash,
        CancellationToken cancellationToken = default)
    {
        var report = await _verifyAssetHandler.HandleAsync(
            new VerifyAssetQuery(assetId, currentContentHash),
            cancellationToken);

        return report.TrustLevel;
    }

    public async Task<VerificationReport> GetVerificationReportAsync(
        AssetId assetId,
        ContentHash currentContentHash,
        CancellationToken cancellationToken = default)
    {
        return await _verifyAssetHandler.HandleAsync(
            new VerifyAssetQuery(assetId, currentContentHash),
            cancellationToken);
    }

    public async Task<ProofBundle> ExportProofAsync(
        AssetId assetId,
        CancellationToken cancellationToken = default)
    {
        return await _exportProofBundleHandler.HandleAsync(
            new ExportProofBundleCommand(assetId),
            cancellationToken);
    }
}
