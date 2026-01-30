using CreatorLedger.Application.Primitives;
using CreatorLedger.Application.Signing;
using CreatorLedger.Domain.Identity;
using CreatorLedger.Domain.Ledger;
using CreatorLedger.Domain.Ledger.Events;
using CreatorLedger.Domain.Primitives;
using Shared.Crypto;

namespace CreatorLedger.Application.Attestation;

/// <summary>
/// Command to attest an original asset.
/// </summary>
public sealed record AttestAssetCommand(
    AssetId AssetId,
    ContentHash ContentHash,
    CreatorId CreatorId);

/// <summary>
/// Result of attesting an asset.
/// </summary>
public sealed record AttestAssetResult(
    AttestationId AttestationId,
    Ed25519Signature Signature);

/// <summary>
/// Handler for attesting an original asset.
/// </summary>
public sealed class AttestAssetHandler
{
    private readonly IKeyVault _keyVault;
    private readonly ICreatorIdentityRepository _identityRepository;
    private readonly ILedgerRepository _ledgerRepository;
    private readonly IClock _clock;

    public AttestAssetHandler(
        IKeyVault keyVault,
        ICreatorIdentityRepository identityRepository,
        ILedgerRepository ledgerRepository,
        IClock clock)
    {
        _keyVault = keyVault;
        _identityRepository = identityRepository;
        _ledgerRepository = ledgerRepository;
        _clock = clock;
    }

    public async Task<AttestAssetResult> HandleAsync(
        AttestAssetCommand command,
        CancellationToken cancellationToken = default)
    {
        // Load creator identity
        var identity = await _identityRepository.GetAsync(command.CreatorId, cancellationToken)
            ?? throw NotFoundException.ForCreator(command.CreatorId.ToString());

        // Load private key
        using var privateKey = await _keyVault.RetrieveAsync(command.CreatorId, cancellationToken)
            ?? throw NotFoundException.ForCreator(command.CreatorId.ToString());

        var now = _clock.UtcNow;
        var attestationId = AttestationId.New();

        // Create signable payload (includes public key for key rotation support)
        var signable = SigningService.CreateOriginalSignable(
            command.AssetId,
            command.ContentHash,
            command.CreatorId,
            identity.PublicKey,
            now);

        // Sign the payload
        var signature = SigningService.Sign(signable, privateKey);

        // Get previous event hash for chaining
        var previousHash = await _ledgerRepository.GetLedgerTipAsync(cancellationToken);

        // Append attestation event (includes public key for standalone verification)
        var evt = new AssetAttestedEvent(
            EventId.New(),
            now,
            previousHash,
            attestationId,
            command.AssetId,
            command.ContentHash,
            command.CreatorId,
            signature);

        await _ledgerRepository.AppendAsync(evt, cancellationToken);

        return new AttestAssetResult(attestationId, signature);
    }
}
