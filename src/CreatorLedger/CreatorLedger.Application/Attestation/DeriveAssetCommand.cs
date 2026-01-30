using CreatorLedger.Application.Primitives;
using CreatorLedger.Application.Signing;
using CreatorLedger.Domain.Identity;
using CreatorLedger.Domain.Ledger;
using CreatorLedger.Domain.Ledger.Events;
using CreatorLedger.Domain.Primitives;
using Shared.Crypto;

namespace CreatorLedger.Application.Attestation;

/// <summary>
/// Command to derive a new asset from a parent asset.
/// </summary>
public sealed record DeriveAssetCommand(
    AssetId AssetId,
    ContentHash ContentHash,
    CreatorId CreatorId,
    AssetId ParentAssetId,
    AttestationId? ParentAttestationId = null);

/// <summary>
/// Result of deriving an asset.
/// </summary>
public sealed record DeriveAssetResult(
    AttestationId AttestationId,
    Ed25519Signature Signature);

/// <summary>
/// Handler for deriving an asset from a parent.
/// </summary>
public sealed class DeriveAssetHandler
{
    private readonly IKeyVault _keyVault;
    private readonly ICreatorIdentityRepository _identityRepository;
    private readonly ILedgerRepository _ledgerRepository;
    private readonly IClock _clock;

    public DeriveAssetHandler(
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

    public async Task<DeriveAssetResult> HandleAsync(
        DeriveAssetCommand command,
        CancellationToken cancellationToken = default)
    {
        // Verify parent asset has at least one event
        var parentEvents = await _ledgerRepository.GetEventsForAssetAsync(
            command.ParentAssetId, cancellationToken);

        if (parentEvents.Count == 0)
            throw NotFoundException.ForAsset(command.ParentAssetId.ToString());

        // Load creator identity
        var identity = await _identityRepository.GetAsync(command.CreatorId, cancellationToken)
            ?? throw NotFoundException.ForCreator(command.CreatorId.ToString());

        // Load private key
        using var privateKey = await _keyVault.RetrieveAsync(command.CreatorId, cancellationToken)
            ?? throw NotFoundException.ForCreator(command.CreatorId.ToString());

        var now = _clock.UtcNow;
        var attestationId = AttestationId.New();

        // Create signable payload with derivation info (includes public key)
        var signable = SigningService.CreateDerivedSignable(
            command.AssetId,
            command.ContentHash,
            command.CreatorId,
            identity.PublicKey,
            now,
            command.ParentAssetId,
            command.ParentAttestationId);

        // Sign the payload
        var signature = SigningService.Sign(signable, privateKey);

        // Get previous event hash for chaining
        var previousHash = await _ledgerRepository.GetLedgerTipAsync(cancellationToken);

        // Append derivation event (explicit parent linkage)
        var evt = new AssetDerivedEvent(
            EventId.New(),
            now,
            previousHash,
            attestationId,
            command.AssetId,
            command.ContentHash,
            command.CreatorId,
            signature,
            command.ParentAssetId,
            command.ParentAttestationId);

        await _ledgerRepository.AppendAsync(evt, cancellationToken);

        return new DeriveAssetResult(attestationId, signature);
    }
}
