using CreatorLedger.Application.Primitives;
using CreatorLedger.Domain.Identity;
using CreatorLedger.Domain.Ledger;
using CreatorLedger.Domain.Ledger.Events;
using CreatorLedger.Domain.Primitives;
using Shared.Crypto;

namespace CreatorLedger.Application.Identity;

/// <summary>
/// Command to create a new creator identity.
/// </summary>
public sealed record CreateIdentityCommand(string? DisplayName);

/// <summary>
/// Result of creating a creator identity.
/// </summary>
public sealed record CreateIdentityResult(CreatorId CreatorId, Ed25519PublicKey PublicKey);

/// <summary>
/// Handler for creating a new creator identity.
/// </summary>
public sealed class CreateIdentityHandler
{
    private readonly IKeyVault _keyVault;
    private readonly ICreatorIdentityRepository _identityRepository;
    private readonly ILedgerRepository _ledgerRepository;
    private readonly IClock _clock;

    public CreateIdentityHandler(
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

    public async Task<CreateIdentityResult> HandleAsync(
        CreateIdentityCommand command,
        CancellationToken cancellationToken = default)
    {
        // Generate new keypair
        using var keyPair = Ed25519KeyPair.Generate();
        var creatorId = CreatorId.New();
        var now = _clock.UtcNow;

        // Store private key in vault
        await _keyVault.StoreAsync(creatorId, keyPair.PrivateKey, cancellationToken);

        // Create and persist identity (public key only)
        var identity = CreatorIdentity.Create(
            creatorId,
            keyPair.PublicKey,
            command.DisplayName,
            now);

        await _identityRepository.AddAsync(identity, cancellationToken);

        // Append event to ledger for complete provenance
        var previousHash = await _ledgerRepository.GetLedgerTipAsync(cancellationToken);

        var evt = new CreatorCreatedEvent(
            EventId.New(),
            now,
            previousHash,
            creatorId,
            keyPair.PublicKey,
            identity.DisplayName);

        await _ledgerRepository.AppendAsync(evt, cancellationToken);

        return new CreateIdentityResult(creatorId, keyPair.PublicKey);
    }
}
