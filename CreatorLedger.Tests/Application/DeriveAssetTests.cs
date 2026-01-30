using CreatorLedger.Application.Attestation;
using CreatorLedger.Application.Identity;
using CreatorLedger.Application.Primitives;
using CreatorLedger.Application.Signing;
using CreatorLedger.Domain.Ledger.Events;
using CreatorLedger.Domain.Primitives;
using CreatorLedger.Tests.Fakes;
using Shared.Crypto;

namespace CreatorLedger.Tests.Application;

public class DeriveAssetTests
{
    private readonly FakeClock _clock = new();
    private readonly InMemoryKeyVault _keyVault = new();
    private readonly InMemoryCreatorIdentityRepository _identityRepo = new();
    private readonly InMemoryLedgerRepository _ledgerRepo = new();

    private CreateIdentityHandler CreateIdentityHandler() =>
        new(_keyVault, _identityRepo, _ledgerRepo, _clock);

    private AttestAssetHandler CreateAttestHandler() =>
        new(_keyVault, _identityRepo, _ledgerRepo, _clock);

    private DeriveAssetHandler CreateDeriveHandler() =>
        new(_keyVault, _identityRepo, _ledgerRepo, _clock);

    [Fact]
    public async Task DeriveAsset_RequiresParentToExist()
    {
        var identity = await CreateIdentityHandler()
            .HandleAsync(new CreateIdentityCommand("Deriver"));

        var nonExistentParent = AssetId.New();

        var handler = CreateDeriveHandler();

        await Assert.ThrowsAsync<NotFoundException>(() =>
            handler.HandleAsync(new DeriveAssetCommand(
                AssetId.New(),
                ContentHash.Compute("derived"u8),
                identity.CreatorId,
                nonExistentParent)));
    }

    [Fact]
    public async Task DeriveAsset_AppendsAssetDerivedEvent()
    {
        var identity = await CreateIdentityHandler()
            .HandleAsync(new CreateIdentityCommand("Artist"));

        // Create parent
        var parentAssetId = AssetId.New();
        var parentHash = ContentHash.Compute("original"u8);

        var attestResult = await CreateAttestHandler().HandleAsync(
            new AttestAssetCommand(parentAssetId, parentHash, identity.CreatorId));

        // Derive
        var derivedAssetId = AssetId.New();
        var derivedHash = ContentHash.Compute("remix"u8);

        var handler = CreateDeriveHandler();
        var result = await handler.HandleAsync(new DeriveAssetCommand(
            derivedAssetId,
            derivedHash,
            identity.CreatorId,
            parentAssetId,
            attestResult.AttestationId));

        // Check event
        var events = _ledgerRepo.GetAllEvents();
        var derivedEvent = events.OfType<AssetDerivedEvent>().FirstOrDefault();

        Assert.NotNull(derivedEvent);
        Assert.Equal(derivedAssetId, derivedEvent.AssetId);
        Assert.Equal(parentAssetId, derivedEvent.ParentAssetId);
        Assert.Equal(attestResult.AttestationId, derivedEvent.ParentAttestationId);
    }

    [Fact]
    public async Task DeriveAsset_SignatureIsVerifiable()
    {
        var identity = await CreateIdentityHandler()
            .HandleAsync(new CreateIdentityCommand("Remixer"));

        // Create parent
        var parentAssetId = AssetId.New();
        await CreateAttestHandler().HandleAsync(
            new AttestAssetCommand(parentAssetId, ContentHash.Compute("orig"u8), identity.CreatorId));

        // Derive
        var derivedAssetId = AssetId.New();
        var derivedHash = ContentHash.Compute("derived"u8);

        var handler = CreateDeriveHandler();
        var result = await handler.HandleAsync(new DeriveAssetCommand(
            derivedAssetId, derivedHash, identity.CreatorId, parentAssetId));

        // Verify signature using public key
        var creator = await _identityRepo.GetAsync(identity.CreatorId);
        var signable = SigningService.CreateDerivedSignable(
            derivedAssetId, derivedHash, identity.CreatorId, creator!.PublicKey, _clock.UtcNow, parentAssetId);

        var isValid = SigningService.Verify(
            signable, result.Signature, creator.PublicKey);

        Assert.True(isValid);
    }

    [Fact]
    public async Task DeriveAsset_DifferentCreatorCanDerive()
    {
        // Original creator
        var originalCreator = await CreateIdentityHandler()
            .HandleAsync(new CreateIdentityCommand("Original"));

        var parentAssetId = AssetId.New();
        await CreateAttestHandler().HandleAsync(
            new AttestAssetCommand(parentAssetId, ContentHash.Compute("parent"u8), originalCreator.CreatorId));

        // Different creator derives
        var derivingCreator = await CreateIdentityHandler()
            .HandleAsync(new CreateIdentityCommand("Remixer"));

        var derivedAssetId = AssetId.New();

        var handler = CreateDeriveHandler();
        var result = await handler.HandleAsync(new DeriveAssetCommand(
            derivedAssetId,
            ContentHash.Compute("remix"u8),
            derivingCreator.CreatorId,
            parentAssetId));

        var events = _ledgerRepo.GetAllEvents();
        var derivedEvent = events.OfType<AssetDerivedEvent>().First();

        Assert.Equal(derivingCreator.CreatorId, derivedEvent.CreatorId);
    }
}
