using CreatorLedger.Application.Attestation;
using CreatorLedger.Application.Identity;
using CreatorLedger.Application.Primitives;
using CreatorLedger.Application.Signing;
using CreatorLedger.Domain.Ledger.Events;
using CreatorLedger.Domain.Primitives;
using CreatorLedger.Tests.Fakes;
using Shared.Crypto;

namespace CreatorLedger.Tests.Application;

public class AttestAssetTests
{
    private readonly FakeClock _clock = new();
    private readonly InMemoryKeyVault _keyVault = new();
    private readonly InMemoryCreatorIdentityRepository _identityRepo = new();
    private readonly InMemoryLedgerRepository _ledgerRepo = new();

    private CreateIdentityHandler CreateIdentityHandler() =>
        new(_keyVault, _identityRepo, _ledgerRepo, _clock);

    private AttestAssetHandler CreateAttestHandler() =>
        new(_keyVault, _identityRepo, _ledgerRepo, _clock);

    [Fact]
    public async Task AttestAsset_ProducesVerifiableSignature()
    {
        // Create identity first
        var identity = await CreateIdentityHandler()
            .HandleAsync(new CreateIdentityCommand("Signer"));

        var assetId = AssetId.New();
        var contentHash = ContentHash.Compute("test content"u8);

        // Attest the asset
        var handler = CreateAttestHandler();
        var result = await handler.HandleAsync(
            new AttestAssetCommand(assetId, contentHash, identity.CreatorId));

        // Verify the signature
        var creator = await _identityRepo.GetAsync(identity.CreatorId);
        var signable = SigningService.CreateOriginalSignable(
            assetId, contentHash, identity.CreatorId, creator!.PublicKey, _clock.UtcNow);

        var isValid = SigningService.Verify(signable, result.Signature, creator.PublicKey);
        Assert.True(isValid);
    }

    [Fact]
    public async Task AttestAsset_AppendsAssetAttestedEvent()
    {
        var identity = await CreateIdentityHandler()
            .HandleAsync(new CreateIdentityCommand("Creator"));

        var assetId = AssetId.New();
        var contentHash = ContentHash.Compute("data"u8);

        var handler = CreateAttestHandler();
        var result = await handler.HandleAsync(
            new AttestAssetCommand(assetId, contentHash, identity.CreatorId));

        var events = _ledgerRepo.GetAllEvents();
        var attestEvent = events.OfType<AssetAttestedEvent>().FirstOrDefault();

        Assert.NotNull(attestEvent);
        Assert.Equal(assetId, attestEvent.AssetId);
        Assert.Equal(contentHash, attestEvent.ContentHash);
        Assert.Equal(identity.CreatorId, attestEvent.CreatorId);
        Assert.Equal(result.AttestationId, attestEvent.AttestationId);
    }

    [Fact]
    public async Task AttestAsset_ThrowsForUnknownCreator()
    {
        var handler = CreateAttestHandler();
        var unknownCreatorId = CreatorId.New();

        await Assert.ThrowsAsync<NotFoundException>(() =>
            handler.HandleAsync(new AttestAssetCommand(
                AssetId.New(),
                ContentHash.Compute("x"u8),
                unknownCreatorId)));
    }

    [Fact]
    public async Task AttestAsset_ChainsEvents()
    {
        var identity = await CreateIdentityHandler()
            .HandleAsync(new CreateIdentityCommand("Chainer"));

        var handler = CreateAttestHandler();

        // First attestation
        await handler.HandleAsync(new AttestAssetCommand(
            AssetId.New(),
            ContentHash.Compute("first"u8),
            identity.CreatorId));

        var tipAfterFirst = await _ledgerRepo.GetLedgerTipAsync();

        // Second attestation
        await handler.HandleAsync(new AttestAssetCommand(
            AssetId.New(),
            ContentHash.Compute("second"u8),
            identity.CreatorId));

        // Verify the second event chains to the first
        var events = _ledgerRepo.GetAllEvents();
        var secondAttest = events.OfType<AssetAttestedEvent>().Last();

        Assert.Equal(tipAfterFirst, secondAttest.PreviousEventHash);
    }
}
