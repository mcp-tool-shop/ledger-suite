using CreatorLedger.Application.Attestation;
using CreatorLedger.Application.Export;
using CreatorLedger.Application.Identity;
using CreatorLedger.Application.Primitives;
using CreatorLedger.Application.Signing;
using CreatorLedger.Domain.Primitives;
using CreatorLedger.Tests.Fakes;
using Shared.Crypto;

namespace CreatorLedger.Tests.Application;

public class ExportProofBundleTests
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

    private ExportProofBundleHandler CreateExportHandler() =>
        new(_ledgerRepo, _identityRepo, _clock);

    [Fact]
    public async Task Export_ThrowsForUnknownAsset()
    {
        var handler = CreateExportHandler();

        await Assert.ThrowsAsync<NotFoundException>(() =>
            handler.HandleAsync(new ExportProofBundleCommand(AssetId.New())));
    }

    [Fact]
    public async Task Export_ContainsAttestationInfo()
    {
        var identity = await CreateIdentityHandler()
            .HandleAsync(new CreateIdentityCommand("Creator"));

        var assetId = AssetId.New();
        var contentHash = ContentHash.Compute("content"u8);

        await CreateAttestHandler().HandleAsync(
            new AttestAssetCommand(assetId, contentHash, identity.CreatorId));

        var handler = CreateExportHandler();
        var bundle = await handler.HandleAsync(new ExportProofBundleCommand(assetId));

        Assert.Equal(assetId.ToString(), bundle.AssetId);
        Assert.Single(bundle.Attestations);
        Assert.Equal(contentHash.ToString(), bundle.Attestations[0].ContentHash);
    }

    [Fact]
    public async Task Export_ContainsCreatorPublicKey()
    {
        var identity = await CreateIdentityHandler()
            .HandleAsync(new CreateIdentityCommand("Photographer"));

        var assetId = AssetId.New();
        await CreateAttestHandler().HandleAsync(
            new AttestAssetCommand(assetId, ContentHash.Compute("photo"u8), identity.CreatorId));

        var handler = CreateExportHandler();
        var bundle = await handler.HandleAsync(new ExportProofBundleCommand(assetId));

        Assert.Single(bundle.Creators);
        Assert.Equal(identity.CreatorId.ToString(), bundle.Creators[0].CreatorId);
        Assert.Equal(identity.PublicKey.ToString(), bundle.Creators[0].PublicKey);
    }

    [Fact]
    public async Task Export_CanVerifyWithoutDatabase()
    {
        var identity = await CreateIdentityHandler()
            .HandleAsync(new CreateIdentityCommand("Artist"));

        var assetId = AssetId.New();
        var contentHash = ContentHash.Compute("artwork"u8);

        await CreateAttestHandler().HandleAsync(
            new AttestAssetCommand(assetId, contentHash, identity.CreatorId));

        var handler = CreateExportHandler();
        var bundle = await handler.HandleAsync(new ExportProofBundleCommand(assetId));

        // Simulate standalone verification (no database access)
        var attestation = bundle.Attestations[0];

        // Parse the public key from the attestation proof (self-contained)
        var publicKey = Ed25519PublicKey.Parse(attestation.CreatorPublicKey);

        // Reconstruct the signable from attestation data
        var signable = SigningService.FromEvent(
            attestation.AssetId,
            attestation.ContentHash,
            attestation.CreatorId,
            attestation.CreatorPublicKey,
            attestation.AttestedAtUtc);

        // Parse the signature
        var signature = Ed25519Signature.Parse(attestation.Signature);

        // Verify - should succeed
        var isValid = SigningService.Verify(signable, signature, publicKey);
        Assert.True(isValid);
    }

    [Fact]
    public async Task Export_IncludesParentChainForDerivedAsset()
    {
        var identity = await CreateIdentityHandler()
            .HandleAsync(new CreateIdentityCommand("Creator"));

        // Create parent
        var parentId = AssetId.New();
        await CreateAttestHandler().HandleAsync(
            new AttestAssetCommand(parentId, ContentHash.Compute("parent"u8), identity.CreatorId));

        // Create derived
        var derivedId = AssetId.New();
        await CreateDeriveHandler().HandleAsync(
            new DeriveAssetCommand(derivedId, ContentHash.Compute("derived"u8), identity.CreatorId, parentId));

        var handler = CreateExportHandler();
        var bundle = await handler.HandleAsync(new ExportProofBundleCommand(derivedId));

        // Should have both attestations
        Assert.Equal(2, bundle.Attestations.Count);

        // Should have parent linkage
        var derivedAttestation = bundle.Attestations.First(a => a.AssetId == derivedId.ToString());
        Assert.Equal(parentId.ToString(), derivedAttestation.DerivedFromAssetId);
    }

    [Fact]
    public async Task Export_HasVersionInfo()
    {
        var identity = await CreateIdentityHandler()
            .HandleAsync(new CreateIdentityCommand("Versioner"));

        var assetId = AssetId.New();
        await CreateAttestHandler().HandleAsync(
            new AttestAssetCommand(assetId, ContentHash.Compute("v"u8), identity.CreatorId));

        var handler = CreateExportHandler();
        var bundle = await handler.HandleAsync(new ExportProofBundleCommand(assetId));

        Assert.Equal("proof.v1", bundle.Version);
        Assert.NotNull(bundle.ExportedAtUtc);
    }

    [Fact]
    public async Task Export_HasAlgorithmsSection()
    {
        var identity = await CreateIdentityHandler()
            .HandleAsync(new CreateIdentityCommand("AlgoChecker"));

        var assetId = AssetId.New();
        await CreateAttestHandler().HandleAsync(
            new AttestAssetCommand(assetId, ContentHash.Compute("algo"u8), identity.CreatorId));

        var handler = CreateExportHandler();
        var bundle = await handler.HandleAsync(new ExportProofBundleCommand(assetId));

        Assert.NotNull(bundle.Algorithms);
        Assert.Equal("Ed25519", bundle.Algorithms.Signature);
        Assert.Equal("SHA-256", bundle.Algorithms.Hash);
        Assert.Equal("UTF-8", bundle.Algorithms.Encoding);
    }

    [Fact]
    public async Task Export_HasLedgerTipHash()
    {
        var identity = await CreateIdentityHandler()
            .HandleAsync(new CreateIdentityCommand("TipChecker"));

        var assetId = AssetId.New();
        await CreateAttestHandler().HandleAsync(
            new AttestAssetCommand(assetId, ContentHash.Compute("tip"u8), identity.CreatorId));

        var handler = CreateExportHandler();
        var bundle = await handler.HandleAsync(new ExportProofBundleCommand(assetId));

        Assert.NotNull(bundle.LedgerTipHash);
        Assert.NotEmpty(bundle.LedgerTipHash);

        // Verify it's a valid Digest256 format (hex string)
        Assert.Equal(64, bundle.LedgerTipHash.Length);
    }

    [Fact]
    public async Task Export_AttestationHasCreatorPublicKey()
    {
        var identity = await CreateIdentityHandler()
            .HandleAsync(new CreateIdentityCommand("PubKeyChecker"));

        var assetId = AssetId.New();
        await CreateAttestHandler().HandleAsync(
            new AttestAssetCommand(assetId, ContentHash.Compute("pubkey"u8), identity.CreatorId));

        var handler = CreateExportHandler();
        var bundle = await handler.HandleAsync(new ExportProofBundleCommand(assetId));

        var attestation = bundle.Attestations[0];
        Assert.NotNull(attestation.CreatorPublicKey);
        Assert.NotEmpty(attestation.CreatorPublicKey);

        // Verify it matches the creator's public key
        var creator = bundle.Creators.First(c => c.CreatorId == attestation.CreatorId);
        Assert.Equal(creator.PublicKey, attestation.CreatorPublicKey);
    }
}
