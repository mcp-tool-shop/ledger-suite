using CreatorLedger.Application.Attestation;
using CreatorLedger.Application.Identity;
using CreatorLedger.Application.Verification;
using CreatorLedger.Domain.Primitives;
using CreatorLedger.Domain.Trust;
using CreatorLedger.Tests.Fakes;
using Shared.Crypto;

namespace CreatorLedger.Tests.Application;

public class VerifyAssetTests
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

    private VerifyAssetHandler CreateVerifyHandler() =>
        new(_ledgerRepo, _identityRepo);

    [Fact]
    public async Task Verify_UnknownAsset_ReturnsUnverified()
    {
        var handler = CreateVerifyHandler();
        var unknownAssetId = AssetId.New();
        var contentHash = ContentHash.Compute("unknown"u8);

        var report = await handler.HandleAsync(
            new VerifyAssetQuery(unknownAssetId, contentHash));

        Assert.Equal(TrustLevel.Unverified, report.TrustLevel);
        Assert.Contains("No attestation found", report.Reason);
    }

    [Fact]
    public async Task Verify_HashMismatch_ReturnsBroken()
    {
        // Setup: create and attest an asset
        var identity = await CreateIdentityHandler()
            .HandleAsync(new CreateIdentityCommand("Creator"));

        var assetId = AssetId.New();
        var originalHash = ContentHash.Compute("original content"u8);

        await CreateAttestHandler().HandleAsync(
            new AttestAssetCommand(assetId, originalHash, identity.CreatorId));

        // Verify with different hash (simulating modified content)
        var modifiedHash = ContentHash.Compute("modified content"u8);
        var handler = CreateVerifyHandler();

        var report = await handler.HandleAsync(
            new VerifyAssetQuery(assetId, modifiedHash));

        Assert.Equal(TrustLevel.Broken, report.TrustLevel);
        Assert.False(report.HashMatches);
        Assert.Contains("modified", report.Reason);
    }

    [Fact]
    public async Task Verify_ValidSignatureAndHash_ReturnsSigned()
    {
        // Setup: create and attest an asset
        var identity = await CreateIdentityHandler()
            .HandleAsync(new CreateIdentityCommand("Creator"));

        var assetId = AssetId.New();
        var contentHash = ContentHash.Compute("my asset"u8);

        await CreateAttestHandler().HandleAsync(
            new AttestAssetCommand(assetId, contentHash, identity.CreatorId));

        // Verify with same hash
        var handler = CreateVerifyHandler();

        var report = await handler.HandleAsync(
            new VerifyAssetQuery(assetId, contentHash));

        Assert.Equal(TrustLevel.Signed, report.TrustLevel);
        Assert.True(report.HashMatches);
        Assert.True(report.SignatureValid);
        Assert.False(report.IsAnchored);
    }

    [Fact]
    public async Task Verify_DerivedAsset_ReturnsDerived()
    {
        // Create parent asset
        var identity = await CreateIdentityHandler()
            .HandleAsync(new CreateIdentityCommand("Artist"));

        var parentAssetId = AssetId.New();
        var parentHash = ContentHash.Compute("original artwork"u8);

        await CreateAttestHandler().HandleAsync(
            new AttestAssetCommand(parentAssetId, parentHash, identity.CreatorId));

        // Create derived asset
        var derivedAssetId = AssetId.New();
        var derivedHash = ContentHash.Compute("derivative work"u8);

        await CreateDeriveHandler().HandleAsync(
            new DeriveAssetCommand(derivedAssetId, derivedHash, identity.CreatorId, parentAssetId));

        // Verify derived asset
        var handler = CreateVerifyHandler();

        var report = await handler.HandleAsync(
            new VerifyAssetQuery(derivedAssetId, derivedHash));

        Assert.Equal(TrustLevel.Derived, report.TrustLevel);
        Assert.Equal(parentAssetId, report.ParentAssetId);
        Assert.True(report.ParentChainValid);
    }

    [Fact]
    public async Task Verify_ReportContainsCreatorInfo()
    {
        var identity = await CreateIdentityHandler()
            .HandleAsync(new CreateIdentityCommand("Photographer"));

        var assetId = AssetId.New();
        var contentHash = ContentHash.Compute("photo"u8);

        await CreateAttestHandler().HandleAsync(
            new AttestAssetCommand(assetId, contentHash, identity.CreatorId));

        var handler = CreateVerifyHandler();

        var report = await handler.HandleAsync(
            new VerifyAssetQuery(assetId, contentHash));

        Assert.Equal(identity.CreatorId, report.CreatorId);
        Assert.NotNull(report.AttestationId);
    }
}
