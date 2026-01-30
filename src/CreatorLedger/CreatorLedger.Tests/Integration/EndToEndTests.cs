using System.Runtime.Versioning;
using CreatorLedger.Application.Attestation;
using CreatorLedger.Application.Export;
using CreatorLedger.Application.Identity;
using CreatorLedger.Application.Signing;
using CreatorLedger.Application.Verification;
using CreatorLedger.Domain.Trust;
using CreatorLedger.Domain.Primitives;
using CreatorLedger.Infrastructure.Security;
using Shared.Crypto;

namespace CreatorLedger.Tests.Integration;

/// <summary>
/// End-to-end integration tests that prove the full system works together.
/// These tests use real SQLite and DPAPI.
/// </summary>
[SupportedOSPlatform("windows")]
public class EndToEndTests : IDisposable
{
    private readonly SqliteTestFixture _fixture;
    private readonly string _tempKeyDir;
    private readonly DpapiKeyVault _keyVault;

    // Handlers
    private readonly CreateIdentityHandler _createIdentityHandler;
    private readonly AttestAssetHandler _attestHandler;
    private readonly DeriveAssetHandler _deriveHandler;
    private readonly VerifyAssetHandler _verifyHandler;
    private readonly ExportProofBundleHandler _exportHandler;

    public EndToEndTests()
    {
        _fixture = new SqliteTestFixture();
        _tempKeyDir = Path.Combine(Path.GetTempPath(), $"e2e_keyvault_{Guid.NewGuid():N}");
        _keyVault = new DpapiKeyVault(_tempKeyDir);

        // Wire up handlers with real infrastructure
        _createIdentityHandler = new CreateIdentityHandler(
            _keyVault,
            _fixture.IdentityRepository,
            _fixture.LedgerRepository,
            _fixture.Clock);

        _attestHandler = new AttestAssetHandler(
            _keyVault,
            _fixture.IdentityRepository,
            _fixture.LedgerRepository,
            _fixture.Clock);

        _deriveHandler = new DeriveAssetHandler(
            _keyVault,
            _fixture.IdentityRepository,
            _fixture.LedgerRepository,
            _fixture.Clock);

        _verifyHandler = new VerifyAssetHandler(
            _fixture.LedgerRepository,
            _fixture.IdentityRepository);

        _exportHandler = new ExportProofBundleHandler(
            _fixture.LedgerRepository,
            _fixture.IdentityRepository,
            _fixture.Clock);
    }

    public void Dispose()
    {
        _fixture.Dispose();

        try
        {
            if (Directory.Exists(_tempKeyDir))
                Directory.Delete(_tempKeyDir, recursive: true);
        }
        catch { }
    }

    [Fact]
    public async Task FullFlow_Create_Attest_Verify_Returns_Signed()
    {
        // 1. Create identity
        var identityResult = await _createIdentityHandler.HandleAsync(
            new CreateIdentityCommand("Test Artist"));

        // 2. Attest an asset
        var assetId = AssetId.New();
        var contentHash = ContentHash.Compute("my artwork content"u8);

        var attestResult = await _attestHandler.HandleAsync(
            new AttestAssetCommand(assetId, contentHash, identityResult.CreatorId));

        // 3. Verify the asset (with matching hash)
        var verifyResult = await _verifyHandler.HandleAsync(
            new VerifyAssetQuery(assetId, contentHash));

        // Should be Signed (valid signature, not anchored)
        Assert.Equal(TrustLevel.Signed, verifyResult.TrustLevel);
        Assert.True(verifyResult.HashMatches);
        Assert.True(verifyResult.SignatureValid);
        Assert.False(verifyResult.IsAnchored);
    }

    [Fact]
    public async Task Verify_HashMismatch_Returns_Broken()
    {
        // 1. Create identity and attest
        var identityResult = await _createIdentityHandler.HandleAsync(
            new CreateIdentityCommand("Hash Tester"));

        var assetId = AssetId.New();
        var originalHash = ContentHash.Compute("original content"u8);

        await _attestHandler.HandleAsync(
            new AttestAssetCommand(assetId, originalHash, identityResult.CreatorId));

        // 2. Verify with DIFFERENT hash (simulating modified content)
        var modifiedHash = ContentHash.Compute("modified content"u8);

        var verifyResult = await _verifyHandler.HandleAsync(
            new VerifyAssetQuery(assetId, modifiedHash));

        // Should be Broken
        Assert.Equal(TrustLevel.Broken, verifyResult.TrustLevel);
        Assert.False(verifyResult.HashMatches);
    }

    [Fact]
    public async Task Verify_DerivedAsset_Returns_Derived()
    {
        // 1. Create identity
        var identityResult = await _createIdentityHandler.HandleAsync(
            new CreateIdentityCommand("Remix Artist"));

        // 2. Create and attest parent asset
        var parentAssetId = AssetId.New();
        var parentHash = ContentHash.Compute("original artwork"u8);

        await _attestHandler.HandleAsync(
            new AttestAssetCommand(parentAssetId, parentHash, identityResult.CreatorId));

        // 3. Create derived asset
        var derivedAssetId = AssetId.New();
        var derivedHash = ContentHash.Compute("remix version"u8);

        await _deriveHandler.HandleAsync(
            new DeriveAssetCommand(derivedAssetId, derivedHash, identityResult.CreatorId, parentAssetId));

        // 4. Verify derived asset
        var verifyResult = await _verifyHandler.HandleAsync(
            new VerifyAssetQuery(derivedAssetId, derivedHash));

        // Should be Derived
        Assert.Equal(TrustLevel.Derived, verifyResult.TrustLevel);
        Assert.Equal(parentAssetId, verifyResult.ParentAssetId);
        Assert.True(verifyResult.ParentChainValid);
    }

    [Fact]
    public async Task Export_ProducesVerifiableBundle()
    {
        // 1. Create identity and attest
        var identityResult = await _createIdentityHandler.HandleAsync(
            new CreateIdentityCommand("Exporter"));

        var assetId = AssetId.New();
        var contentHash = ContentHash.Compute("exportable content"u8);

        await _attestHandler.HandleAsync(
            new AttestAssetCommand(assetId, contentHash, identityResult.CreatorId));

        // 2. Export proof bundle
        var bundle = await _exportHandler.HandleAsync(
            new ExportProofBundleCommand(assetId));

        // 3. Verify bundle structure
        Assert.Equal("proof.v1", bundle.Version);
        Assert.NotNull(bundle.LedgerTipHash);
        Assert.NotEmpty(bundle.LedgerTipHash);
        Assert.Single(bundle.Attestations);
        Assert.Single(bundle.Creators);

        // 4. Verify the bundle is self-contained and verifiable
        var attestation = bundle.Attestations[0];

        // Parse public key from the attestation (self-contained)
        var publicKey = Ed25519PublicKey.Parse(attestation.CreatorPublicKey);

        // Reconstruct signable from bundle data
        var signable = SigningService.FromEvent(
            attestation.AssetId,
            attestation.ContentHash,
            attestation.CreatorId,
            attestation.CreatorPublicKey,
            attestation.AttestedAtUtc);

        // Parse signature
        var signature = Ed25519Signature.Parse(attestation.Signature);

        // Verify signature (no database needed!)
        var isValid = SigningService.Verify(signable, signature, publicKey);
        Assert.True(isValid);
    }

    [Fact]
    public async Task ChainContinuity_MultipleEvents_MaintainsChain()
    {
        // Create identity
        var identity1 = await _createIdentityHandler.HandleAsync(
            new CreateIdentityCommand("Chain Test 1"));

        var identity2 = await _createIdentityHandler.HandleAsync(
            new CreateIdentityCommand("Chain Test 2"));

        // Attest multiple assets
        for (int i = 0; i < 3; i++)
        {
            var contentBytes = System.Text.Encoding.UTF8.GetBytes($"asset_{i}");
            await _attestHandler.HandleAsync(
                new AttestAssetCommand(
                    AssetId.New(),
                    ContentHash.Compute(contentBytes),
                    identity1.CreatorId));
        }

        // Verify event count and chain
        var eventCount = await _fixture.LedgerRepository.GetEventCountAsync();
        Assert.True(eventCount >= 5); // 2 creator events + 3 attestation events

        // Verify tip is non-zero
        var tip = await _fixture.LedgerRepository.GetLedgerTipAsync();
        Assert.NotEqual(Digest256.Zero, tip);
    }

    [Fact]
    public async Task Export_DerivedAsset_IncludesParentChain()
    {
        // 1. Create identity
        var identityResult = await _createIdentityHandler.HandleAsync(
            new CreateIdentityCommand("Chain Exporter"));

        // 2. Create parent asset
        var parentAssetId = AssetId.New();
        await _attestHandler.HandleAsync(
            new AttestAssetCommand(parentAssetId, ContentHash.Compute("parent"u8), identityResult.CreatorId));

        // 3. Create derived asset
        var derivedAssetId = AssetId.New();
        await _deriveHandler.HandleAsync(
            new DeriveAssetCommand(derivedAssetId, ContentHash.Compute("derived"u8), identityResult.CreatorId, parentAssetId));

        // 4. Export the derived asset
        var bundle = await _exportHandler.HandleAsync(
            new ExportProofBundleCommand(derivedAssetId));

        // Should include both parent and derived attestations
        Assert.Equal(2, bundle.Attestations.Count);

        var derivedAttestation = bundle.Attestations.First(a => a.AssetId == derivedAssetId.ToString());
        Assert.Equal(parentAssetId.ToString(), derivedAttestation.DerivedFromAssetId);
    }
}
