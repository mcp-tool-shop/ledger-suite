using System.Text.Json;
using CreatorLedger.Application.Attestation;
using CreatorLedger.Application.Export;
using CreatorLedger.Application.Identity;
using CreatorLedger.Cli.Verification;
using CreatorLedger.Domain.Primitives;
using CreatorLedger.Tests.Fakes;
using Shared.Crypto;

namespace CreatorLedger.Tests.Cli;

/// <summary>
/// Tests for the CLI bundle verifier.
/// </summary>
public class BundleVerifierTests : IDisposable
{
    private readonly string _tempDir;
    private readonly InMemoryLedgerRepository _ledgerRepo;
    private readonly InMemoryCreatorIdentityRepository _identityRepo;
    private readonly InMemoryKeyVault _keyVault;
    private readonly FakeClock _clock;

    private readonly CreateIdentityHandler _createIdentityHandler;
    private readonly AttestAssetHandler _attestHandler;
    private readonly ExportProofBundleHandler _exportHandler;

    public BundleVerifierTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"cli_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);

        _ledgerRepo = new InMemoryLedgerRepository();
        _identityRepo = new InMemoryCreatorIdentityRepository();
        _keyVault = new InMemoryKeyVault();
        _clock = new FakeClock();

        _createIdentityHandler = new CreateIdentityHandler(
            _keyVault, _identityRepo, _ledgerRepo, _clock);

        _attestHandler = new AttestAssetHandler(
            _keyVault, _identityRepo, _ledgerRepo, _clock);

        _exportHandler = new ExportProofBundleHandler(
            _ledgerRepo, _identityRepo, _clock);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDir))
                Directory.Delete(_tempDir, recursive: true);
        }
        catch { }
    }

    [Fact]
    public async Task Verify_ValidBundle_ReturnsVerified()
    {
        // Create identity and attest
        var identity = await _createIdentityHandler.HandleAsync(new CreateIdentityCommand("Test Artist"));
        var assetId = AssetId.New();
        var content = "test artwork content"u8.ToArray();
        var contentHash = ContentHash.Compute(content);

        await _attestHandler.HandleAsync(new AttestAssetCommand(assetId, contentHash, identity.CreatorId));

        // Export bundle
        var bundle = await _exportHandler.HandleAsync(new ExportProofBundleCommand(assetId));
        var bundlePath = Path.Combine(_tempDir, "bundle.json");
        await File.WriteAllTextAsync(bundlePath, JsonSerializer.Serialize(bundle));

        // Verify
        var verifier = new BundleVerifier();
        var result = verifier.Verify(bundlePath);

        Assert.Equal(VerificationStatus.Verified, result.Status);
        Assert.Equal("Signed", result.TrustLevel);
        Assert.Equal(1, result.SignaturesValid);
        Assert.Equal(0, result.SignaturesFailed);
    }

    [Fact]
    public async Task Verify_WithMatchingAssetFile_ReturnsVerified()
    {
        // Create identity and attest
        var identity = await _createIdentityHandler.HandleAsync(new CreateIdentityCommand("Asset Verifier"));
        var assetId = AssetId.New();
        var content = "my artwork file content"u8.ToArray();
        var contentHash = ContentHash.Compute(content);

        await _attestHandler.HandleAsync(new AttestAssetCommand(assetId, contentHash, identity.CreatorId));

        // Export bundle
        var bundle = await _exportHandler.HandleAsync(new ExportProofBundleCommand(assetId));
        var bundlePath = Path.Combine(_tempDir, "bundle.json");
        await File.WriteAllTextAsync(bundlePath, JsonSerializer.Serialize(bundle));

        // Write asset file
        var assetPath = Path.Combine(_tempDir, "artwork.bin");
        await File.WriteAllBytesAsync(assetPath, content);

        // Verify with asset
        var verifier = new BundleVerifier();
        var result = verifier.Verify(bundlePath, assetPath);

        Assert.Equal(VerificationStatus.Verified, result.Status);
        Assert.True(result.HashMatches);
    }

    [Fact]
    public async Task Verify_WithMismatchedAssetFile_ReturnsBroken()
    {
        // Create identity and attest
        var identity = await _createIdentityHandler.HandleAsync(new CreateIdentityCommand("Hash Mismatch Test"));
        var assetId = AssetId.New();
        var originalContent = "original content"u8.ToArray();
        var contentHash = ContentHash.Compute(originalContent);

        await _attestHandler.HandleAsync(new AttestAssetCommand(assetId, contentHash, identity.CreatorId));

        // Export bundle
        var bundle = await _exportHandler.HandleAsync(new ExportProofBundleCommand(assetId));
        var bundlePath = Path.Combine(_tempDir, "bundle.json");
        await File.WriteAllTextAsync(bundlePath, JsonSerializer.Serialize(bundle));

        // Write DIFFERENT content to asset file
        var assetPath = Path.Combine(_tempDir, "modified.bin");
        await File.WriteAllBytesAsync(assetPath, "modified content"u8.ToArray());

        // Verify with mismatched asset
        var verifier = new BundleVerifier();
        var result = verifier.Verify(bundlePath, assetPath);

        Assert.Equal(VerificationStatus.Broken, result.Status);
        Assert.False(result.HashMatches);
        Assert.Contains("mismatch", result.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Verify_TamperedSignature_ReturnsBroken()
    {
        // Create identity and attest
        var identity = await _createIdentityHandler.HandleAsync(new CreateIdentityCommand("Tamper Test"));
        var assetId = AssetId.New();
        var contentHash = ContentHash.Compute("test"u8);

        await _attestHandler.HandleAsync(new AttestAssetCommand(assetId, contentHash, identity.CreatorId));

        // Export bundle
        var bundle = await _exportHandler.HandleAsync(new ExportProofBundleCommand(assetId));

        // Tamper with signature
        var tamperedAttestations = bundle.Attestations.Select(a => new AttestationProof
        {
            AttestationId = a.AttestationId,
            AssetId = a.AssetId,
            ContentHash = a.ContentHash,
            CreatorId = a.CreatorId,
            CreatorPublicKey = a.CreatorPublicKey,
            AttestedAtUtc = a.AttestedAtUtc,
            Signature = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // Invalid
            EventType = a.EventType
        }).ToList();

        var tampered = new ProofBundle
        {
            Version = bundle.Version,
            Algorithms = bundle.Algorithms,
            ExportedAtUtc = bundle.ExportedAtUtc,
            AssetId = bundle.AssetId,
            Attestations = tamperedAttestations,
            Creators = bundle.Creators,
            Anchor = bundle.Anchor,
            LedgerTipHash = bundle.LedgerTipHash
        };

        var bundlePath = Path.Combine(_tempDir, "tampered.json");
        await File.WriteAllTextAsync(bundlePath, JsonSerializer.Serialize(tampered));

        // Verify
        var verifier = new BundleVerifier();
        var result = verifier.Verify(bundlePath);

        Assert.Equal(VerificationStatus.Broken, result.Status);
        Assert.True(result.SignaturesFailed > 0);
    }

    [Fact]
    public void Verify_NonExistentBundle_ReturnsInvalidInput()
    {
        var verifier = new BundleVerifier();
        var result = verifier.Verify("/nonexistent/path/bundle.json");

        Assert.Equal(VerificationStatus.InvalidInput, result.Status);
        Assert.Contains("not found", result.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Verify_InvalidJson_ReturnsInvalidInput()
    {
        var bundlePath = Path.Combine(_tempDir, "invalid.json");
        File.WriteAllText(bundlePath, "{ not valid json }}}");

        var verifier = new BundleVerifier();
        var result = verifier.Verify(bundlePath);

        Assert.Equal(VerificationStatus.InvalidInput, result.Status);
    }

    [Fact]
    public void Verify_WrongVersion_ReturnsInvalidInput()
    {
        var bundlePath = Path.Combine(_tempDir, "wrong_version.json");
        File.WriteAllText(bundlePath, """
            {
                "version": "proof.v99",
                "assetId": "test",
                "attestations": [],
                "creators": [],
                "ledgerTipHash": "abc123",
                "exportedAtUtc": "2024-01-01T00:00:00Z",
                "algorithms": { "signature": "Ed25519", "hash": "SHA-256", "encoding": "UTF-8" }
            }
            """);

        var verifier = new BundleVerifier();
        var result = verifier.Verify(bundlePath);

        Assert.Equal(VerificationStatus.InvalidInput, result.Status);
        Assert.Contains("version", result.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Verify_ExitCode_MatchesStatus()
    {
        // Verified = 0
        Assert.Equal(0, (int)VerificationStatus.Verified);

        // Unverified = 2
        Assert.Equal(2, (int)VerificationStatus.Unverified);

        // Broken = 3
        Assert.Equal(3, (int)VerificationStatus.Broken);

        // InvalidInput = 4
        Assert.Equal(4, (int)VerificationStatus.InvalidInput);

        // Error = 5
        Assert.Equal(5, (int)VerificationStatus.Error);
    }
}
