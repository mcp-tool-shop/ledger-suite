using CreatorLedger.Domain.Attestation;
using CreatorLedger.Domain.Primitives;
using Shared.Crypto;

namespace CreatorLedger.Tests.Domain;

public class AssetAttestationTests
{
    private static (Ed25519Signature signature, ContentHash hash) CreateTestSignatureAndHash()
    {
        using var keyPair = Ed25519KeyPair.Generate();
        var data = "test asset content"u8.ToArray();
        var hash = ContentHash.Compute(data);
        var signature = keyPair.Sign(data);
        return (signature, hash);
    }

    [Fact]
    public void CreateOriginal_ValidInputs_Succeeds()
    {
        var (signature, contentHash) = CreateTestSignatureAndHash();
        var attestationId = AttestationId.New();
        var assetId = AssetId.New();
        var creatorId = CreatorId.New();
        var attestedAt = DateTimeOffset.UtcNow;

        var attestation = AssetAttestation.CreateOriginal(
            attestationId, assetId, contentHash, creatorId, attestedAt, signature);

        Assert.Equal(attestationId, attestation.Id);
        Assert.Equal(assetId, attestation.AssetId);
        Assert.Equal(contentHash, attestation.ContentHash);
        Assert.Equal(creatorId, attestation.CreatorId);
        Assert.Equal(attestedAt, attestation.AttestedAtUtc);
        Assert.Equal(signature, attestation.Signature);
        Assert.False(attestation.IsDerived);
        Assert.Null(attestation.DerivedFromAssetId);
        Assert.Null(attestation.DerivedFromAttestationId);
    }

    [Fact]
    public void CreateDerived_ValidInputs_Succeeds()
    {
        var (signature, contentHash) = CreateTestSignatureAndHash();
        var attestationId = AttestationId.New();
        var assetId = AssetId.New();
        var creatorId = CreatorId.New();
        var attestedAt = DateTimeOffset.UtcNow;
        var parentAssetId = AssetId.New();
        var parentAttestationId = AttestationId.New();

        var attestation = AssetAttestation.CreateDerived(
            attestationId, assetId, contentHash, creatorId, attestedAt, signature,
            parentAssetId, parentAttestationId);

        Assert.True(attestation.IsDerived);
        Assert.Equal(parentAssetId, attestation.DerivedFromAssetId);
        Assert.Equal(parentAttestationId, attestation.DerivedFromAttestationId);
    }

    [Fact]
    public void CreateDerived_WithoutParentAttestationId_Succeeds()
    {
        var (signature, contentHash) = CreateTestSignatureAndHash();
        var attestationId = AttestationId.New();
        var assetId = AssetId.New();
        var creatorId = CreatorId.New();
        var attestedAt = DateTimeOffset.UtcNow;
        var parentAssetId = AssetId.New();

        var attestation = AssetAttestation.CreateDerived(
            attestationId, assetId, contentHash, creatorId, attestedAt, signature,
            parentAssetId);

        Assert.True(attestation.IsDerived);
        Assert.Equal(parentAssetId, attestation.DerivedFromAssetId);
        Assert.Null(attestation.DerivedFromAttestationId);
    }

    [Fact]
    public void CreateOriginal_NonUtcTimestamp_Throws()
    {
        var (signature, contentHash) = CreateTestSignatureAndHash();
        var attestationId = AttestationId.New();
        var assetId = AssetId.New();
        var creatorId = CreatorId.New();
        var nonUtc = new DateTimeOffset(2024, 1, 1, 12, 0, 0, TimeSpan.FromHours(-5));

        Assert.Throws<DomainException>(() =>
            AssetAttestation.CreateOriginal(
                attestationId, assetId, contentHash, creatorId, nonUtc, signature));
    }

    [Fact]
    public void CreateOriginal_EmptyContentHash_Throws()
    {
        using var keyPair = Ed25519KeyPair.Generate();
        var signature = keyPair.Sign("test"u8);
        var attestationId = AttestationId.New();
        var assetId = AssetId.New();
        var creatorId = CreatorId.New();
        var attestedAt = DateTimeOffset.UtcNow;
        ContentHash emptyHash = default;

        Assert.Throws<DomainException>(() =>
            AssetAttestation.CreateOriginal(
                attestationId, assetId, emptyHash, creatorId, attestedAt, signature));
    }

    [Fact]
    public void CreateOriginal_EmptySignature_Throws()
    {
        var contentHash = ContentHash.Compute("test"u8);
        var attestationId = AttestationId.New();
        var assetId = AssetId.New();
        var creatorId = CreatorId.New();
        var attestedAt = DateTimeOffset.UtcNow;
        Ed25519Signature emptySignature = default;

        Assert.Throws<DomainException>(() =>
            AssetAttestation.CreateOriginal(
                attestationId, assetId, contentHash, creatorId, attestedAt, emptySignature));
    }

    [Fact]
    public void Reconstitute_AllowsAnyData()
    {
        var (signature, contentHash) = CreateTestSignatureAndHash();
        var attestationId = AttestationId.New();
        var assetId = AssetId.New();
        var creatorId = CreatorId.New();
        var attestedAt = DateTimeOffset.UtcNow;
        var parentAssetId = AssetId.New();
        var parentAttestationId = AttestationId.New();

        var attestation = AssetAttestation.Reconstitute(
            attestationId, assetId, contentHash, creatorId, attestedAt, signature,
            parentAssetId, parentAttestationId);

        Assert.Equal(attestationId, attestation.Id);
        Assert.Equal(parentAssetId, attestation.DerivedFromAssetId);
        Assert.Equal(parentAttestationId, attestation.DerivedFromAttestationId);
    }
}
