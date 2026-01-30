using CreatorLedger.Application.Signing;
using CreatorLedger.Domain.Primitives;
using Shared.Crypto;

namespace CreatorLedger.Tests.Application;

public class SigningServiceTests
{
    [Fact]
    public void CreateOriginalSignable_HasCorrectVersion()
    {
        using var keyPair = Ed25519KeyPair.Generate();
        var signable = SigningService.CreateOriginalSignable(
            AssetId.New(),
            ContentHash.Compute("test"u8),
            CreatorId.New(),
            keyPair.PublicKey,
            DateTimeOffset.UtcNow);

        Assert.Equal("attestation.v1", signable.Version);
    }

    [Fact]
    public void CreateOriginalSignable_HasNullDerivedFields()
    {
        using var keyPair = Ed25519KeyPair.Generate();
        var signable = SigningService.CreateOriginalSignable(
            AssetId.New(),
            ContentHash.Compute("test"u8),
            CreatorId.New(),
            keyPair.PublicKey,
            DateTimeOffset.UtcNow);

        Assert.Null(signable.DerivedFromAssetId);
        Assert.Null(signable.DerivedFromAttestationId);
    }

    [Fact]
    public void CreateOriginalSignable_IncludesPublicKey()
    {
        using var keyPair = Ed25519KeyPair.Generate();
        var signable = SigningService.CreateOriginalSignable(
            AssetId.New(),
            ContentHash.Compute("test"u8),
            CreatorId.New(),
            keyPair.PublicKey,
            DateTimeOffset.UtcNow);

        Assert.Equal(keyPair.PublicKey.ToString(), signable.CreatorPublicKey);
    }

    [Fact]
    public void CreateDerivedSignable_HasParentFields()
    {
        using var keyPair = Ed25519KeyPair.Generate();
        var parentAssetId = AssetId.New();
        var parentAttestationId = AttestationId.New();

        var signable = SigningService.CreateDerivedSignable(
            AssetId.New(),
            ContentHash.Compute("derived"u8),
            CreatorId.New(),
            keyPair.PublicKey,
            DateTimeOffset.UtcNow,
            parentAssetId,
            parentAttestationId);

        Assert.Equal(parentAssetId.ToString(), signable.DerivedFromAssetId);
        Assert.Equal(parentAttestationId.ToString(), signable.DerivedFromAttestationId);
    }

    [Fact]
    public void SignAndVerify_RoundTrip()
    {
        using var keyPair = Ed25519KeyPair.Generate();

        var signable = SigningService.CreateOriginalSignable(
            AssetId.New(),
            ContentHash.Compute("content"u8),
            CreatorId.New(),
            keyPair.PublicKey,
            DateTimeOffset.UtcNow);

        var signature = SigningService.Sign(signable, keyPair.PrivateKey);
        var isValid = SigningService.Verify(signable, signature, keyPair.PublicKey);

        Assert.True(isValid);
    }

    [Fact]
    public void Verify_WrongKey_Fails()
    {
        using var signerKey = Ed25519KeyPair.Generate();
        using var wrongKey = Ed25519KeyPair.Generate();

        // Note: signable is created with the signer's public key
        var signable = SigningService.CreateOriginalSignable(
            AssetId.New(),
            ContentHash.Compute("content"u8),
            CreatorId.New(),
            signerKey.PublicKey,
            DateTimeOffset.UtcNow);

        var signature = SigningService.Sign(signable, signerKey.PrivateKey);

        // Verification with wrong key should fail because public key in signable doesn't match
        var isValid = SigningService.Verify(signable, signature, wrongKey.PublicKey);

        Assert.False(isValid);
    }

    [Fact]
    public void Verify_ModifiedContent_Fails()
    {
        using var keyPair = Ed25519KeyPair.Generate();
        var assetId = AssetId.New();
        var creatorId = CreatorId.New();
        var timestamp = DateTimeOffset.UtcNow;

        var originalSignable = SigningService.CreateOriginalSignable(
            assetId,
            ContentHash.Compute("original"u8),
            creatorId,
            keyPair.PublicKey,
            timestamp);

        var signature = SigningService.Sign(originalSignable, keyPair.PrivateKey);

        // Try to verify with different content hash
        var tamperedSignable = SigningService.CreateOriginalSignable(
            assetId,
            ContentHash.Compute("tampered"u8),
            creatorId,
            keyPair.PublicKey,
            timestamp);

        var isValid = SigningService.Verify(tamperedSignable, signature, keyPair.PublicKey);

        Assert.False(isValid);
    }

    [Fact]
    public void FromEvent_ReconstructsSignable()
    {
        using var keyPair = Ed25519KeyPair.Generate();
        var assetId = AssetId.New();
        var contentHash = ContentHash.Compute("data"u8);
        var creatorId = CreatorId.New();
        var timestamp = DateTimeOffset.UtcNow;

        var original = SigningService.CreateOriginalSignable(
            assetId, contentHash, creatorId, keyPair.PublicKey, timestamp);

        var reconstructed = SigningService.FromEvent(
            assetId.ToString(),
            contentHash.ToString(),
            creatorId.ToString(),
            keyPair.PublicKey.ToString(),
            CanonicalJson.FormatTimestamp(timestamp));

        // Both should produce same bytes for signing
        var originalBytes = CanonicalJson.SerializeToBytes(original);
        var reconstructedBytes = CanonicalJson.SerializeToBytes(reconstructed);

        Assert.Equal(originalBytes, reconstructedBytes);
    }

    [Fact]
    public void Signable_IsDeterministic()
    {
        using var keyPair = Ed25519KeyPair.Generate();
        var assetId = AssetId.New();
        var contentHash = ContentHash.Compute("data"u8);
        var creatorId = CreatorId.New();
        var timestamp = new DateTimeOffset(2024, 6, 15, 12, 0, 0, TimeSpan.Zero);

        var signable1 = SigningService.CreateOriginalSignable(assetId, contentHash, creatorId, keyPair.PublicKey, timestamp);
        var signable2 = SigningService.CreateOriginalSignable(assetId, contentHash, creatorId, keyPair.PublicKey, timestamp);

        var bytes1 = CanonicalJson.SerializeToBytes(signable1);
        var bytes2 = CanonicalJson.SerializeToBytes(signable2);

        Assert.Equal(bytes1, bytes2);
    }
}
