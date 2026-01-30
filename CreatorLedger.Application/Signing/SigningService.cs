using CreatorLedger.Domain.Primitives;
using Shared.Crypto;

namespace CreatorLedger.Application.Signing;

/// <summary>
/// Service for creating and verifying attestation signatures.
/// Encapsulates the "bytes to sign" contract.
///
/// CRITICAL: All signing goes through CanonicalJson.SerializeToBytes().
/// No other serialization method is valid for signatures.
/// </summary>
public static class SigningService
{
    /// <summary>
    /// Creates an attestation signable DTO for an original asset.
    /// </summary>
    public static AttestationSignable CreateOriginalSignable(
        AssetId assetId,
        ContentHash contentHash,
        CreatorId creatorId,
        Ed25519PublicKey creatorPublicKey,
        DateTimeOffset attestedAtUtc)
    {
        return new AttestationSignable
        {
            AssetId = assetId.ToString(),
            ContentHash = contentHash.ToString(),
            CreatorId = creatorId.ToString(),
            CreatorPublicKey = creatorPublicKey.ToString(),
            AttestedAtUtc = CanonicalJson.FormatTimestamp(attestedAtUtc),
            DerivedFromAssetId = null,
            DerivedFromAttestationId = null
        };
    }

    /// <summary>
    /// Creates an attestation signable DTO for a derived asset.
    /// </summary>
    public static AttestationSignable CreateDerivedSignable(
        AssetId assetId,
        ContentHash contentHash,
        CreatorId creatorId,
        Ed25519PublicKey creatorPublicKey,
        DateTimeOffset attestedAtUtc,
        AssetId parentAssetId,
        AttestationId? parentAttestationId = null)
    {
        return new AttestationSignable
        {
            AssetId = assetId.ToString(),
            ContentHash = contentHash.ToString(),
            CreatorId = creatorId.ToString(),
            CreatorPublicKey = creatorPublicKey.ToString(),
            AttestedAtUtc = CanonicalJson.FormatTimestamp(attestedAtUtc),
            DerivedFromAssetId = parentAssetId.ToString(),
            DerivedFromAttestationId = parentAttestationId?.ToString()
        };
    }

    /// <summary>
    /// Signs an attestation signable with the given private key.
    /// CRITICAL: Only uses CanonicalJson for byte representation.
    /// </summary>
    public static Ed25519Signature Sign(AttestationSignable signable, Ed25519PrivateKey privateKey)
    {
        var bytes = CanonicalJson.SerializeToBytes(signable);
        return privateKey.Sign(bytes);
    }

    /// <summary>
    /// Verifies an attestation signature against a signable DTO.
    /// Also verifies the public key in the signable matches the provided key.
    /// </summary>
    public static bool Verify(AttestationSignable signable, Ed25519Signature signature, Ed25519PublicKey publicKey)
    {
        // Verify the signable's public key matches the provided key
        if (signable.CreatorPublicKey != publicKey.ToString())
            return false;

        var bytes = CanonicalJson.SerializeToBytes(signable);
        return publicKey.Verify(bytes, signature);
    }

    /// <summary>
    /// Reconstructs a signable from attestation event data for verification.
    /// </summary>
    public static AttestationSignable FromEvent(
        string assetId,
        string contentHash,
        string creatorId,
        string creatorPublicKey,
        string attestedAtUtc,
        string? derivedFromAssetId = null,
        string? derivedFromAttestationId = null)
    {
        return new AttestationSignable
        {
            AssetId = assetId,
            ContentHash = contentHash,
            CreatorId = creatorId,
            CreatorPublicKey = creatorPublicKey,
            AttestedAtUtc = attestedAtUtc,
            DerivedFromAssetId = derivedFromAssetId,
            DerivedFromAttestationId = derivedFromAttestationId
        };
    }
}
