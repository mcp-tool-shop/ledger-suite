using System.Text.Json.Serialization;

namespace CreatorLedger.Application.Export;

/// <summary>
/// A standalone proof bundle that can verify asset provenance without database access.
/// </summary>
public sealed class ProofBundle
{
    /// <summary>
    /// Schema version for forward compatibility.
    /// </summary>
    [JsonPropertyOrder(0)]
    public string Version { get; init; } = "proof.v1";

    /// <summary>
    /// Cryptographic algorithms used in this proof bundle.
    /// Enables verifiers to know what algorithms to use without hardcoding.
    /// </summary>
    [JsonPropertyOrder(1)]
    public AlgorithmsInfo Algorithms { get; init; } = AlgorithmsInfo.Default;

    /// <summary>
    /// When this proof was exported.
    /// </summary>
    [JsonPropertyOrder(2)]
    public required string ExportedAtUtc { get; init; }

    /// <summary>
    /// The asset this proof is for.
    /// </summary>
    [JsonPropertyOrder(3)]
    public required string AssetId { get; init; }

    /// <summary>
    /// The attestation chain for this asset.
    /// </summary>
    [JsonPropertyOrder(4)]
    public required List<AttestationProof> Attestations { get; init; }

    /// <summary>
    /// All creator public keys needed to verify signatures.
    /// </summary>
    [JsonPropertyOrder(5)]
    public required List<CreatorProof> Creators { get; init; }

    /// <summary>
    /// Optional blockchain anchor reference.
    /// </summary>
    [JsonPropertyOrder(6)]
    public AnchorProof? Anchor { get; init; }

    /// <summary>
    /// Hash of the ledger tip at export time.
    /// Allows verification that exported events are part of a consistent chain.
    /// </summary>
    [JsonPropertyOrder(7)]
    public required string LedgerTipHash { get; init; }
}

/// <summary>
/// Cryptographic algorithms used in the proof bundle.
/// </summary>
public sealed class AlgorithmsInfo
{
    /// <summary>
    /// Default algorithms for v1 proof bundles.
    /// </summary>
    public static readonly AlgorithmsInfo Default = new()
    {
        Signature = "Ed25519",
        Hash = "SHA-256",
        Encoding = "UTF-8"
    };

    /// <summary>
    /// Signature algorithm (e.g., "Ed25519").
    /// </summary>
    [JsonPropertyOrder(0)]
    public required string Signature { get; init; }

    /// <summary>
    /// Hash algorithm for content hashing and event chaining (e.g., "SHA-256").
    /// </summary>
    [JsonPropertyOrder(1)]
    public required string Hash { get; init; }

    /// <summary>
    /// Text encoding for canonical JSON (e.g., "UTF-8").
    /// </summary>
    [JsonPropertyOrder(2)]
    public required string Encoding { get; init; }
}

/// <summary>
/// Proof of a single attestation.
/// Contains all data needed to reconstruct the signable and verify the signature.
/// </summary>
public sealed class AttestationProof
{
    [JsonPropertyOrder(0)]
    public required string AttestationId { get; init; }

    [JsonPropertyOrder(1)]
    public required string AssetId { get; init; }

    [JsonPropertyOrder(2)]
    public required string ContentHash { get; init; }

    [JsonPropertyOrder(3)]
    public required string CreatorId { get; init; }

    /// <summary>
    /// Creator's public key at time of attestation.
    /// Included for self-contained verification (supports key rotation).
    /// </summary>
    [JsonPropertyOrder(4)]
    public required string CreatorPublicKey { get; init; }

    [JsonPropertyOrder(5)]
    public required string AttestedAtUtc { get; init; }

    [JsonPropertyOrder(6)]
    public required string Signature { get; init; }

    [JsonPropertyOrder(7)]
    public string? DerivedFromAssetId { get; init; }

    [JsonPropertyOrder(8)]
    public string? DerivedFromAttestationId { get; init; }

    [JsonPropertyOrder(9)]
    public required string EventType { get; init; }
}

/// <summary>
/// Creator public key for signature verification.
/// </summary>
public sealed class CreatorProof
{
    [JsonPropertyOrder(0)]
    public required string CreatorId { get; init; }

    [JsonPropertyOrder(1)]
    public required string PublicKey { get; init; }

    [JsonPropertyOrder(2)]
    public string? DisplayName { get; init; }
}

/// <summary>
/// Blockchain anchor reference.
/// </summary>
public sealed class AnchorProof
{
    [JsonPropertyOrder(0)]
    public required string ChainName { get; init; }

    [JsonPropertyOrder(1)]
    public required string TransactionId { get; init; }

    [JsonPropertyOrder(2)]
    public required string LedgerRootHash { get; init; }

    [JsonPropertyOrder(3)]
    public long? BlockNumber { get; init; }

    [JsonPropertyOrder(4)]
    public required string AnchoredAtUtc { get; init; }
}
