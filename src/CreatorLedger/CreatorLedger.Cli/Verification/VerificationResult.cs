namespace CreatorLedger.Cli.Verification;

/// <summary>
/// Result of verifying a proof bundle.
/// </summary>
public sealed class VerificationResult
{
    /// <summary>
    /// Overall verification status.
    /// </summary>
    public required VerificationStatus Status { get; init; }

    /// <summary>
    /// Human-readable trust level.
    /// </summary>
    public required string TrustLevel { get; init; }

    /// <summary>
    /// Primary reason for the result.
    /// </summary>
    public required string Reason { get; init; }

    /// <summary>
    /// Asset ID from the bundle.
    /// </summary>
    public required string AssetId { get; init; }

    /// <summary>
    /// Content hash from the attestation.
    /// </summary>
    public string? AttestedContentHash { get; init; }

    /// <summary>
    /// Content hash computed from the provided asset file (if any).
    /// </summary>
    public string? ComputedContentHash { get; init; }

    /// <summary>
    /// Whether the content hash matches (if asset file was provided).
    /// </summary>
    public bool? HashMatches { get; init; }

    /// <summary>
    /// Number of attestations verified.
    /// </summary>
    public int AttestationsVerified { get; init; }

    /// <summary>
    /// Number of signatures that passed verification.
    /// </summary>
    public int SignaturesValid { get; init; }

    /// <summary>
    /// Number of signatures that failed verification.
    /// </summary>
    public int SignaturesFailed { get; init; }

    /// <summary>
    /// Creator information for the primary attestation.
    /// </summary>
    public CreatorInfo? Creator { get; init; }

    /// <summary>
    /// Attestation timestamp.
    /// </summary>
    public string? AttestedAtUtc { get; init; }

    /// <summary>
    /// Anchor information if present.
    /// </summary>
    public AnchorInfo? Anchor { get; init; }

    /// <summary>
    /// Detailed verification steps (for verbose output).
    /// </summary>
    public List<string> Steps { get; init; } = new();

    /// <summary>
    /// Errors encountered during verification.
    /// </summary>
    public List<string> Errors { get; init; } = new();
}

/// <summary>
/// Overall verification status (maps to exit codes).
/// </summary>
public enum VerificationStatus
{
    /// <summary>
    /// Verification passed - asset is authentic.
    /// Exit code: 0
    /// </summary>
    Verified = 0,

    /// <summary>
    /// Not verified but structurally valid (e.g., unknown creator).
    /// Exit code: 2
    /// </summary>
    Unverified = 2,

    /// <summary>
    /// Verification failed - tamper detected or invalid.
    /// Exit code: 3
    /// </summary>
    Broken = 3,

    /// <summary>
    /// Input/parse error (bad JSON, missing fields).
    /// Exit code: 4
    /// </summary>
    InvalidInput = 4,

    /// <summary>
    /// Runtime error.
    /// Exit code: 5
    /// </summary>
    Error = 5
}

/// <summary>
/// Creator information for display.
/// </summary>
public sealed class CreatorInfo
{
    public required string CreatorId { get; init; }
    public required string PublicKey { get; init; }
    public string? DisplayName { get; init; }

    /// <summary>
    /// Short form of public key for display (first 12 chars).
    /// </summary>
    public string ShortPublicKey => PublicKey.Length > 12 ? PublicKey[..12] + "..." : PublicKey;
}

/// <summary>
/// Anchor information for display.
/// </summary>
public sealed class AnchorInfo
{
    public required string ChainName { get; init; }
    public required string TransactionId { get; init; }
    public long? BlockNumber { get; init; }
    public required string AnchoredAtUtc { get; init; }
}
