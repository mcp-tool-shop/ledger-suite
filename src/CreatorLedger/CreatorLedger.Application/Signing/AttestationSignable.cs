using System.Text.Json.Serialization;

namespace CreatorLedger.Application.Signing;

/// <summary>
/// Stable, versioned DTO for attestation signing.
/// Field order is explicit and must never change for signature compatibility.
///
/// STABILITY CONTRACT:
/// - Field order is fixed (JsonPropertyOrder)
/// - Field names are fixed
/// - Adding fields requires version bump to "attestation.v2"
/// - GUIDs must be "D" format (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
/// - Timestamps must be ISO 8601 UTC ("O" format)
/// - Hashes must be lowercase hex
/// - Public key must be "ed25519:base64" format
/// </summary>
public sealed class AttestationSignable
{
    /// <summary>
    /// Schema version. Increment if structure changes.
    /// </summary>
    [JsonPropertyOrder(0)]
    public string Version { get; init; } = "attestation.v1";

    /// <summary>
    /// The asset being attested (GUID "D" format).
    /// </summary>
    [JsonPropertyOrder(1)]
    public required string AssetId { get; init; }

    /// <summary>
    /// SHA-256 hash of asset content (lowercase hex, 64 chars).
    /// </summary>
    [JsonPropertyOrder(2)]
    public required string ContentHash { get; init; }

    /// <summary>
    /// The creator making the attestation (GUID "D" format).
    /// </summary>
    [JsonPropertyOrder(3)]
    public required string CreatorId { get; init; }

    /// <summary>
    /// The creator's public key at time of signing ("ed25519:base64").
    /// Included for key rotation support - signature is bound to this specific key.
    /// </summary>
    [JsonPropertyOrder(4)]
    public required string CreatorPublicKey { get; init; }

    /// <summary>
    /// Timestamp in ISO 8601 UTC format ("O" format).
    /// </summary>
    [JsonPropertyOrder(5)]
    public required string AttestedAtUtc { get; init; }

    /// <summary>
    /// Optional: Parent asset ID if this is derived (GUID "D" format).
    /// </summary>
    [JsonPropertyOrder(6)]
    public string? DerivedFromAssetId { get; init; }

    /// <summary>
    /// Optional: Parent attestation ID for precise lineage (GUID "D" format).
    /// </summary>
    [JsonPropertyOrder(7)]
    public string? DerivedFromAttestationId { get; init; }
}
