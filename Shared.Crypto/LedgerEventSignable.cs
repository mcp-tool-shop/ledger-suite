using System.Text.Json.Serialization;

namespace Shared.Crypto;

/// <summary>
/// Canonical representation of a ledger event for hashing.
/// This DTO defines EXACTLY what bytes go into event_hash computation.
///
/// CONTRACT VERSION: event.v1
/// DO NOT MODIFY after deployment - create LedgerEventSignableV2 instead.
///
/// Hash = SHA-256(CanonicalJson.SerializeToBytes(LedgerEventSignable))
/// </summary>
public sealed class LedgerEventSignable
{
    /// <summary>
    /// Schema version for forward compatibility.
    /// </summary>
    [JsonPropertyOrder(0)]
    public string Version { get; init; } = "event.v1";

    /// <summary>
    /// Event ID in GUID "D" format.
    /// </summary>
    [JsonPropertyOrder(1)]
    public required string EventId { get; init; }

    /// <summary>
    /// Monotonic sequence number (ordering key).
    /// </summary>
    [JsonPropertyOrder(2)]
    public required long Seq { get; init; }

    /// <summary>
    /// Event type identifier (e.g., "asset_attested", "creator_created").
    /// </summary>
    [JsonPropertyOrder(3)]
    public required string EventType { get; init; }

    /// <summary>
    /// Timestamp in ISO 8601 "O" format, always UTC.
    /// </summary>
    [JsonPropertyOrder(4)]
    public required string OccurredAtUtc { get; init; }

    /// <summary>
    /// Previous event's hash in lowercase hex (64 chars).
    /// Digest256.Zero hex for genesis event.
    /// </summary>
    [JsonPropertyOrder(5)]
    public required string PreviousEventHash { get; init; }

    /// <summary>
    /// The exact canonical JSON bytes of the event payload.
    /// This is stored as-is in payload_json column.
    /// </summary>
    [JsonPropertyOrder(6)]
    public required string PayloadJson { get; init; }

    /// <summary>
    /// Ed25519 signature in base64 format.
    /// Null for system events (CreatorCreated, LedgerAnchored, AssetExported).
    /// </summary>
    [JsonPropertyOrder(7)]
    public string? SignatureBase64 { get; init; }

    /// <summary>
    /// Creator's public key in "ed25519:base64" format.
    /// Null for system events without a creator.
    /// </summary>
    [JsonPropertyOrder(8)]
    public string? CreatorPublicKey { get; init; }
}

/// <summary>
/// Computes deterministic event hashes using the frozen LedgerEventSignable contract.
/// </summary>
public static class EventHasher
{
    /// <summary>
    /// Computes the canonical hash for a ledger event.
    /// This hash is stored in event_hash and used for chain verification.
    /// </summary>
    /// <param name="eventId">Event ID in GUID "D" format</param>
    /// <param name="seq">Monotonic sequence number</param>
    /// <param name="eventType">Event type identifier</param>
    /// <param name="occurredAtUtc">Timestamp (must be UTC)</param>
    /// <param name="previousEventHash">Previous event hash</param>
    /// <param name="payloadJson">Canonical JSON payload (stored in DB)</param>
    /// <param name="signatureBase64">Signature or null for system events</param>
    /// <param name="creatorPublicKey">Creator public key or null</param>
    /// <returns>SHA-256 digest of the canonical JSON representation</returns>
    public static Digest256 ComputeHash(
        string eventId,
        long seq,
        string eventType,
        DateTimeOffset occurredAtUtc,
        Digest256 previousEventHash,
        string payloadJson,
        string? signatureBase64,
        string? creatorPublicKey)
    {
        var signable = new LedgerEventSignable
        {
            EventId = eventId,
            Seq = seq,
            EventType = eventType,
            OccurredAtUtc = CanonicalJson.FormatTimestamp(occurredAtUtc),
            PreviousEventHash = previousEventHash.ToString(),
            PayloadJson = payloadJson,
            SignatureBase64 = signatureBase64,
            CreatorPublicKey = creatorPublicKey
        };

        return CanonicalJson.HashOf(signable);
    }

    /// <summary>
    /// Verifies that an event hash matches the expected value.
    /// Use this to validate stored events haven't been tampered with.
    /// </summary>
    public static bool VerifyHash(
        Digest256 expectedHash,
        string eventId,
        long seq,
        string eventType,
        DateTimeOffset occurredAtUtc,
        Digest256 previousEventHash,
        string payloadJson,
        string? signatureBase64,
        string? creatorPublicKey)
    {
        var computed = ComputeHash(
            eventId, seq, eventType, occurredAtUtc,
            previousEventHash, payloadJson, signatureBase64, creatorPublicKey);

        return computed == expectedHash;
    }
}
