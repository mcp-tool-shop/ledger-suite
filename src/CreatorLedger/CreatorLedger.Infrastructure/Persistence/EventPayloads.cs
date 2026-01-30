using System.Text.Json.Serialization;

namespace CreatorLedger.Infrastructure.Persistence;

/// <summary>
/// Event payload DTOs for canonical JSON serialization.
/// These define EXACTLY what goes into payload_json and gets hashed.
///
/// CRITICAL: Property order is deterministic via JsonPropertyOrder.
/// DO NOT change property order after deployment.
/// </summary>
internal static class EventPayloads
{
    public const string SchemaVersion = "event.v1";

    /// <summary>
    /// Payload for asset_attested events.
    /// </summary>
    public sealed class AssetAttestedPayload
    {
        [JsonPropertyOrder(0)]
        public required string AttestationId { get; init; }

        [JsonPropertyOrder(1)]
        public required string AssetId { get; init; }

        [JsonPropertyOrder(2)]
        public required string ContentHash { get; init; }

        [JsonPropertyOrder(3)]
        public required string CreatorId { get; init; }

        [JsonPropertyOrder(4)]
        public required string CreatorPublicKey { get; init; }
    }

    /// <summary>
    /// Payload for asset_derived events.
    /// </summary>
    public sealed class AssetDerivedPayload
    {
        [JsonPropertyOrder(0)]
        public required string AttestationId { get; init; }

        [JsonPropertyOrder(1)]
        public required string AssetId { get; init; }

        [JsonPropertyOrder(2)]
        public required string ContentHash { get; init; }

        [JsonPropertyOrder(3)]
        public required string CreatorId { get; init; }

        [JsonPropertyOrder(4)]
        public required string CreatorPublicKey { get; init; }

        [JsonPropertyOrder(5)]
        public required string ParentAssetId { get; init; }

        [JsonPropertyOrder(6)]
        public string? ParentAttestationId { get; init; }
    }

    /// <summary>
    /// Payload for creator_created events.
    /// </summary>
    public sealed class CreatorCreatedPayload
    {
        [JsonPropertyOrder(0)]
        public required string CreatorId { get; init; }

        [JsonPropertyOrder(1)]
        public required string PublicKey { get; init; }

        [JsonPropertyOrder(2)]
        public string? DisplayName { get; init; }
    }

    /// <summary>
    /// Payload for ledger_anchored events.
    /// </summary>
    public sealed class LedgerAnchoredPayload
    {
        [JsonPropertyOrder(0)]
        public required string LedgerRootHash { get; init; }

        [JsonPropertyOrder(1)]
        public required string ChainName { get; init; }

        [JsonPropertyOrder(2)]
        public required string TransactionId { get; init; }

        [JsonPropertyOrder(3)]
        public long? BlockNumber { get; init; }
    }

    /// <summary>
    /// Payload for asset_exported events.
    /// </summary>
    public sealed class AssetExportedPayload
    {
        [JsonPropertyOrder(0)]
        public required string AssetId { get; init; }

        [JsonPropertyOrder(1)]
        public required string AttestationId { get; init; }

        [JsonPropertyOrder(2)]
        public string? ExportTarget { get; init; }
    }
}
