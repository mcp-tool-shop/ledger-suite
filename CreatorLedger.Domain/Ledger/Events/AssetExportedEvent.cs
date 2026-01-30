using CreatorLedger.Domain.Primitives;
using Shared.Crypto;

namespace CreatorLedger.Domain.Ledger.Events;

/// <summary>
/// Event recording that an asset was exported with a proof bundle.
/// </summary>
public sealed class AssetExportedEvent : LedgerEvent
{
    public const string TypeName = "asset_exported";

    public override string EventType => TypeName;

    public AssetId AssetId { get; }
    public AttestationId AttestationId { get; }

    /// <summary>
    /// Optional description of export destination or purpose.
    /// </summary>
    public string? ExportTarget { get; }

    public AssetExportedEvent(
        EventId id,
        DateTimeOffset occurredAtUtc,
        Digest256 previousEventHash,
        AssetId assetId,
        AttestationId attestationId,
        string? exportTarget = null)
        : base(id, occurredAtUtc, previousEventHash)
    {
        AssetId = assetId;
        AttestationId = attestationId;
        ExportTarget = exportTarget;
    }
}
