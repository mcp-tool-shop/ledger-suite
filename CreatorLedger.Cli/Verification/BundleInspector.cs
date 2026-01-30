using System.Text.Json;
using CreatorLedger.Application.Export;

namespace CreatorLedger.Cli.Verification;

/// <summary>
/// Result of inspecting a proof bundle.
/// </summary>
public sealed class InspectionResult
{
    public required string Version { get; init; }
    public required string AssetId { get; init; }
    public required string ExportedAtUtc { get; init; }
    public required string LedgerTipHash { get; init; }
    public required AlgorithmsInfo Algorithms { get; init; }
    public required int AttestationCount { get; init; }
    public required int CreatorCount { get; init; }
    public required List<AttestationSummary> Attestations { get; init; }
    public required List<CreatorSummary> Creators { get; init; }
    public AnchorSummary? Anchor { get; init; }
}

public sealed class AttestationSummary
{
    public required string AttestationId { get; init; }
    public required string AssetId { get; init; }
    public required string EventType { get; init; }
    public required string AttestedAtUtc { get; init; }
    public required string CreatorId { get; init; }
    public required string ContentHashShort { get; init; }
    public string? DerivedFromAssetId { get; init; }
}

public sealed class CreatorSummary
{
    public required string CreatorId { get; init; }
    public required string PublicKeyShort { get; init; }
    public string? DisplayName { get; init; }
}

public sealed class AnchorSummary
{
    public required string ChainName { get; init; }
    public required string TransactionId { get; init; }
    public long? BlockNumber { get; init; }
    public required string AnchoredAtUtc { get; init; }
}

/// <summary>
/// Inspects proof bundles without verifying signatures.
/// </summary>
public sealed class BundleInspector
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    /// <summary>
    /// Inspects a proof bundle and returns structural information.
    /// </summary>
    public InspectionResult? Inspect(string bundlePath, out string? error)
    {
        error = null;

        try
        {
            var json = File.ReadAllText(bundlePath);
            var bundle = JsonSerializer.Deserialize<ProofBundle>(json, JsonOptions);

            if (bundle is null)
            {
                error = "Failed to deserialize proof bundle";
                return null;
            }

            return new InspectionResult
            {
                Version = bundle.Version,
                AssetId = bundle.AssetId,
                ExportedAtUtc = bundle.ExportedAtUtc,
                LedgerTipHash = bundle.LedgerTipHash,
                Algorithms = bundle.Algorithms,
                AttestationCount = bundle.Attestations.Count,
                CreatorCount = bundle.Creators.Count,
                Attestations = bundle.Attestations.Select(a => new AttestationSummary
                {
                    AttestationId = a.AttestationId,
                    AssetId = a.AssetId,
                    EventType = a.EventType,
                    AttestedAtUtc = a.AttestedAtUtc,
                    CreatorId = a.CreatorId,
                    ContentHashShort = a.ContentHash.Length > 16 ? a.ContentHash[..16] + "..." : a.ContentHash,
                    DerivedFromAssetId = a.DerivedFromAssetId
                }).ToList(),
                Creators = bundle.Creators.Select(c => new CreatorSummary
                {
                    CreatorId = c.CreatorId,
                    PublicKeyShort = c.PublicKey.Length > 20 ? c.PublicKey[..20] + "..." : c.PublicKey,
                    DisplayName = c.DisplayName
                }).ToList(),
                Anchor = bundle.Anchor is not null ? new AnchorSummary
                {
                    ChainName = bundle.Anchor.ChainName,
                    TransactionId = bundle.Anchor.TransactionId,
                    BlockNumber = bundle.Anchor.BlockNumber,
                    AnchoredAtUtc = bundle.Anchor.AnchoredAtUtc
                } : null
            };
        }
        catch (FileNotFoundException)
        {
            error = $"File not found: {bundlePath}";
            return null;
        }
        catch (JsonException ex)
        {
            error = $"Invalid JSON: {ex.Message}";
            return null;
        }
        catch (Exception ex)
        {
            error = $"Error reading bundle: {ex.Message}";
            return null;
        }
    }
}
