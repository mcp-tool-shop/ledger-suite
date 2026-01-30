using CreatorLedger.Domain.Ledger;
using CreatorLedger.Domain.Ledger.Events;
using CreatorLedger.Domain.Primitives;
using Shared.Crypto;

namespace CreatorLedger.Tests.Fakes;

/// <summary>
/// In-memory ledger repository for testing.
/// </summary>
public sealed class InMemoryLedgerRepository : ILedgerRepository
{
    private readonly List<LedgerEvent> _events = new();
    private Digest256 _currentTip = Digest256.Zero;

    public Task AppendAsync(LedgerEvent ledgerEvent, CancellationToken cancellationToken = default)
    {
        _events.Add(ledgerEvent);

        // Update the tip hash (simplified: hash of event ID)
        _currentTip = Digest256.ComputeUtf8(ledgerEvent.Id.ToString());

        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<LedgerEvent>> GetEventsForAssetAsync(
        AssetId assetId,
        CancellationToken cancellationToken = default)
    {
        var events = _events
            .Where(e => IsEventForAsset(e, assetId))
            .OrderBy(e => e.OccurredAtUtc)
            .ToList();

        return Task.FromResult<IReadOnlyList<LedgerEvent>>(events);
    }

    public Task<Digest256> GetLedgerTipAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult(_currentTip);
    }

    public Task<LedgerEvent?> GetEventByIdAsync(EventId eventId, CancellationToken cancellationToken = default)
    {
        var evt = _events.FirstOrDefault(e => e.Id == eventId);
        return Task.FromResult(evt);
    }

    public Task<long> GetEventCountAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult((long)_events.Count);
    }

    /// <summary>
    /// Gets all events (for testing inspection).
    /// </summary>
    public IReadOnlyList<LedgerEvent> GetAllEvents() => _events.ToList();

    /// <summary>
    /// Gets all events as a list (for testing inspection).
    /// </summary>
    public List<LedgerEvent> Events => _events;

    private static bool IsEventForAsset(LedgerEvent evt, AssetId assetId)
    {
        return evt switch
        {
            AssetAttestedEvent e => e.AssetId == assetId,
            AssetDerivedEvent e => e.AssetId == assetId,
            AssetExportedEvent e => e.AssetId == assetId,
            _ => false
        };
    }
}
