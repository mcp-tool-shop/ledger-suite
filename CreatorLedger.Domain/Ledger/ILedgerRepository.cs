using CreatorLedger.Domain.Primitives;
using Shared.Crypto;

namespace CreatorLedger.Domain.Ledger;

/// <summary>
/// Repository for the append-only ledger event store.
/// </summary>
public interface ILedgerRepository
{
    /// <summary>
    /// Appends an event to the ledger.
    /// </summary>
    /// <param name="ledgerEvent">The event to append.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task AppendAsync(LedgerEvent ledgerEvent, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets all events related to a specific asset, in chronological order.
    /// </summary>
    /// <param name="assetId">The asset to get events for.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Events related to the asset.</returns>
    Task<IReadOnlyList<LedgerEvent>> GetEventsForAssetAsync(
        AssetId assetId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the current tip of the ledger (most recent event hash).
    /// Returns Digest256.Zero if the ledger is empty.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The hash of the most recent event, or Digest256.Zero for genesis.</returns>
    Task<Digest256> GetLedgerTipAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets an event by its ID.
    /// </summary>
    /// <param name="eventId">The event ID.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The event, or null if not found.</returns>
    Task<LedgerEvent?> GetEventByIdAsync(EventId eventId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the total count of events in the ledger.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The number of events.</returns>
    Task<long> GetEventCountAsync(CancellationToken cancellationToken = default);
}
