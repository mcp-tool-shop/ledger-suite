using CreatorLedger.Application.Primitives;
using CreatorLedger.Domain.Anchoring;
using CreatorLedger.Domain.Ledger;
using CreatorLedger.Domain.Ledger.Events;
using CreatorLedger.Domain.Primitives;
using Shared.Crypto;

namespace CreatorLedger.Application.Anchoring;

/// <summary>
/// Command to anchor the current ledger state to an external blockchain.
///
/// This operation:
/// 1. Reads the current ledger tip hash
/// 2. Calls the chain anchor adapter to submit the hash
/// 3. Appends a LedgerAnchoredEvent to record the anchor
///
/// The anchored hash is the ledger tip at the time of anchoring,
/// which includes all events up to that point.
/// </summary>
public sealed record AnchorProofCommand;

/// <summary>
/// Result of the anchor operation.
/// </summary>
public sealed record AnchorProofResult
{
    /// <summary>
    /// The hash that was anchored (ledger tip at time of anchor).
    /// </summary>
    public required Digest256 AnchoredHash { get; init; }

    /// <summary>
    /// The chain where the anchor was published.
    /// </summary>
    public required string ChainName { get; init; }

    /// <summary>
    /// The transaction ID on the blockchain.
    /// </summary>
    public required string TransactionId { get; init; }

    /// <summary>
    /// Block number if known.
    /// </summary>
    public long? BlockNumber { get; init; }

    /// <summary>
    /// URL to view the transaction in a block explorer.
    /// </summary>
    public string? ExplorerUrl { get; init; }

    /// <summary>
    /// The event ID of the LedgerAnchoredEvent that was appended.
    /// </summary>
    public required EventId EventId { get; init; }
}

/// <summary>
/// Handler for anchoring the ledger to a blockchain.
/// </summary>
public sealed class AnchorProofHandler
{
    private readonly IChainAnchor _chainAnchor;
    private readonly ILedgerRepository _ledgerRepository;
    private readonly IClock _clock;

    public AnchorProofHandler(
        IChainAnchor chainAnchor,
        ILedgerRepository ledgerRepository,
        IClock clock)
    {
        _chainAnchor = chainAnchor;
        _ledgerRepository = ledgerRepository;
        _clock = clock;
    }

    public async Task<AnchorProofResult> HandleAsync(
        AnchorProofCommand command,
        CancellationToken cancellationToken = default)
    {
        // 1. Get current ledger tip hash
        var tipHash = await _ledgerRepository.GetLedgerTipAsync(cancellationToken);

        if (tipHash == Digest256.Zero)
        {
            throw new InvalidOperationException(
                "Cannot anchor an empty ledger. Create at least one event first.");
        }

        // 2. Submit to chain anchor
        var anchorResult = await _chainAnchor.AnchorAsync(tipHash, cancellationToken);

        // 3. Create and append LedgerAnchoredEvent
        // Note: After anchoring, the tip has NOT changed yet - we need to get it again
        // to use as the previous hash for the anchor event itself.
        var previousHash = await _ledgerRepository.GetLedgerTipAsync(cancellationToken);

        var anchorEvent = new LedgerAnchoredEvent(
            EventId.New(),
            _clock.UtcNow,
            previousHash,
            tipHash,  // The hash we anchored (which was the tip before this event)
            anchorResult.ChainName,
            anchorResult.TransactionId,
            anchorResult.BlockNumber);

        await _ledgerRepository.AppendAsync(anchorEvent, cancellationToken);

        return new AnchorProofResult
        {
            AnchoredHash = tipHash,
            ChainName = anchorResult.ChainName,
            TransactionId = anchorResult.TransactionId,
            BlockNumber = anchorResult.BlockNumber,
            ExplorerUrl = anchorResult.ExplorerUrl,
            EventId = anchorEvent.Id
        };
    }
}
