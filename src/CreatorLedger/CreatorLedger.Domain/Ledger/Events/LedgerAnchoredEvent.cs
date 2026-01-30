using CreatorLedger.Domain.Primitives;
using Shared.Crypto;

namespace CreatorLedger.Domain.Ledger.Events;

/// <summary>
/// Event recording that the ledger was anchored to a blockchain.
/// </summary>
public sealed class LedgerAnchoredEvent : LedgerEvent
{
    public const string TypeName = "ledger_anchored";

    public override string EventType => TypeName;

    /// <summary>
    /// The hash of the ledger state that was anchored.
    /// </summary>
    public Digest256 LedgerRootHash { get; }

    /// <summary>
    /// The blockchain where the anchor was published.
    /// Examples: "polygon", "bitcoin", "ethereum"
    /// </summary>
    public string ChainName { get; }

    /// <summary>
    /// The transaction ID on the blockchain.
    /// </summary>
    public string TransactionId { get; }

    /// <summary>
    /// The block number where the anchor was included (if known).
    /// </summary>
    public long? BlockNumber { get; }

    public LedgerAnchoredEvent(
        EventId id,
        DateTimeOffset occurredAtUtc,
        Digest256 previousEventHash,
        Digest256 ledgerRootHash,
        string chainName,
        string transactionId,
        long? blockNumber = null)
        : base(id, occurredAtUtc, previousEventHash)
    {
        if (ledgerRootHash == default)
            throw new DomainException("LedgerRootHash cannot be empty");
        if (string.IsNullOrWhiteSpace(chainName))
            throw new DomainException("ChainName is required");
        if (string.IsNullOrWhiteSpace(transactionId))
            throw new DomainException("TransactionId is required");

        LedgerRootHash = ledgerRootHash;
        ChainName = chainName;
        TransactionId = transactionId;
        BlockNumber = blockNumber;
    }
}
