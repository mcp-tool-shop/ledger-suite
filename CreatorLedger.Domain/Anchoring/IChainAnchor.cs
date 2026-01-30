using Shared.Crypto;

namespace CreatorLedger.Domain.Anchoring;

/// <summary>
/// Result of an anchor operation on a blockchain.
/// </summary>
public sealed record AnchorResult
{
    /// <summary>
    /// The blockchain where the anchor was published.
    /// Examples: "polygon", "bitcoin", "ethereum", "null" (for NullAnchor)
    /// </summary>
    public required string ChainName { get; init; }

    /// <summary>
    /// The transaction ID on the blockchain.
    /// For NullAnchor, this is a pseudo-ID.
    /// </summary>
    public required string TransactionId { get; init; }

    /// <summary>
    /// The block number where the anchor was included (if known).
    /// May be null if the transaction is pending or the chain doesn't have block numbers.
    /// </summary>
    public long? BlockNumber { get; init; }

    /// <summary>
    /// URL to view the transaction in a block explorer (optional).
    /// Example: "https://polygonscan.com/tx/{TransactionId}"
    /// </summary>
    public string? ExplorerUrl { get; init; }

    /// <summary>
    /// When the anchor was confirmed (if known).
    /// </summary>
    public DateTimeOffset? ConfirmedAtUtc { get; init; }
}

/// <summary>
/// Interface for anchoring ledger state to an external blockchain or timestamping service.
///
/// Implementations are responsible for:
/// - Submitting the hash to the external chain
/// - Waiting for confirmation (or returning pending state)
/// - Returning the transaction details
///
/// The ledger tip hash (not individual asset hashes) is what gets anchored.
/// This provides batch anchoring and preserves privacy.
/// </summary>
public interface IChainAnchor
{
    /// <summary>
    /// Gets the name of this anchor chain.
    /// </summary>
    string ChainName { get; }

    /// <summary>
    /// Anchors a hash to the external chain.
    /// </summary>
    /// <param name="hash">The hash to anchor (typically ledger tip hash).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The anchor result with transaction details.</returns>
    /// <exception cref="AnchorException">If the anchor operation fails.</exception>
    Task<AnchorResult> AnchorAsync(Digest256 hash, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if an anchor exists for a given hash.
    /// </summary>
    /// <param name="hash">The hash to look up.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The anchor result if found, null otherwise.</returns>
    Task<AnchorResult?> LookupAsync(Digest256 hash, CancellationToken cancellationToken = default);
}

/// <summary>
/// Exception thrown when an anchor operation fails.
/// </summary>
public class AnchorException : Exception
{
    public string ChainName { get; }

    public AnchorException(string chainName, string message)
        : base(message)
    {
        ChainName = chainName;
    }

    public AnchorException(string chainName, string message, Exception innerException)
        : base(message, innerException)
    {
        ChainName = chainName;
    }
}
