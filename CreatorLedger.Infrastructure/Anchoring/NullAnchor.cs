using System.Collections.Concurrent;
using CreatorLedger.Domain.Anchoring;
using Shared.Crypto;

namespace CreatorLedger.Infrastructure.Anchoring;

/// <summary>
/// A null/mock anchor for testing and development.
///
/// This adapter does NOT submit to any real blockchain.
/// It simply records the hash locally and returns a pseudo-transaction ID.
///
/// Use cases:
/// - Unit/integration testing without blockchain dependencies
/// - Local development without network access
/// - Proving the anchor flow works end-to-end before deploying real adapters
///
/// The chain name is "null" to make it clear this isn't a real anchor.
/// </summary>
public sealed class NullAnchor : IChainAnchor
{
    private readonly ConcurrentDictionary<Digest256, AnchorRecord> _anchors = new();
    private long _txCounter;

    public string ChainName => "null";

    public Task<AnchorResult> AnchorAsync(Digest256 hash, CancellationToken cancellationToken = default)
    {
        // Generate a pseudo-transaction ID
        var txId = $"null-tx-{Interlocked.Increment(ref _txCounter):D8}";
        var now = DateTimeOffset.UtcNow;

        var record = new AnchorRecord
        {
            Hash = hash,
            TransactionId = txId,
            AnchoredAtUtc = now
        };

        _anchors[hash] = record;

        var result = new AnchorResult
        {
            ChainName = ChainName,
            TransactionId = txId,
            BlockNumber = null, // NullAnchor doesn't have blocks
            ExplorerUrl = null, // No explorer for null chain
            ConfirmedAtUtc = now // Instantly "confirmed"
        };

        return Task.FromResult(result);
    }

    public Task<AnchorResult?> LookupAsync(Digest256 hash, CancellationToken cancellationToken = default)
    {
        if (!_anchors.TryGetValue(hash, out var record))
        {
            return Task.FromResult<AnchorResult?>(null);
        }

        var result = new AnchorResult
        {
            ChainName = ChainName,
            TransactionId = record.TransactionId,
            BlockNumber = null,
            ExplorerUrl = null,
            ConfirmedAtUtc = record.AnchoredAtUtc
        };

        return Task.FromResult<AnchorResult?>(result);
    }

    /// <summary>
    /// Gets the number of anchors recorded.
    /// Useful for testing.
    /// </summary>
    public int AnchorCount => _anchors.Count;

    /// <summary>
    /// Clears all recorded anchors.
    /// Useful for testing.
    /// </summary>
    public void Clear() => _anchors.Clear();

    private sealed class AnchorRecord
    {
        public required Digest256 Hash { get; init; }
        public required string TransactionId { get; init; }
        public required DateTimeOffset AnchoredAtUtc { get; init; }
    }
}
