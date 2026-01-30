using CreatorLedger.Domain.Primitives;
using Shared.Crypto;

namespace CreatorLedger.Domain.Trust;

/// <summary>
/// Calculates the trust level for an asset.
/// </summary>
public interface ITrustCalculator
{
    /// <summary>
    /// Calculates the trust level for an asset given its current content hash.
    /// </summary>
    /// <param name="assetId">The asset to evaluate.</param>
    /// <param name="currentContentHash">The current hash of the asset's content.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The calculated trust level.</returns>
    Task<TrustLevel> CalculateAsync(
        AssetId assetId,
        ContentHash currentContentHash,
        CancellationToken cancellationToken = default);
}
