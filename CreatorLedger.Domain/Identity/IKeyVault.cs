using CreatorLedger.Domain.Primitives;
using Shared.Crypto;

namespace CreatorLedger.Domain.Identity;

/// <summary>
/// Secure storage for creator private keys.
/// </summary>
public interface IKeyVault
{
    /// <summary>
    /// Stores a private key for a creator.
    /// </summary>
    /// <param name="creatorId">The creator ID.</param>
    /// <param name="privateKey">The private key to store.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task StoreAsync(CreatorId creatorId, Ed25519PrivateKey privateKey, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a private key for a creator.
    /// Caller is responsible for disposing the returned key.
    /// </summary>
    /// <param name="creatorId">The creator ID.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The private key, or null if not found.</returns>
    Task<Ed25519PrivateKey?> RetrieveAsync(CreatorId creatorId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a private key for a creator.
    /// </summary>
    /// <param name="creatorId">The creator ID.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if the key was deleted, false if it didn't exist.</returns>
    Task<bool> DeleteAsync(CreatorId creatorId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if a private key exists for a creator.
    /// </summary>
    /// <param name="creatorId">The creator ID.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if a key exists.</returns>
    Task<bool> ExistsAsync(CreatorId creatorId, CancellationToken cancellationToken = default);
}
