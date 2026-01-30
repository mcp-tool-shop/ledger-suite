using CreatorLedger.Domain.Primitives;

namespace CreatorLedger.Domain.Identity;

/// <summary>
/// Repository for creator identities.
/// </summary>
public interface ICreatorIdentityRepository
{
    /// <summary>
    /// Gets a creator identity by ID.
    /// </summary>
    /// <param name="creatorId">The creator ID.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The identity, or null if not found.</returns>
    Task<CreatorIdentity?> GetAsync(CreatorId creatorId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Adds a new creator identity.
    /// </summary>
    /// <param name="identity">The identity to add.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task AddAsync(CreatorIdentity identity, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if a creator identity exists.
    /// </summary>
    /// <param name="creatorId">The creator ID.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if exists.</returns>
    Task<bool> ExistsAsync(CreatorId creatorId, CancellationToken cancellationToken = default);
}
