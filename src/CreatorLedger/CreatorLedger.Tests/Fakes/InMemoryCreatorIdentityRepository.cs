using CreatorLedger.Domain.Identity;
using CreatorLedger.Domain.Primitives;

namespace CreatorLedger.Tests.Fakes;

/// <summary>
/// In-memory creator identity repository for testing.
/// </summary>
public sealed class InMemoryCreatorIdentityRepository : ICreatorIdentityRepository
{
    private readonly Dictionary<CreatorId, CreatorIdentity> _identities = new();

    public Task<CreatorIdentity?> GetAsync(CreatorId creatorId, CancellationToken cancellationToken = default)
    {
        _identities.TryGetValue(creatorId, out var identity);
        return Task.FromResult(identity);
    }

    public Task AddAsync(CreatorIdentity identity, CancellationToken cancellationToken = default)
    {
        _identities[identity.Id] = identity;
        return Task.CompletedTask;
    }

    public Task<bool> ExistsAsync(CreatorId creatorId, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(_identities.ContainsKey(creatorId));
    }

    /// <summary>
    /// Gets all identities (for testing inspection).
    /// </summary>
    public IReadOnlyCollection<CreatorIdentity> GetAll() => _identities.Values.ToList();
}
