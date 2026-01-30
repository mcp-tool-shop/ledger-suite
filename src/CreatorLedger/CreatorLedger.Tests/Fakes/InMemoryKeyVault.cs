using CreatorLedger.Domain.Identity;
using CreatorLedger.Domain.Primitives;
using Shared.Crypto;

namespace CreatorLedger.Tests.Fakes;

/// <summary>
/// In-memory key vault for testing.
/// </summary>
public sealed class InMemoryKeyVault : IKeyVault
{
    private readonly Dictionary<CreatorId, byte[]> _keys = new();

    public Task StoreAsync(CreatorId creatorId, Ed25519PrivateKey privateKey, CancellationToken cancellationToken = default)
    {
        // Store a copy of the bytes
        _keys[creatorId] = privateKey.AsBytes().ToArray();
        return Task.CompletedTask;
    }

    public Task<Ed25519PrivateKey?> RetrieveAsync(CreatorId creatorId, CancellationToken cancellationToken = default)
    {
        if (_keys.TryGetValue(creatorId, out var bytes))
        {
            return Task.FromResult<Ed25519PrivateKey?>(Ed25519PrivateKey.FromBytes(bytes));
        }
        return Task.FromResult<Ed25519PrivateKey?>(null);
    }

    public Task<bool> DeleteAsync(CreatorId creatorId, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(_keys.Remove(creatorId));
    }

    public Task<bool> ExistsAsync(CreatorId creatorId, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(_keys.ContainsKey(creatorId));
    }
}
