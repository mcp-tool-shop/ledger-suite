using System.Collections.Concurrent;
using System.Security.Cryptography;
using CreatorLedger.Domain.Identity;
using CreatorLedger.Domain.Primitives;
using Shared.Crypto;

namespace CreatorLedger.Infrastructure.Security;

/// <summary>
/// In-memory key vault for development and testing.
/// Keys are stored in memory and lost when the process exits.
///
/// WARNING: This vault does NOT provide secure storage.
/// - Keys are held in plain memory
/// - Keys are NOT persisted
/// - Use ONLY for development, testing, and demos
///
/// For production on Windows, use DpapiKeyVault.
/// </summary>
public sealed class InMemoryKeyVault : IKeyVault, IDisposable
{
    private readonly ConcurrentDictionary<CreatorId, byte[]> _keys = new();
    private bool _disposed;

    public Task StoreAsync(CreatorId creatorId, Ed25519PrivateKey privateKey, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        // Make a copy of the key bytes
        var keyBytes = privateKey.AsBytes().ToArray();

        // If replacing, zero old key
        if (_keys.TryRemove(creatorId, out var oldKey))
        {
            CryptographicOperations.ZeroMemory(oldKey);
        }

        _keys[creatorId] = keyBytes;
        return Task.CompletedTask;
    }

    public Task<Ed25519PrivateKey?> RetrieveAsync(CreatorId creatorId, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (!_keys.TryGetValue(creatorId, out var keyBytes))
        {
            return Task.FromResult<Ed25519PrivateKey?>(null);
        }

        // Create a new key from stored bytes
        // Caller is responsible for disposing
        var key = Ed25519PrivateKey.FromBytes(keyBytes);
        return Task.FromResult<Ed25519PrivateKey?>(key);
    }

    public Task<bool> DeleteAsync(CreatorId creatorId, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (_keys.TryRemove(creatorId, out var keyBytes))
        {
            CryptographicOperations.ZeroMemory(keyBytes);
            return Task.FromResult(true);
        }

        return Task.FromResult(false);
    }

    public Task<bool> ExistsAsync(CreatorId creatorId, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        return Task.FromResult(_keys.ContainsKey(creatorId));
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;

        // Zero all stored keys
        foreach (var kvp in _keys)
        {
            CryptographicOperations.ZeroMemory(kvp.Value);
        }

        _keys.Clear();
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(InMemoryKeyVault));
        }
    }
}
