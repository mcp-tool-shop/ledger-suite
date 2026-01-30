using System.Runtime.Versioning;
using CreatorLedger.Domain.Primitives;
using CreatorLedger.Infrastructure.Security;
using Shared.Crypto;

namespace CreatorLedger.Tests.Infrastructure;

/// <summary>
/// Tests for key vault implementations.
/// </summary>
public class KeyVaultTests
{
    [Fact]
    public async Task InMemoryKeyVault_StoreAndRetrieve_RoundTrips()
    {
        using var vault = new InMemoryKeyVault();
        var creatorId = CreatorId.New();

        using var keyPair = Ed25519KeyPair.Generate();
        var privateKey = keyPair.PrivateKey;

        // Store
        await vault.StoreAsync(creatorId, privateKey);

        // Verify exists
        Assert.True(await vault.ExistsAsync(creatorId));

        // Retrieve
        using var retrieved = await vault.RetrieveAsync(creatorId);
        Assert.NotNull(retrieved);

        // Verify key bytes match
        Assert.True(privateKey.AsBytes().SequenceEqual(retrieved.AsBytes()));
    }

    [Fact]
    public async Task InMemoryKeyVault_Retrieve_NonExistent_ReturnsNull()
    {
        using var vault = new InMemoryKeyVault();
        var creatorId = CreatorId.New();

        var result = await vault.RetrieveAsync(creatorId);

        Assert.Null(result);
    }

    [Fact]
    public async Task InMemoryKeyVault_Delete_ExistingKey_ReturnsTrue()
    {
        using var vault = new InMemoryKeyVault();
        var creatorId = CreatorId.New();

        using var keyPair = Ed25519KeyPair.Generate();
        await vault.StoreAsync(creatorId, keyPair.PrivateKey);

        // Delete
        var deleted = await vault.DeleteAsync(creatorId);

        Assert.True(deleted);
        Assert.False(await vault.ExistsAsync(creatorId));
    }

    [Fact]
    public async Task InMemoryKeyVault_Delete_NonExistent_ReturnsFalse()
    {
        using var vault = new InMemoryKeyVault();
        var creatorId = CreatorId.New();

        var deleted = await vault.DeleteAsync(creatorId);

        Assert.False(deleted);
    }

    [Fact]
    public async Task InMemoryKeyVault_Dispose_ClearsKeys()
    {
        var vault = new InMemoryKeyVault();
        var creatorId = CreatorId.New();

        using var keyPair = Ed25519KeyPair.Generate();
        await vault.StoreAsync(creatorId, keyPair.PrivateKey);

        // Dispose
        vault.Dispose();

        // Should throw on subsequent operations
        await Assert.ThrowsAsync<ObjectDisposedException>(() => vault.ExistsAsync(creatorId));
    }

    [Fact]
    public void KeyVaultFactory_CreateForDevelopment_ReturnsInMemoryVault()
    {
        var vault = KeyVaultFactory.CreateForDevelopment();

        Assert.IsType<InMemoryKeyVault>(vault);
    }

    [Fact]
    public void KeyVaultFactory_InMemory_ReturnsInMemoryVault()
    {
        var vault = KeyVaultFactory.Create(KeyVaultFactory.VaultType.InMemory);

        Assert.IsType<InMemoryKeyVault>(vault);
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void KeyVaultFactory_Dpapi_OnWindows_ReturnsDpapiVault()
    {
        if (!OperatingSystem.IsWindows())
        {
            // Skip on non-Windows
            return;
        }

        var tempDir = Path.Combine(Path.GetTempPath(), $"keyvault_test_{Guid.NewGuid():N}");

        try
        {
            var vault = KeyVaultFactory.Create(KeyVaultFactory.VaultType.Dpapi, tempDir);

            Assert.IsType<DpapiKeyVault>(vault);
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void KeyVaultFactory_Auto_OnWindows_ReturnsDpapiVault()
    {
        if (!OperatingSystem.IsWindows())
        {
            // Skip on non-Windows
            return;
        }

        var tempDir = Path.Combine(Path.GetTempPath(), $"keyvault_auto_test_{Guid.NewGuid():N}");

        try
        {
            var vault = KeyVaultFactory.Create(KeyVaultFactory.VaultType.Auto, tempDir);

            Assert.IsType<DpapiKeyVault>(vault);
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }
}
