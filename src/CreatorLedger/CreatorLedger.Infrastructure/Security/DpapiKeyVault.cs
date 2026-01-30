using System.Runtime.Versioning;
using System.Security.Cryptography;
using CreatorLedger.Domain.Identity;
using CreatorLedger.Domain.Primitives;
using Shared.Crypto;

namespace CreatorLedger.Infrastructure.Security;

/// <summary>
/// Windows DPAPI-based secure key vault.
/// Encrypts private keys using the current user's credentials.
///
/// Keys are stored as files: {baseDir}/keys/{creatorId}.bin
/// File contents: DPAPI-encrypted 32-byte Ed25519 seed
///
/// SECURITY NOTES:
/// - Keys are protected with DataProtectionScope.CurrentUser
/// - Only the same Windows user account can decrypt
/// - Keys are zeroed after use
/// - File permissions should be restricted by the caller
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DpapiKeyVault : IKeyVault
{
    private readonly string _keysDirectory;

    public DpapiKeyVault(string baseDirectory)
    {
        _keysDirectory = Path.Combine(baseDirectory, "keys");
        Directory.CreateDirectory(_keysDirectory);
    }

    /// <summary>
    /// Creates a DPAPI key vault using the standard LocalAppData location.
    /// Path: %LOCALAPPDATA%\CreatorLedger\keys\
    /// </summary>
    public static DpapiKeyVault CreateDefault()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var baseDir = Path.Combine(localAppData, "CreatorLedger");
        return new DpapiKeyVault(baseDir);
    }

    public Task StoreAsync(CreatorId creatorId, Ed25519PrivateKey privateKey, CancellationToken cancellationToken = default)
    {
        var filePath = GetKeyFilePath(creatorId);

        // Get raw seed bytes
        var seedBytes = privateKey.AsBytes().ToArray();

        try
        {
            // Encrypt with DPAPI (CurrentUser scope)
            var encryptedBytes = ProtectedData.Protect(
                seedBytes,
                optionalEntropy: null,
                scope: DataProtectionScope.CurrentUser);

            // Write to file
            File.WriteAllBytes(filePath, encryptedBytes);

            return Task.CompletedTask;
        }
        finally
        {
            // Zero the unencrypted seed copy
            CryptographicOperations.ZeroMemory(seedBytes);
        }
    }

    public Task<Ed25519PrivateKey?> RetrieveAsync(CreatorId creatorId, CancellationToken cancellationToken = default)
    {
        var filePath = GetKeyFilePath(creatorId);

        if (!File.Exists(filePath))
            return Task.FromResult<Ed25519PrivateKey?>(null);

        byte[]? decryptedBytes = null;

        try
        {
            var encryptedBytes = File.ReadAllBytes(filePath);

            // Decrypt with DPAPI
            decryptedBytes = ProtectedData.Unprotect(
                encryptedBytes,
                optionalEntropy: null,
                scope: DataProtectionScope.CurrentUser);

            // Validate length
            if (decryptedBytes.Length != Ed25519PrivateKey.ByteLength)
            {
                throw new CryptographicException(
                    $"Decrypted key has invalid length: expected {Ed25519PrivateKey.ByteLength}, got {decryptedBytes.Length}");
            }

            // Create key from decrypted bytes
            var privateKey = Ed25519PrivateKey.FromBytes(decryptedBytes);

            return Task.FromResult<Ed25519PrivateKey?>(privateKey);
        }
        catch (CryptographicException ex)
        {
            // Distinguish "decrypt failed" from "not found"
            throw new InvalidOperationException(
                $"Failed to decrypt key for creator {creatorId}. " +
                "This may occur if the key was created by a different user account.",
                ex);
        }
        finally
        {
            // Always zero decrypted bytes
            if (decryptedBytes != null)
                CryptographicOperations.ZeroMemory(decryptedBytes);
        }
    }

    public Task<bool> DeleteAsync(CreatorId creatorId, CancellationToken cancellationToken = default)
    {
        var filePath = GetKeyFilePath(creatorId);

        if (!File.Exists(filePath))
            return Task.FromResult(false);

        // Overwrite with random data before deleting (defense in depth)
        try
        {
            var randomData = new byte[256];
            RandomNumberGenerator.Fill(randomData);
            File.WriteAllBytes(filePath, randomData);
        }
        catch
        {
            // Best effort - continue with delete
        }

        File.Delete(filePath);
        return Task.FromResult(true);
    }

    public Task<bool> ExistsAsync(CreatorId creatorId, CancellationToken cancellationToken = default)
    {
        var filePath = GetKeyFilePath(creatorId);
        return Task.FromResult(File.Exists(filePath));
    }

    private string GetKeyFilePath(CreatorId creatorId)
    {
        // Sanitize creator ID for filename (GUIDs are safe, but be defensive)
        var filename = $"{creatorId}.bin";
        return Path.Combine(_keysDirectory, filename);
    }
}
