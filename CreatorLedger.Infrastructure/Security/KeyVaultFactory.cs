using System.Runtime.InteropServices;
using CreatorLedger.Domain.Identity;

namespace CreatorLedger.Infrastructure.Security;

/// <summary>
/// Factory for creating platform-appropriate key vaults.
/// </summary>
public static class KeyVaultFactory
{
    /// <summary>
    /// Key vault type to use.
    /// </summary>
    public enum VaultType
    {
        /// <summary>
        /// Automatically select based on platform.
        /// Windows: DPAPI, Other: In-memory with warning.
        /// </summary>
        Auto,

        /// <summary>
        /// Windows DPAPI-based vault. Only works on Windows.
        /// </summary>
        Dpapi,

        /// <summary>
        /// In-memory vault for development/testing.
        /// Keys are NOT persisted and NOT secure.
        /// </summary>
        InMemory
    }

    /// <summary>
    /// Creates a key vault based on the specified type.
    /// </summary>
    /// <param name="vaultType">The type of vault to create.</param>
    /// <param name="baseDirectory">
    /// Base directory for file-based vaults (DPAPI).
    /// If null, uses the default location (%LOCALAPPDATA%\CreatorLedger).
    /// </param>
    /// <returns>An IKeyVault implementation.</returns>
    /// <exception cref="PlatformNotSupportedException">
    /// Thrown when DPAPI is requested on a non-Windows platform.
    /// </exception>
    public static IKeyVault Create(VaultType vaultType, string? baseDirectory = null)
    {
        return vaultType switch
        {
            VaultType.Auto => CreateAuto(baseDirectory),
            VaultType.Dpapi => CreateDpapi(baseDirectory),
            VaultType.InMemory => new InMemoryKeyVault(),
            _ => throw new ArgumentOutOfRangeException(nameof(vaultType))
        };
    }

    /// <summary>
    /// Creates a vault using automatic platform detection.
    /// </summary>
    private static IKeyVault CreateAuto(string? baseDirectory)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return CreateDpapi(baseDirectory);
        }

        // Non-Windows: use in-memory vault with a warning
        Console.Error.WriteLine(
            "WARNING: Running on non-Windows platform. " +
            "Using in-memory key vault - keys will NOT be persisted. " +
            "For production on Windows, DPAPI will be used automatically.");

        return new InMemoryKeyVault();
    }

    /// <summary>
    /// Creates a DPAPI vault. Throws on non-Windows.
    /// </summary>
    private static IKeyVault CreateDpapi(string? baseDirectory)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            throw new PlatformNotSupportedException(
                "DPAPI key vault is only supported on Windows. " +
                "On non-Windows platforms, use VaultType.InMemory for development/testing, " +
                "or implement a platform-specific secure storage solution.");
        }

        if (baseDirectory is not null)
        {
            return new DpapiKeyVault(baseDirectory);
        }

        return DpapiKeyVault.CreateDefault();
    }

    /// <summary>
    /// Creates a vault for development/testing (always in-memory).
    /// This method is explicit about not providing secure storage.
    /// </summary>
    public static IKeyVault CreateForDevelopment()
    {
        return new InMemoryKeyVault();
    }
}
