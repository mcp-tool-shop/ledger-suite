using CreatorLedger.Domain.Primitives;
using Shared.Crypto;

namespace CreatorLedger.Domain.Identity;

/// <summary>
/// Aggregate root representing a creator's cryptographic identity.
/// Immutable after creation.
/// </summary>
public sealed class CreatorIdentity
{
    public const int MaxDisplayNameLength = 80;

    public CreatorId Id { get; }
    public Ed25519PublicKey PublicKey { get; }
    public string? DisplayName { get; }
    public DateTimeOffset CreatedAtUtc { get; }

    private CreatorIdentity(
        CreatorId id,
        Ed25519PublicKey publicKey,
        string? displayName,
        DateTimeOffset createdAtUtc)
    {
        Id = id;
        PublicKey = publicKey;
        DisplayName = displayName;
        CreatedAtUtc = createdAtUtc;
    }

    /// <summary>
    /// Creates a new creator identity.
    /// </summary>
    /// <param name="id">Unique identifier for this identity.</param>
    /// <param name="publicKey">The Ed25519 public key for this creator.</param>
    /// <param name="displayName">Optional display name (trimmed, max 80 chars).</param>
    /// <param name="createdAtUtc">Creation timestamp (must be UTC).</param>
    public static CreatorIdentity Create(
        CreatorId id,
        Ed25519PublicKey publicKey,
        string? displayName,
        DateTimeOffset createdAtUtc)
    {
        if (publicKey is null)
            throw new DomainException("PublicKey is required for CreatorIdentity");

        if (createdAtUtc.Offset != TimeSpan.Zero)
            throw new DomainException("CreatedAtUtc must be UTC (offset must be zero)");

        var normalizedDisplayName = NormalizeDisplayName(displayName);

        return new CreatorIdentity(id, publicKey, normalizedDisplayName, createdAtUtc);
    }

    /// <summary>
    /// Reconstitutes a CreatorIdentity from persisted data.
    /// Use for loading from storage only.
    /// </summary>
    public static CreatorIdentity Reconstitute(
        CreatorId id,
        Ed25519PublicKey publicKey,
        string? displayName,
        DateTimeOffset createdAtUtc)
    {
        return new CreatorIdentity(id, publicKey, displayName, createdAtUtc);
    }

    private static string? NormalizeDisplayName(string? displayName)
    {
        if (string.IsNullOrWhiteSpace(displayName))
            return null;

        var trimmed = displayName.Trim();

        if (trimmed.Length > MaxDisplayNameLength)
            throw new DomainException($"DisplayName cannot exceed {MaxDisplayNameLength} characters");

        return trimmed;
    }
}
