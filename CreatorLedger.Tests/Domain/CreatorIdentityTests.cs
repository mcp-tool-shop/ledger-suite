using CreatorLedger.Domain.Identity;
using CreatorLedger.Domain.Primitives;
using Shared.Crypto;

namespace CreatorLedger.Tests.Domain;

public class CreatorIdentityTests
{
    private static Ed25519PublicKey CreateTestPublicKey()
    {
        using var keyPair = Ed25519KeyPair.Generate();
        return keyPair.PublicKey;
    }

    [Fact]
    public void Create_ValidInputs_Succeeds()
    {
        var id = CreatorId.New();
        var publicKey = CreateTestPublicKey();
        var displayName = "Test Creator";
        var createdAt = DateTimeOffset.UtcNow;

        var identity = CreatorIdentity.Create(id, publicKey, displayName, createdAt);

        Assert.Equal(id, identity.Id);
        Assert.Equal(publicKey, identity.PublicKey);
        Assert.Equal(displayName, identity.DisplayName);
        Assert.Equal(createdAt, identity.CreatedAtUtc);
    }

    [Fact]
    public void Create_NullDisplayName_IsAllowed()
    {
        var id = CreatorId.New();
        var publicKey = CreateTestPublicKey();
        var createdAt = DateTimeOffset.UtcNow;

        var identity = CreatorIdentity.Create(id, publicKey, null, createdAt);

        Assert.Null(identity.DisplayName);
    }

    [Fact]
    public void Create_WhitespaceDisplayName_BecomesNull()
    {
        var id = CreatorId.New();
        var publicKey = CreateTestPublicKey();
        var createdAt = DateTimeOffset.UtcNow;

        var identity = CreatorIdentity.Create(id, publicKey, "   ", createdAt);

        Assert.Null(identity.DisplayName);
    }

    [Fact]
    public void Create_DisplayNameWithWhitespace_IsTrimmed()
    {
        var id = CreatorId.New();
        var publicKey = CreateTestPublicKey();
        var createdAt = DateTimeOffset.UtcNow;

        var identity = CreatorIdentity.Create(id, publicKey, "  Alice  ", createdAt);

        Assert.Equal("Alice", identity.DisplayName);
    }

    [Fact]
    public void Create_DisplayNameTooLong_Throws()
    {
        var id = CreatorId.New();
        var publicKey = CreateTestPublicKey();
        var createdAt = DateTimeOffset.UtcNow;
        var longName = new string('x', CreatorIdentity.MaxDisplayNameLength + 1);

        Assert.Throws<DomainException>(() =>
            CreatorIdentity.Create(id, publicKey, longName, createdAt));
    }

    [Fact]
    public void Create_DisplayNameAtMaxLength_Succeeds()
    {
        var id = CreatorId.New();
        var publicKey = CreateTestPublicKey();
        var createdAt = DateTimeOffset.UtcNow;
        var maxName = new string('x', CreatorIdentity.MaxDisplayNameLength);

        var identity = CreatorIdentity.Create(id, publicKey, maxName, createdAt);

        Assert.Equal(maxName, identity.DisplayName);
    }

    [Fact]
    public void Create_NonUtcTimestamp_Throws()
    {
        var id = CreatorId.New();
        var publicKey = CreateTestPublicKey();
        var nonUtc = new DateTimeOffset(2024, 1, 1, 12, 0, 0, TimeSpan.FromHours(-5));

        Assert.Throws<DomainException>(() =>
            CreatorIdentity.Create(id, publicKey, "Test", nonUtc));
    }

    [Fact]
    public void Create_UtcTimestamp_Succeeds()
    {
        var id = CreatorId.New();
        var publicKey = CreateTestPublicKey();
        var utc = new DateTimeOffset(2024, 1, 1, 12, 0, 0, TimeSpan.Zero);

        var identity = CreatorIdentity.Create(id, publicKey, "Test", utc);

        Assert.Equal(utc, identity.CreatedAtUtc);
        Assert.Equal(TimeSpan.Zero, identity.CreatedAtUtc.Offset);
    }

    [Fact]
    public void Create_NullPublicKey_Throws()
    {
        var id = CreatorId.New();
        var createdAt = DateTimeOffset.UtcNow;

        Assert.Throws<DomainException>(() =>
            CreatorIdentity.Create(id, null!, "Test", createdAt));
    }

    [Fact]
    public void Reconstitute_DoesNotValidate()
    {
        // Reconstitute should allow loading persisted data without re-validation
        var id = CreatorId.New();
        var publicKey = CreateTestPublicKey();
        var displayName = "Already Persisted";
        var createdAt = DateTimeOffset.UtcNow;

        var identity = CreatorIdentity.Reconstitute(id, publicKey, displayName, createdAt);

        Assert.Equal(displayName, identity.DisplayName);
    }
}
