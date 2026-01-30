using CreatorLedger.Domain.Identity;
using CreatorLedger.Domain.Primitives;
using Shared.Crypto;

namespace CreatorLedger.Tests.Integration;

public class SqliteCreatorIdentityRepositoryTests : IDisposable
{
    private readonly SqliteTestFixture _fixture;

    public SqliteCreatorIdentityRepositoryTests()
    {
        _fixture = new SqliteTestFixture();
    }

    public void Dispose() => _fixture.Dispose();

    [Fact]
    public async Task AddAndGet_RoundTrip()
    {
        using var keyPair = Ed25519KeyPair.Generate();
        var creatorId = CreatorId.New();
        var identity = CreatorIdentity.Create(
            creatorId,
            keyPair.PublicKey,
            "Test Creator",
            _fixture.Clock.UtcNow);

        await _fixture.IdentityRepository.AddAsync(identity);

        var retrieved = await _fixture.IdentityRepository.GetAsync(creatorId);

        Assert.NotNull(retrieved);
        Assert.Equal(identity.Id, retrieved.Id);
        Assert.Equal(identity.PublicKey.ToString(), retrieved.PublicKey.ToString());
        Assert.Equal(identity.DisplayName, retrieved.DisplayName);
    }

    [Fact]
    public async Task Get_UnknownId_ReturnsNull()
    {
        var unknownId = CreatorId.New();

        var result = await _fixture.IdentityRepository.GetAsync(unknownId);

        Assert.Null(result);
    }

    [Fact]
    public async Task GetByPublicKey_FindsCreator()
    {
        using var keyPair = Ed25519KeyPair.Generate();
        var identity = CreatorIdentity.Create(
            CreatorId.New(),
            keyPair.PublicKey,
            null,
            _fixture.Clock.UtcNow);

        await _fixture.IdentityRepository.AddAsync(identity);

        var retrieved = await _fixture.IdentityRepository.GetByPublicKeyAsync(keyPair.PublicKey);

        Assert.NotNull(retrieved);
        Assert.Equal(identity.Id, retrieved.Id);
    }

    [Fact]
    public async Task Exists_ReturnsTrueForExisting()
    {
        using var keyPair = Ed25519KeyPair.Generate();
        var creatorId = CreatorId.New();
        var identity = CreatorIdentity.Create(
            creatorId,
            keyPair.PublicKey,
            "Exists Test",
            _fixture.Clock.UtcNow);

        await _fixture.IdentityRepository.AddAsync(identity);

        var exists = await _fixture.IdentityRepository.ExistsAsync(creatorId);

        Assert.True(exists);
    }

    [Fact]
    public async Task Exists_ReturnsFalseForMissing()
    {
        var unknownId = CreatorId.New();

        var exists = await _fixture.IdentityRepository.ExistsAsync(unknownId);

        Assert.False(exists);
    }

    [Fact]
    public async Task Add_DuplicatePublicKey_Throws()
    {
        using var keyPair = Ed25519KeyPair.Generate();

        var identity1 = CreatorIdentity.Create(
            CreatorId.New(),
            keyPair.PublicKey,
            "Creator 1",
            _fixture.Clock.UtcNow);

        var identity2 = CreatorIdentity.Create(
            CreatorId.New(),
            keyPair.PublicKey, // Same public key!
            "Creator 2",
            _fixture.Clock.UtcNow);

        await _fixture.IdentityRepository.AddAsync(identity1);

        // Should throw due to unique index on public_key
        await Assert.ThrowsAnyAsync<Exception>(() =>
            _fixture.IdentityRepository.AddAsync(identity2));
    }
}
