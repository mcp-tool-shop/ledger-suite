using CreatorLedger.Application.Identity;
using CreatorLedger.Domain.Ledger.Events;
using CreatorLedger.Tests.Fakes;

namespace CreatorLedger.Tests.Application;

public class CreateIdentityTests
{
    private readonly FakeClock _clock = new();
    private readonly InMemoryKeyVault _keyVault = new();
    private readonly InMemoryCreatorIdentityRepository _identityRepo = new();
    private readonly InMemoryLedgerRepository _ledgerRepo = new();

    private CreateIdentityHandler CreateHandler() =>
        new(_keyVault, _identityRepo, _ledgerRepo, _clock);

    [Fact]
    public async Task CreateIdentity_StoresPrivateKey()
    {
        var handler = CreateHandler();

        var result = await handler.HandleAsync(new CreateIdentityCommand("Alice"));

        var keyExists = await _keyVault.ExistsAsync(result.CreatorId);
        Assert.True(keyExists);
    }

    [Fact]
    public async Task CreateIdentity_PersistsPublicIdentity()
    {
        var handler = CreateHandler();

        var result = await handler.HandleAsync(new CreateIdentityCommand("Bob"));

        var identity = await _identityRepo.GetAsync(result.CreatorId);
        Assert.NotNull(identity);
        Assert.Equal(result.PublicKey, identity.PublicKey);
        Assert.Equal("Bob", identity.DisplayName);
    }

    [Fact]
    public async Task CreateIdentity_AppendsCreatorCreatedEvent()
    {
        var handler = CreateHandler();

        var result = await handler.HandleAsync(new CreateIdentityCommand("Carol"));

        var events = _ledgerRepo.GetAllEvents();
        Assert.Single(events);

        var evt = Assert.IsType<CreatorCreatedEvent>(events[0]);
        Assert.Equal(result.CreatorId, evt.CreatorId);
        Assert.Equal(result.PublicKey, evt.PublicKey);
        Assert.Equal("Carol", evt.DisplayName);
    }

    [Fact]
    public async Task CreateIdentity_UsesClockForTimestamp()
    {
        var expectedTime = new DateTimeOffset(2024, 1, 15, 10, 30, 0, TimeSpan.Zero);
        _clock.SetTime(expectedTime);
        var handler = CreateHandler();

        await handler.HandleAsync(new CreateIdentityCommand(null));

        var identity = _identityRepo.GetAll().First();
        Assert.Equal(expectedTime, identity.CreatedAtUtc);
    }

    [Fact]
    public async Task CreateIdentity_NullDisplayName_IsAllowed()
    {
        var handler = CreateHandler();

        var result = await handler.HandleAsync(new CreateIdentityCommand(null));

        var identity = await _identityRepo.GetAsync(result.CreatorId);
        Assert.Null(identity!.DisplayName);
    }

    [Fact]
    public async Task CreateIdentity_ReturnsUniqueIds()
    {
        var handler = CreateHandler();

        var result1 = await handler.HandleAsync(new CreateIdentityCommand("A"));
        var result2 = await handler.HandleAsync(new CreateIdentityCommand("B"));

        Assert.NotEqual(result1.CreatorId, result2.CreatorId);
        Assert.NotEqual(result1.PublicKey, result2.PublicKey);
    }
}
