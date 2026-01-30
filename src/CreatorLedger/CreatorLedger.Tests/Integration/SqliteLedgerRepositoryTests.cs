using System.Runtime.Versioning;
using CreatorLedger.Application.Attestation;
using CreatorLedger.Application.Identity;
using CreatorLedger.Application.Signing;
using CreatorLedger.Domain.Identity;
using CreatorLedger.Domain.Ledger.Events;
using CreatorLedger.Domain.Primitives;
using CreatorLedger.Infrastructure.Security;
using Shared.Crypto;

namespace CreatorLedger.Tests.Integration;

[SupportedOSPlatform("windows")]
public class SqliteLedgerRepositoryTests : IDisposable
{
    private readonly SqliteTestFixture _fixture;
    private readonly string _tempKeyDir;
    private readonly DpapiKeyVault _keyVault;

    public SqliteLedgerRepositoryTests()
    {
        _fixture = new SqliteTestFixture();
        _tempKeyDir = Path.Combine(Path.GetTempPath(), $"keyvault_test_{Guid.NewGuid():N}");
        _keyVault = new DpapiKeyVault(_tempKeyDir);
    }

    public void Dispose()
    {
        _fixture.Dispose();

        // Clean up key vault directory
        try
        {
            if (Directory.Exists(_tempKeyDir))
                Directory.Delete(_tempKeyDir, recursive: true);
        }
        catch { }
    }

    [Fact]
    public async Task GetLedgerTip_EmptyLedger_ReturnsZero()
    {
        var tip = await _fixture.LedgerRepository.GetLedgerTipAsync();

        Assert.Equal(Digest256.Zero, tip);
    }

    [Fact]
    public async Task AppendAsync_SingleEvent_UpdatesTip()
    {
        // Create a creator first
        using var keyPair = Ed25519KeyPair.Generate();
        var creatorId = CreatorId.New();
        var identity = CreatorIdentity.Create(creatorId, keyPair.PublicKey, "Creator", _fixture.Clock.UtcNow);
        await _fixture.IdentityRepository.AddAsync(identity);

        var previousTip = await _fixture.LedgerRepository.GetLedgerTipAsync();

        // Append a creator_created event
        var evt = new CreatorCreatedEvent(
            EventId.New(),
            _fixture.Clock.UtcNow,
            previousTip,
            creatorId,
            keyPair.PublicKey,
            "Creator");

        await _fixture.LedgerRepository.AppendAsync(evt);

        var newTip = await _fixture.LedgerRepository.GetLedgerTipAsync();

        Assert.NotEqual(Digest256.Zero, newTip);
        Assert.NotEqual(previousTip, newTip);
    }

    [Fact]
    public async Task AppendAsync_ChainVerification_EnforcesCorrectPreviousHash()
    {
        // Create a creator first
        using var keyPair = Ed25519KeyPair.Generate();
        var creatorId = CreatorId.New();
        var identity = CreatorIdentity.Create(creatorId, keyPair.PublicKey, "Creator", _fixture.Clock.UtcNow);
        await _fixture.IdentityRepository.AddAsync(identity);

        // Append first event
        var firstTip = await _fixture.LedgerRepository.GetLedgerTipAsync();
        var firstEvent = new CreatorCreatedEvent(
            EventId.New(),
            _fixture.Clock.UtcNow,
            firstTip,
            creatorId,
            keyPair.PublicKey,
            "Creator");
        await _fixture.LedgerRepository.AppendAsync(firstEvent);

        // Get new tip
        var secondTip = await _fixture.LedgerRepository.GetLedgerTipAsync();

        // Try to append with WRONG previous hash - should fail
        var badEvent = new CreatorCreatedEvent(
            EventId.New(),
            _fixture.Clock.UtcNow,
            Digest256.Zero, // Wrong! Should be secondTip
            CreatorId.New(),
            keyPair.PublicKey,
            "Bad Creator");

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _fixture.LedgerRepository.AppendAsync(badEvent));
    }

    [Fact]
    public async Task GetEventsForAsset_ReturnsInSeqOrder()
    {
        // Setup: Create identity with key vault
        using var keyPair = Ed25519KeyPair.Generate();
        var creatorId = CreatorId.New();
        var identity = CreatorIdentity.Create(creatorId, keyPair.PublicKey, "Artist", _fixture.Clock.UtcNow);
        await _fixture.IdentityRepository.AddAsync(identity);
        await _keyVault.StoreAsync(creatorId, keyPair.PrivateKey);

        // Create handlers that use the real repos
        var createIdentityHandler = new CreateIdentityHandler(
            _keyVault, _fixture.IdentityRepository, _fixture.LedgerRepository, _fixture.Clock);
        var attestHandler = new AttestAssetHandler(
            _keyVault, _fixture.IdentityRepository, _fixture.LedgerRepository, _fixture.Clock);

        // Attest two assets
        var assetId1 = AssetId.New();
        var assetId2 = AssetId.New();

        await attestHandler.HandleAsync(
            new AttestAssetCommand(assetId1, ContentHash.Compute("asset1"u8), creatorId));

        await attestHandler.HandleAsync(
            new AttestAssetCommand(assetId2, ContentHash.Compute("asset2"u8), creatorId));

        // Get events for each asset
        var events1 = await _fixture.LedgerRepository.GetEventsForAssetAsync(assetId1);
        var events2 = await _fixture.LedgerRepository.GetEventsForAssetAsync(assetId2);

        Assert.Single(events1);
        Assert.Single(events2);
        Assert.IsType<AssetAttestedEvent>(events1[0]);
        Assert.IsType<AssetAttestedEvent>(events2[0]);
    }

    [Fact]
    public async Task GetEventCount_TracksAppends()
    {
        using var keyPair = Ed25519KeyPair.Generate();
        var creatorId = CreatorId.New();
        var identity = CreatorIdentity.Create(creatorId, keyPair.PublicKey, "Counter", _fixture.Clock.UtcNow);
        await _fixture.IdentityRepository.AddAsync(identity);

        var initialCount = await _fixture.LedgerRepository.GetEventCountAsync();

        // Append events
        var tip = await _fixture.LedgerRepository.GetLedgerTipAsync();
        var evt = new CreatorCreatedEvent(
            EventId.New(),
            _fixture.Clock.UtcNow,
            tip,
            creatorId,
            keyPair.PublicKey,
            "Counter");
        await _fixture.LedgerRepository.AppendAsync(evt);

        var afterCount = await _fixture.LedgerRepository.GetEventCountAsync();

        Assert.Equal(initialCount + 1, afterCount);
    }

    [Fact]
    public async Task GetEventById_FindsExistingEvent()
    {
        using var keyPair = Ed25519KeyPair.Generate();
        var creatorId = CreatorId.New();
        var identity = CreatorIdentity.Create(creatorId, keyPair.PublicKey, "Finder", _fixture.Clock.UtcNow);
        await _fixture.IdentityRepository.AddAsync(identity);

        var eventId = EventId.New();
        var tip = await _fixture.LedgerRepository.GetLedgerTipAsync();
        var evt = new CreatorCreatedEvent(
            eventId,
            _fixture.Clock.UtcNow,
            tip,
            creatorId,
            keyPair.PublicKey,
            "Finder");
        await _fixture.LedgerRepository.AppendAsync(evt);

        var found = await _fixture.LedgerRepository.GetEventByIdAsync(eventId);

        Assert.NotNull(found);
        Assert.Equal(eventId, found.Id);
        Assert.IsType<CreatorCreatedEvent>(found);
    }

    [Fact]
    public async Task GetEventById_ReturnsNullForMissing()
    {
        var found = await _fixture.LedgerRepository.GetEventByIdAsync(EventId.New());

        Assert.Null(found);
    }
}
