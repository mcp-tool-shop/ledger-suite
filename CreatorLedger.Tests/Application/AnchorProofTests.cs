using CreatorLedger.Application.Anchoring;
using CreatorLedger.Domain.Ledger;
using CreatorLedger.Domain.Ledger.Events;
using CreatorLedger.Domain.Primitives;
using CreatorLedger.Infrastructure.Anchoring;
using CreatorLedger.Tests.Fakes;
using Shared.Crypto;

namespace CreatorLedger.Tests.Application;

public class AnchorProofTests
{
    private readonly InMemoryLedgerRepository _ledgerRepo;
    private readonly NullAnchor _anchor;
    private readonly FakeClock _clock;
    private readonly AnchorProofHandler _handler;

    public AnchorProofTests()
    {
        _ledgerRepo = new InMemoryLedgerRepository();
        _anchor = new NullAnchor();
        _clock = new FakeClock();
        _handler = new AnchorProofHandler(_anchor, _ledgerRepo, _clock);
    }

    [Fact]
    public async Task AnchorProof_EmptyLedger_Throws()
    {
        // Empty ledger has Zero tip
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => _handler.HandleAsync(new AnchorProofCommand()));

        Assert.Contains("empty ledger", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AnchorProof_AppendsLedgerAnchoredEvent()
    {
        // Add an event so ledger isn't empty
        await AddDummyEventAsync();

        // Anchor
        var result = await _handler.HandleAsync(new AnchorProofCommand());

        // Verify LedgerAnchoredEvent was appended
        Assert.Equal(2, _ledgerRepo.Events.Count); // dummy + anchor
        var anchorEvent = _ledgerRepo.Events.Last() as LedgerAnchoredEvent;
        Assert.NotNull(anchorEvent);
    }

    [Fact]
    public async Task AnchorProof_ReturnsCorrectChainName()
    {
        await AddDummyEventAsync();

        var result = await _handler.HandleAsync(new AnchorProofCommand());

        Assert.Equal("null", result.ChainName);
    }

    [Fact]
    public async Task AnchorProof_RecordsCorrectTipHash()
    {
        // Add event
        await AddDummyEventAsync();
        var tipBeforeAnchor = await _ledgerRepo.GetLedgerTipAsync();

        // Anchor
        var result = await _handler.HandleAsync(new AnchorProofCommand());

        // The anchored hash should be the tip before the anchor event
        var anchorEvent = _ledgerRepo.Events.Last() as LedgerAnchoredEvent;
        Assert.NotNull(anchorEvent);
        Assert.Equal(tipBeforeAnchor, anchorEvent.LedgerRootHash);
        Assert.Equal(tipBeforeAnchor, result.AnchoredHash);
    }

    [Fact]
    public async Task AnchorProof_ChainsPreviousHashCorrectly()
    {
        await AddDummyEventAsync();
        var tipBeforeAnchor = await _ledgerRepo.GetLedgerTipAsync();

        var result = await _handler.HandleAsync(new AnchorProofCommand());

        // The anchor event's previous hash should be the tip before it was appended
        var anchorEvent = _ledgerRepo.Events.Last() as LedgerAnchoredEvent;
        Assert.NotNull(anchorEvent);
        Assert.Equal(tipBeforeAnchor, anchorEvent.PreviousEventHash);
    }

    [Fact]
    public async Task AnchorProof_TransactionIdIsGenerated()
    {
        await AddDummyEventAsync();

        var result = await _handler.HandleAsync(new AnchorProofCommand());

        Assert.StartsWith("null-tx-", result.TransactionId);
    }

    [Fact]
    public async Task AnchorProof_MultipleAnchors_GenerateDifferentTxIds()
    {
        await AddDummyEventAsync();

        var result1 = await _handler.HandleAsync(new AnchorProofCommand());
        var result2 = await _handler.HandleAsync(new AnchorProofCommand());

        Assert.NotEqual(result1.TransactionId, result2.TransactionId);
    }

    [Fact]
    public async Task AnchorProof_AnchoredHashCanBeLookedUp()
    {
        await AddDummyEventAsync();
        var tip = await _ledgerRepo.GetLedgerTipAsync();

        await _handler.HandleAsync(new AnchorProofCommand());

        // The NullAnchor should have recorded the hash
        var lookup = await _anchor.LookupAsync(tip);
        Assert.NotNull(lookup);
        Assert.Equal("null", lookup.ChainName);
    }

    private async Task AddDummyEventAsync()
    {
        // Add a CreatorCreated event as a seed
        var creatorId = CreatorId.New();
        using var keyPair = Ed25519KeyPair.Generate();

        var evt = new CreatorCreatedEvent(
            EventId.New(),
            _clock.UtcNow,
            Digest256.Zero, // Genesis
            creatorId,
            keyPair.PublicKey,
            "Test Creator");

        await _ledgerRepo.AppendAsync(evt);
    }
}
