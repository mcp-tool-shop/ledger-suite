using CreatorLedger.Domain.Ledger.Events;
using CreatorLedger.Domain.Primitives;
using Shared.Crypto;

namespace CreatorLedger.Tests.Domain;

public class LedgerEventTests
{
    private static (Ed25519Signature signature, ContentHash hash) CreateTestSignatureAndHash()
    {
        using var keyPair = Ed25519KeyPair.Generate();
        var data = "test"u8.ToArray();
        var hash = ContentHash.Compute(data);
        var signature = keyPair.Sign(data);
        return (signature, hash);
    }

    [Fact]
    public void AssetAttestedEvent_GenesisHash_IsAllowed()
    {
        var (signature, contentHash) = CreateTestSignatureAndHash();

        var evt = new AssetAttestedEvent(
            EventId.New(),
            DateTimeOffset.UtcNow,
            Digest256.Zero, // Genesis event uses zero hash
            AttestationId.New(),
            AssetId.New(),
            contentHash,
            CreatorId.New(),
            signature);

        Assert.Equal(Digest256.Zero, evt.PreviousEventHash);
    }

    [Fact]
    public void AssetAttestedEvent_NonUtcTimestamp_Throws()
    {
        var (signature, contentHash) = CreateTestSignatureAndHash();
        var nonUtc = new DateTimeOffset(2024, 1, 1, 12, 0, 0, TimeSpan.FromHours(-5));

        Assert.Throws<DomainException>(() =>
            new AssetAttestedEvent(
                EventId.New(),
                nonUtc,
                Digest256.Zero,
                AttestationId.New(),
                AssetId.New(),
                contentHash,
                CreatorId.New(),
                signature));
    }

    [Fact]
    public void AssetAttestedEvent_UtcTimestamp_Succeeds()
    {
        var (signature, contentHash) = CreateTestSignatureAndHash();
        var utc = new DateTimeOffset(2024, 1, 1, 12, 0, 0, TimeSpan.Zero);

        var evt = new AssetAttestedEvent(
            EventId.New(),
            utc,
            Digest256.Zero,
            AttestationId.New(),
            AssetId.New(),
            contentHash,
            CreatorId.New(),
            signature);

        Assert.Equal(utc, evt.OccurredAtUtc);
        Assert.Equal(TimeSpan.Zero, evt.OccurredAtUtc.Offset);
    }

    [Fact]
    public void AssetAttestedEvent_EmptyContentHash_Throws()
    {
        using var keyPair = Ed25519KeyPair.Generate();
        var signature = keyPair.Sign("test"u8);

        Assert.Throws<DomainException>(() =>
            new AssetAttestedEvent(
                EventId.New(),
                DateTimeOffset.UtcNow,
                Digest256.Zero,
                AttestationId.New(),
                AssetId.New(),
                default, // empty
                CreatorId.New(),
                signature));
    }

    [Fact]
    public void AssetAttestedEvent_EmptySignature_Throws()
    {
        var contentHash = ContentHash.Compute("test"u8);

        Assert.Throws<DomainException>(() =>
            new AssetAttestedEvent(
                EventId.New(),
                DateTimeOffset.UtcNow,
                Digest256.Zero,
                AttestationId.New(),
                AssetId.New(),
                contentHash,
                CreatorId.New(),
                default)); // empty
    }

    [Fact]
    public void AssetAttestedEvent_HasCorrectEventType()
    {
        var (signature, contentHash) = CreateTestSignatureAndHash();

        var evt = new AssetAttestedEvent(
            EventId.New(),
            DateTimeOffset.UtcNow,
            Digest256.Zero,
            AttestationId.New(),
            AssetId.New(),
            contentHash,
            CreatorId.New(),
            signature);

        Assert.Equal("asset_attested", evt.EventType);
    }

    [Fact]
    public void AssetDerivedEvent_HasCorrectEventType()
    {
        var (signature, contentHash) = CreateTestSignatureAndHash();

        var evt = new AssetDerivedEvent(
            EventId.New(),
            DateTimeOffset.UtcNow,
            Digest256.Zero,
            AttestationId.New(),
            AssetId.New(),
            contentHash,
            CreatorId.New(),
            signature,
            AssetId.New());

        Assert.Equal("asset_derived", evt.EventType);
    }

    [Fact]
    public void AssetDerivedEvent_CapturesParentInfo()
    {
        var (signature, contentHash) = CreateTestSignatureAndHash();
        var parentAssetId = AssetId.New();
        var parentAttestationId = AttestationId.New();

        var evt = new AssetDerivedEvent(
            EventId.New(),
            DateTimeOffset.UtcNow,
            Digest256.Zero,
            AttestationId.New(),
            AssetId.New(),
            contentHash,
            CreatorId.New(),
            signature,
            parentAssetId,
            parentAttestationId);

        Assert.Equal(parentAssetId, evt.ParentAssetId);
        Assert.Equal(parentAttestationId, evt.ParentAttestationId);
    }

    [Fact]
    public void AssetExportedEvent_HasCorrectEventType()
    {
        var evt = new AssetExportedEvent(
            EventId.New(),
            DateTimeOffset.UtcNow,
            Digest256.Zero,
            AssetId.New(),
            AttestationId.New(),
            "portfolio.zip");

        Assert.Equal("asset_exported", evt.EventType);
        Assert.Equal("portfolio.zip", evt.ExportTarget);
    }

    [Fact]
    public void LedgerAnchoredEvent_HasCorrectEventType()
    {
        var ledgerRoot = Digest256.Compute("ledger state"u8);

        var evt = new LedgerAnchoredEvent(
            EventId.New(),
            DateTimeOffset.UtcNow,
            Digest256.Zero,
            ledgerRoot,
            "polygon",
            "0x1234abcd",
            blockNumber: 12345678);

        Assert.Equal("ledger_anchored", evt.EventType);
        Assert.Equal(ledgerRoot, evt.LedgerRootHash);
        Assert.Equal("polygon", evt.ChainName);
        Assert.Equal("0x1234abcd", evt.TransactionId);
        Assert.Equal(12345678, evt.BlockNumber);
    }

    [Fact]
    public void LedgerAnchoredEvent_EmptyLedgerRootHash_Throws()
    {
        Assert.Throws<DomainException>(() =>
            new LedgerAnchoredEvent(
                EventId.New(),
                DateTimeOffset.UtcNow,
                Digest256.Zero,
                default, // empty
                "polygon",
                "0x1234abcd"));
    }

    [Fact]
    public void LedgerAnchoredEvent_EmptyChainName_Throws()
    {
        var ledgerRoot = Digest256.Compute("ledger state"u8);

        Assert.Throws<DomainException>(() =>
            new LedgerAnchoredEvent(
                EventId.New(),
                DateTimeOffset.UtcNow,
                Digest256.Zero,
                ledgerRoot,
                "", // empty
                "0x1234abcd"));
    }

    [Fact]
    public void LedgerAnchoredEvent_EmptyTransactionId_Throws()
    {
        var ledgerRoot = Digest256.Compute("ledger state"u8);

        Assert.Throws<DomainException>(() =>
            new LedgerAnchoredEvent(
                EventId.New(),
                DateTimeOffset.UtcNow,
                Digest256.Zero,
                ledgerRoot,
                "polygon",
                "")); // empty
    }

    [Fact]
    public void Events_ChainedPreviousHash_Works()
    {
        var (signature1, contentHash1) = CreateTestSignatureAndHash();
        var (signature2, contentHash2) = CreateTestSignatureAndHash();

        // First event uses genesis hash
        var event1 = new AssetAttestedEvent(
            EventId.New(),
            DateTimeOffset.UtcNow,
            Digest256.Zero,
            AttestationId.New(),
            AssetId.New(),
            contentHash1,
            CreatorId.New(),
            signature1);

        // Compute hash of first event (simplified - real impl would use canonical JSON)
        var event1Hash = Digest256.ComputeUtf8(event1.Id.ToString());

        // Second event chains to first
        var event2 = new AssetAttestedEvent(
            EventId.New(),
            DateTimeOffset.UtcNow,
            event1Hash,
            AttestationId.New(),
            AssetId.New(),
            contentHash2,
            CreatorId.New(),
            signature2);

        Assert.Equal(Digest256.Zero, event1.PreviousEventHash);
        Assert.Equal(event1Hash, event2.PreviousEventHash);
    }
}
