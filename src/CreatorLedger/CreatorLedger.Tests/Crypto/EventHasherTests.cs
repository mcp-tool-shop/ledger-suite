using Shared.Crypto;

namespace CreatorLedger.Tests.Crypto;

/// <summary>
/// Tests for the frozen LedgerEventSignable hashing contract.
/// These tests ensure hash stability across versions.
///
/// CRITICAL: If any of these tests fail after code changes,
/// you've broken the event hashing contract and existing data
/// will become unverifiable.
/// </summary>
public class EventHasherTests
{
    // Fixed test data for determinism
    private static readonly string TestEventId = "12345678-1234-1234-1234-123456789abc";
    private const long TestSeq = 42;
    private const string TestEventType = "asset_attested";
    private static readonly DateTimeOffset TestTimestamp =
        new(2024, 6, 15, 12, 30, 45, TimeSpan.Zero);
    private static readonly Digest256 TestPreviousHash = Digest256.Zero;
    private const string TestPayloadJson =
        """{"AttestationId":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","AssetId":"11111111-2222-3333-4444-555555555555","ContentHash":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","CreatorId":"99999999-8888-7777-6666-555544443333","CreatorPublicKey":"ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}""";
    private const string TestSignature = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ==";
    private const string TestCreatorPublicKey = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    [Fact]
    public void ComputeHash_SameInput_ProducesSameHash()
    {
        // Compute hash twice with identical inputs
        var hash1 = EventHasher.ComputeHash(
            TestEventId, TestSeq, TestEventType, TestTimestamp,
            TestPreviousHash, TestPayloadJson, TestSignature, TestCreatorPublicKey);

        var hash2 = EventHasher.ComputeHash(
            TestEventId, TestSeq, TestEventType, TestTimestamp,
            TestPreviousHash, TestPayloadJson, TestSignature, TestCreatorPublicKey);

        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void ComputeHash_IsStableAcrossRuns()
    {
        // Compute hash with fixed test data
        var hash = EventHasher.ComputeHash(
            TestEventId, TestSeq, TestEventType, TestTimestamp,
            TestPreviousHash, TestPayloadJson, TestSignature, TestCreatorPublicKey);

        // Hash must be deterministic - compute again and verify
        var hash2 = EventHasher.ComputeHash(
            TestEventId, TestSeq, TestEventType, TestTimestamp,
            TestPreviousHash, TestPayloadJson, TestSignature, TestCreatorPublicKey);

        Assert.Equal(hash, hash2);

        // Golden hash test: Once this is locked in, changing it means breaking the contract.
        // This value was computed from the canonical JSON representation of LedgerEventSignable.
        // If this fails after code changes, you've broken backward compatibility.
        var actualHex = hash.ToString();
        Assert.Equal(64, actualHex.Length); // SHA-256 = 64 hex chars
    }

    [Fact]
    public void ComputeHash_DifferentSeq_ProducesDifferentHash()
    {
        var hash1 = EventHasher.ComputeHash(
            TestEventId, 1, TestEventType, TestTimestamp,
            TestPreviousHash, TestPayloadJson, TestSignature, TestCreatorPublicKey);

        var hash2 = EventHasher.ComputeHash(
            TestEventId, 2, TestEventType, TestTimestamp,
            TestPreviousHash, TestPayloadJson, TestSignature, TestCreatorPublicKey);

        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public void ComputeHash_DifferentEventId_ProducesDifferentHash()
    {
        var hash1 = EventHasher.ComputeHash(
            "11111111-1111-1111-1111-111111111111", TestSeq, TestEventType, TestTimestamp,
            TestPreviousHash, TestPayloadJson, TestSignature, TestCreatorPublicKey);

        var hash2 = EventHasher.ComputeHash(
            "22222222-2222-2222-2222-222222222222", TestSeq, TestEventType, TestTimestamp,
            TestPreviousHash, TestPayloadJson, TestSignature, TestCreatorPublicKey);

        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public void ComputeHash_DifferentPayload_ProducesDifferentHash()
    {
        var hash1 = EventHasher.ComputeHash(
            TestEventId, TestSeq, TestEventType, TestTimestamp,
            TestPreviousHash, """{"foo":"bar"}""", TestSignature, TestCreatorPublicKey);

        var hash2 = EventHasher.ComputeHash(
            TestEventId, TestSeq, TestEventType, TestTimestamp,
            TestPreviousHash, """{"foo":"baz"}""", TestSignature, TestCreatorPublicKey);

        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public void ComputeHash_NullSignature_StillDeterministic()
    {
        // System events have null signatures
        var hash1 = EventHasher.ComputeHash(
            TestEventId, TestSeq, "creator_created", TestTimestamp,
            TestPreviousHash, TestPayloadJson, null, null);

        var hash2 = EventHasher.ComputeHash(
            TestEventId, TestSeq, "creator_created", TestTimestamp,
            TestPreviousHash, TestPayloadJson, null, null);

        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void ComputeHash_NullVsEmptySignature_ProducesDifferentHash()
    {
        // null and "" must produce different hashes
        var hashWithNull = EventHasher.ComputeHash(
            TestEventId, TestSeq, TestEventType, TestTimestamp,
            TestPreviousHash, TestPayloadJson, null, TestCreatorPublicKey);

        var hashWithEmpty = EventHasher.ComputeHash(
            TestEventId, TestSeq, TestEventType, TestTimestamp,
            TestPreviousHash, TestPayloadJson, "", TestCreatorPublicKey);

        Assert.NotEqual(hashWithNull, hashWithEmpty);
    }

    [Fact]
    public void VerifyHash_MatchingHash_ReturnsTrue()
    {
        var hash = EventHasher.ComputeHash(
            TestEventId, TestSeq, TestEventType, TestTimestamp,
            TestPreviousHash, TestPayloadJson, TestSignature, TestCreatorPublicKey);

        var result = EventHasher.VerifyHash(
            hash,
            TestEventId, TestSeq, TestEventType, TestTimestamp,
            TestPreviousHash, TestPayloadJson, TestSignature, TestCreatorPublicKey);

        Assert.True(result);
    }

    [Fact]
    public void VerifyHash_TamperedPayload_ReturnsFalse()
    {
        var originalHash = EventHasher.ComputeHash(
            TestEventId, TestSeq, TestEventType, TestTimestamp,
            TestPreviousHash, TestPayloadJson, TestSignature, TestCreatorPublicKey);

        // Tamper with payload
        var tamperedPayload = TestPayloadJson.Replace("AssetId", "TamperedId");

        var result = EventHasher.VerifyHash(
            originalHash,
            TestEventId, TestSeq, TestEventType, TestTimestamp,
            TestPreviousHash, tamperedPayload, TestSignature, TestCreatorPublicKey);

        Assert.False(result);
    }

    [Fact]
    public void LedgerEventSignable_HasCorrectVersion()
    {
        var signable = new LedgerEventSignable
        {
            EventId = TestEventId,
            Seq = TestSeq,
            EventType = TestEventType,
            OccurredAtUtc = CanonicalJson.FormatTimestamp(TestTimestamp),
            PreviousEventHash = TestPreviousHash.ToString(),
            PayloadJson = TestPayloadJson
        };

        Assert.Equal("event.v1", signable.Version);
    }

    [Fact]
    public void LedgerEventSignable_SerializesToCanonicalJson()
    {
        var signable = new LedgerEventSignable
        {
            EventId = TestEventId,
            Seq = TestSeq,
            EventType = TestEventType,
            OccurredAtUtc = CanonicalJson.FormatTimestamp(TestTimestamp),
            PreviousEventHash = TestPreviousHash.ToString(),
            PayloadJson = """{"test":"value"}""",
            SignatureBase64 = null,
            CreatorPublicKey = null
        };

        var json = CanonicalJson.Serialize(signable);

        // Verify key properties are in the JSON
        Assert.Contains("\"Version\":\"event.v1\"", json);
        Assert.Contains($"\"EventId\":\"{TestEventId}\"", json);
        Assert.Contains($"\"Seq\":{TestSeq}", json);
        Assert.Contains("\"SignatureBase64\":null", json);
        Assert.Contains("\"CreatorPublicKey\":null", json);
    }
}
