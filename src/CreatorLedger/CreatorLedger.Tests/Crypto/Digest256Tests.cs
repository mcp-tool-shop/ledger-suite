using Shared.Crypto;

namespace CreatorLedger.Tests.Crypto;

public class Digest256Tests
{
    [Fact]
    public void Compute_SameInput_ProducesSameDigest()
    {
        var data = "event data"u8.ToArray();

        var digest1 = Digest256.Compute(data);
        var digest2 = Digest256.Compute(data);

        Assert.Equal(digest1, digest2);
    }

    [Fact]
    public void Compute_DifferentInput_ProducesDifferentDigest()
    {
        var data1 = "event1"u8.ToArray();
        var data2 = "event2"u8.ToArray();

        var digest1 = Digest256.Compute(data1);
        var digest2 = Digest256.Compute(data2);

        Assert.NotEqual(digest1, digest2);
    }

    [Fact]
    public void ComputeUtf8_MatchesByteCompute()
    {
        const string text = "canonical json";
        var bytes = System.Text.Encoding.UTF8.GetBytes(text);

        var digestFromUtf8 = Digest256.ComputeUtf8(text);
        var digestFromBytes = Digest256.Compute(bytes);

        Assert.Equal(digestFromBytes, digestFromUtf8);
    }

    [Fact]
    public void Zero_IsAllZeros()
    {
        var zero = Digest256.Zero;
        var bytes = zero.AsBytes();

        Assert.Equal(Digest256.ByteLength, bytes.Length);
        Assert.All(bytes.ToArray(), b => Assert.Equal(0, b));
    }

    [Fact]
    public void Zero_HasKnownHexRepresentation()
    {
        var zero = Digest256.Zero;

        Assert.Equal(new string('0', 64), zero.ToString());
    }

    [Fact]
    public void Parse_ValidHex_Succeeds()
    {
        var original = Digest256.Compute("test"u8.ToArray());
        var hex = original.ToString();

        var parsed = Digest256.Parse(hex);

        Assert.Equal(original, parsed);
    }

    [Fact]
    public void Parse_InvalidHex_Throws()
    {
        Assert.Throws<FormatException>(() => Digest256.Parse("not-hex"));
    }

    [Fact]
    public void TryParse_ValidHex_ReturnsTrue()
    {
        var original = Digest256.Compute("data"u8.ToArray());
        var hex = original.ToString();

        var success = Digest256.TryParse(hex, out var parsed);

        Assert.True(success);
        Assert.Equal(original, parsed);
    }

    [Fact]
    public void TryParse_InvalidHex_ReturnsFalse()
    {
        var success = Digest256.TryParse("invalid", out _);

        Assert.False(success);
    }

    [Fact]
    public void FromBytes_ValidLength_Succeeds()
    {
        var bytes = new byte[Digest256.ByteLength];
        bytes[0] = 0xAB;
        bytes[31] = 0xCD;

        var digest = Digest256.FromBytes(bytes);

        Assert.Equal(bytes, digest.AsBytes().ToArray());
    }

    [Fact]
    public void FromBytes_InvalidLength_Throws()
    {
        var shortBytes = new byte[16];

        Assert.Throws<ArgumentException>(() => Digest256.FromBytes(shortBytes));
    }

    [Fact]
    public void ToString_ReturnsLowercaseHex()
    {
        var digest = Digest256.Compute("test"u8.ToArray());
        var hex = digest.ToString();

        Assert.Equal(64, hex.Length);
        Assert.Equal(hex, hex.ToLowerInvariant());
    }

    [Fact]
    public void Equality_SameDigest_AreEqual()
    {
        var digest1 = Digest256.Compute("same"u8.ToArray());
        var digest2 = Digest256.Compute("same"u8.ToArray());

        Assert.True(digest1 == digest2);
        Assert.False(digest1 != digest2);
        Assert.True(digest1.Equals(digest2));
    }

    [Fact]
    public void CompareTo_ProducesConsistentOrdering()
    {
        var digests = new[]
        {
            Digest256.Compute("x"u8.ToArray()),
            Digest256.Compute("y"u8.ToArray()),
            Digest256.Compute("z"u8.ToArray()),
        };

        var sorted = digests.OrderBy(d => d).ToArray();

        Assert.True(sorted[0] <= sorted[1]);
        Assert.True(sorted[1] <= sorted[2]);
    }

    [Fact]
    public void Digest256_And_ContentHash_AreDifferentTypes()
    {
        // Same input produces same raw bytes, but they're different semantic types
        var data = "same input"u8.ToArray();

        var contentHash = ContentHash.Compute(data);
        var digest = Digest256.Compute(data);

        // Both produce same hex (same algorithm)
        Assert.Equal(contentHash.ToString(), digest.ToString());

        // But they're not the same type (compile-time safety)
        // This test documents the semantic distinction
    }
}
