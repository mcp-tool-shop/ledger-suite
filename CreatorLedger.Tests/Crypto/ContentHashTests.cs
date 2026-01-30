using Shared.Crypto;

namespace CreatorLedger.Tests.Crypto;

public class ContentHashTests
{
    [Fact]
    public void Compute_SameInput_ProducesSameHash()
    {
        var data = "Hello, World!"u8.ToArray();

        var hash1 = ContentHash.Compute(data);
        var hash2 = ContentHash.Compute(data);

        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void Compute_DifferentInput_ProducesDifferentHash()
    {
        var data1 = "Hello"u8.ToArray();
        var data2 = "World"u8.ToArray();

        var hash1 = ContentHash.Compute(data1);
        var hash2 = ContentHash.Compute(data2);

        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public void Compute_EmptyInput_ProducesKnownHash()
    {
        // SHA-256 of empty string is a known constant
        var expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        var hash = ContentHash.Compute([]);

        Assert.Equal(expected, hash.ToString());
    }

    [Fact]
    public void ToString_ReturnsLowercaseHex()
    {
        var data = "test"u8.ToArray();

        var hash = ContentHash.Compute(data);
        var hex = hash.ToString();

        Assert.Equal(64, hex.Length); // 32 bytes = 64 hex chars
        Assert.Equal(hex, hex.ToLowerInvariant());
    }

    [Fact]
    public void Parse_ValidHex_Succeeds()
    {
        var original = ContentHash.Compute("test data"u8.ToArray());
        var hex = original.ToString();

        var parsed = ContentHash.Parse(hex);

        Assert.Equal(original, parsed);
    }

    [Fact]
    public void Parse_InvalidHex_Throws()
    {
        Assert.Throws<FormatException>(() => ContentHash.Parse("not-valid-hex"));
    }

    [Fact]
    public void Parse_WrongLength_Throws()
    {
        Assert.Throws<FormatException>(() => ContentHash.Parse("abcd1234"));
    }

    [Fact]
    public void TryParse_ValidHex_ReturnsTrue()
    {
        var original = ContentHash.Compute("data"u8.ToArray());
        var hex = original.ToString();

        var success = ContentHash.TryParse(hex, out var parsed);

        Assert.True(success);
        Assert.Equal(original, parsed);
    }

    [Fact]
    public void TryParse_InvalidHex_ReturnsFalse()
    {
        var success = ContentHash.TryParse("invalid", out _);

        Assert.False(success);
    }

    [Fact]
    public void TryParse_Null_ReturnsFalse()
    {
        var success = ContentHash.TryParse(null, out _);

        Assert.False(success);
    }

    [Fact]
    public void TryParse_UppercaseHex_Succeeds()
    {
        var original = ContentHash.Compute("test"u8.ToArray());
        var upperHex = original.ToString().ToUpperInvariant();

        var success = ContentHash.TryParse(upperHex, out var parsed);

        Assert.True(success);
        Assert.Equal(original, parsed);
    }

    [Fact]
    public void AsBytes_ReturnsCorrectLength()
    {
        var hash = ContentHash.Compute("data"u8.ToArray());

        Assert.Equal(ContentHash.ByteLength, hash.AsBytes().Length);
    }

    [Fact]
    public void Equality_SameHash_AreEqual()
    {
        var hash1 = ContentHash.Compute("same"u8.ToArray());
        var hash2 = ContentHash.Compute("same"u8.ToArray());

        Assert.True(hash1 == hash2);
        Assert.False(hash1 != hash2);
        Assert.True(hash1.Equals(hash2));
        Assert.True(hash1.Equals((object)hash2));
    }

    [Fact]
    public void Equality_DifferentHash_AreNotEqual()
    {
        var hash1 = ContentHash.Compute("one"u8.ToArray());
        var hash2 = ContentHash.Compute("two"u8.ToArray());

        Assert.False(hash1 == hash2);
        Assert.True(hash1 != hash2);
    }

    [Fact]
    public void CompareTo_ProducesConsistentOrdering()
    {
        var hashes = new[]
        {
            ContentHash.Compute("a"u8.ToArray()),
            ContentHash.Compute("b"u8.ToArray()),
            ContentHash.Compute("c"u8.ToArray()),
        };

        var sorted = hashes.OrderBy(h => h).ToArray();

        // Should be in consistent order
        Assert.True(sorted[0] <= sorted[1]);
        Assert.True(sorted[1] <= sorted[2]);
    }

    [Fact]
    public void GetHashCode_SameHash_SameCode()
    {
        var hash1 = ContentHash.Compute("test"u8.ToArray());
        var hash2 = ContentHash.Compute("test"u8.ToArray());

        Assert.Equal(hash1.GetHashCode(), hash2.GetHashCode());
    }

    [Fact]
    public void Default_ProducesZeroHash()
    {
        ContentHash defaultHash = default;
        var hex = defaultHash.ToString();

        Assert.Equal(new string('0', 64), hex);
    }

    [Fact]
    public void Compute_FromStream_MatchesDirectCompute()
    {
        var data = "stream data test"u8.ToArray();
        using var stream = new MemoryStream(data);

        var hashFromBytes = ContentHash.Compute(data);
        var hashFromStream = ContentHash.Compute(stream);

        Assert.Equal(hashFromBytes, hashFromStream);
    }
}
