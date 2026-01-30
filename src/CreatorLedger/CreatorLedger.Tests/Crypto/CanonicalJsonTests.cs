using Shared.Crypto;

namespace CreatorLedger.Tests.Crypto;

public class CanonicalJsonTests
{
    [Fact]
    public void Serialize_ProducesCompactOutput()
    {
        var obj = new { Name = "test", Value = 42 };

        var json = CanonicalJson.Serialize(obj);

        Assert.DoesNotContain("\n", json);
        Assert.DoesNotContain("  ", json);
    }

    [Fact]
    public void Serialize_SameInput_ProducesSameOutput()
    {
        var obj = new { A = 1, B = "two", C = true };

        var json1 = CanonicalJson.Serialize(obj);
        var json2 = CanonicalJson.Serialize(obj);

        Assert.Equal(json1, json2);
    }

    [Fact]
    public void SerializeToBytes_ProducesUtf8()
    {
        var obj = new { Text = "hello" };

        var bytes = CanonicalJson.SerializeToBytes(obj);
        var text = System.Text.Encoding.UTF8.GetString(bytes);

        Assert.Contains("hello", text);
    }

    [Fact]
    public void HashOf_SameInput_ProducesSameHash()
    {
        var obj = new { Id = "abc", Count = 123 };

        var hash1 = CanonicalJson.HashOf(obj);
        var hash2 = CanonicalJson.HashOf(obj);

        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void HashOf_DifferentInput_ProducesDifferentHash()
    {
        var obj1 = new { Value = 1 };
        var obj2 = new { Value = 2 };

        var hash1 = CanonicalJson.HashOf(obj1);
        var hash2 = CanonicalJson.HashOf(obj2);

        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public void FormatTimestamp_ProducesIso8601()
    {
        var timestamp = new DateTimeOffset(2024, 6, 15, 10, 30, 0, TimeSpan.Zero);

        var formatted = CanonicalJson.FormatTimestamp(timestamp);

        Assert.Equal("2024-06-15T10:30:00.0000000Z", formatted);
    }

    [Fact]
    public void FormatTimestamp_ConvertsToUtc()
    {
        // Eastern time offset
        var timestamp = new DateTimeOffset(2024, 6, 15, 10, 30, 0, TimeSpan.FromHours(-5));

        var formatted = CanonicalJson.FormatTimestamp(timestamp);

        // Should be converted to UTC (10:30 - (-5) = 15:30 UTC)
        Assert.Equal("2024-06-15T15:30:00.0000000Z", formatted);
    }

    [Fact]
    public void ParseTimestamp_RoundTrip()
    {
        var original = DateTimeOffset.UtcNow;
        var formatted = CanonicalJson.FormatTimestamp(original);

        var parsed = CanonicalJson.ParseTimestamp(formatted);

        // Compare with tolerance for formatting precision
        Assert.Equal(original.UtcDateTime, parsed.UtcDateTime, TimeSpan.FromMicroseconds(1));
    }

    [Fact]
    public void ParseTimestamp_FromKnownString()
    {
        const string timestamp = "2024-01-15T12:00:00.0000000Z";

        var parsed = CanonicalJson.ParseTimestamp(timestamp);

        Assert.Equal(2024, parsed.Year);
        Assert.Equal(1, parsed.Month);
        Assert.Equal(15, parsed.Day);
        Assert.Equal(12, parsed.Hour);
        Assert.Equal(0, parsed.Minute);
    }

    [Fact]
    public void Serialize_HandlesSpecialCharacters()
    {
        var obj = new { Text = "Hello \"World\" <tag>" };

        var json = CanonicalJson.Serialize(obj);

        // Should contain the characters, properly escaped
        Assert.Contains("Hello", json);
        Assert.Contains("World", json);
    }

    [Fact]
    public void Serialize_HandlesUnicode()
    {
        var obj = new { Text = "Caf\u00e9 \u2603" }; // Café ☃

        var json = CanonicalJson.Serialize(obj);
        var bytes = CanonicalJson.SerializeToBytes(obj);

        // Should be valid UTF-8
        var decoded = System.Text.Encoding.UTF8.GetString(bytes);
        Assert.Contains("Caf\u00e9", decoded);
    }

    [Fact]
    public void Serialize_NullValue_IncludesNull()
    {
        var obj = new { Name = (string?)null };

        var json = CanonicalJson.Serialize(obj);

        Assert.Contains("null", json);
    }

    [Fact]
    public void HashOf_Deterministic_AcrossInstances()
    {
        // Create two separate instances with same data
        var dto1 = new TestDto { Id = "test-123", CreatedAt = "2024-01-01T00:00:00Z" };
        var dto2 = new TestDto { Id = "test-123", CreatedAt = "2024-01-01T00:00:00Z" };

        var hash1 = CanonicalJson.HashOf(dto1);
        var hash2 = CanonicalJson.HashOf(dto2);

        Assert.Equal(hash1, hash2);
    }

    private sealed class TestDto
    {
        public required string Id { get; init; }
        public required string CreatedAt { get; init; }
    }
}
