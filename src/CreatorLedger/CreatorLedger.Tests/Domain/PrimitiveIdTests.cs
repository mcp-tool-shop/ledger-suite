using CreatorLedger.Domain.Primitives;

namespace CreatorLedger.Tests.Domain;

public class PrimitiveIdTests
{
    [Fact]
    public void CreatorId_New_CreatesUniqueIds()
    {
        var id1 = CreatorId.New();
        var id2 = CreatorId.New();

        Assert.NotEqual(id1, id2);
    }

    [Fact]
    public void CreatorId_Parse_RoundTrip()
    {
        var original = CreatorId.New();
        var str = original.ToString();

        var parsed = CreatorId.Parse(str);

        Assert.Equal(original, parsed);
    }

    [Fact]
    public void CreatorId_Parse_InvalidString_Throws()
    {
        Assert.Throws<FormatException>(() => CreatorId.Parse("not-a-guid"));
    }

    [Fact]
    public void CreatorId_Parse_EmptyGuid_Throws()
    {
        Assert.Throws<FormatException>(() => CreatorId.Parse(Guid.Empty.ToString()));
    }

    [Fact]
    public void CreatorId_FromGuid_EmptyGuid_Throws()
    {
        Assert.Throws<DomainException>(() => CreatorId.FromGuid(Guid.Empty));
    }

    [Fact]
    public void CreatorId_TryParse_Valid_ReturnsTrue()
    {
        var original = CreatorId.New();
        var success = CreatorId.TryParse(original.ToString(), out var parsed);

        Assert.True(success);
        Assert.Equal(original, parsed);
    }

    [Fact]
    public void CreatorId_TryParse_Invalid_ReturnsFalse()
    {
        var success = CreatorId.TryParse("invalid", out _);
        Assert.False(success);
    }

    [Fact]
    public void CreatorId_TryParse_Null_ReturnsFalse()
    {
        var success = CreatorId.TryParse(null, out _);
        Assert.False(success);
    }

    [Fact]
    public void CreatorId_Equality()
    {
        var guid = Guid.NewGuid();
        var id1 = CreatorId.FromGuid(guid);
        var id2 = CreatorId.FromGuid(guid);

        Assert.True(id1 == id2);
        Assert.False(id1 != id2);
        Assert.True(id1.Equals(id2));
        Assert.True(id1.Equals((object)id2));
        Assert.Equal(id1.GetHashCode(), id2.GetHashCode());
    }

    [Fact]
    public void CreatorId_ToGuid_ReturnsOriginalGuid()
    {
        var guid = Guid.NewGuid();
        var id = CreatorId.FromGuid(guid);

        Assert.Equal(guid, id.ToGuid());
    }

    // AssetId tests
    [Fact]
    public void AssetId_New_CreatesUniqueIds()
    {
        var id1 = AssetId.New();
        var id2 = AssetId.New();

        Assert.NotEqual(id1, id2);
    }

    [Fact]
    public void AssetId_Parse_RoundTrip()
    {
        var original = AssetId.New();
        var parsed = AssetId.Parse(original.ToString());

        Assert.Equal(original, parsed);
    }

    [Fact]
    public void AssetId_FromGuid_EmptyGuid_Throws()
    {
        Assert.Throws<DomainException>(() => AssetId.FromGuid(Guid.Empty));
    }

    // AttestationId tests
    [Fact]
    public void AttestationId_New_CreatesUniqueIds()
    {
        var id1 = AttestationId.New();
        var id2 = AttestationId.New();

        Assert.NotEqual(id1, id2);
    }

    [Fact]
    public void AttestationId_Parse_RoundTrip()
    {
        var original = AttestationId.New();
        var parsed = AttestationId.Parse(original.ToString());

        Assert.Equal(original, parsed);
    }

    [Fact]
    public void AttestationId_FromGuid_EmptyGuid_Throws()
    {
        Assert.Throws<DomainException>(() => AttestationId.FromGuid(Guid.Empty));
    }

    // EventId tests
    [Fact]
    public void EventId_New_CreatesUniqueIds()
    {
        var id1 = EventId.New();
        var id2 = EventId.New();

        Assert.NotEqual(id1, id2);
    }

    [Fact]
    public void EventId_Parse_RoundTrip()
    {
        var original = EventId.New();
        var parsed = EventId.Parse(original.ToString());

        Assert.Equal(original, parsed);
    }

    [Fact]
    public void EventId_FromGuid_EmptyGuid_Throws()
    {
        Assert.Throws<DomainException>(() => EventId.FromGuid(Guid.Empty));
    }
}
