using Shared.Crypto;

namespace CreatorLedger.Tests.Crypto;

public class Ed25519Tests
{
    [Fact]
    public void KeyPair_Generate_ProducesValidKeys()
    {
        using var keyPair = Ed25519KeyPair.Generate();

        Assert.NotNull(keyPair.PublicKey);
        Assert.NotNull(keyPair.PrivateKey);
        Assert.Equal(Ed25519PublicKey.ByteLength, keyPair.PublicKey.AsBytes().Length);
        Assert.Equal(Ed25519PrivateKey.ByteLength, keyPair.PrivateKey.AsBytes().Length);
    }

    [Fact]
    public void KeyPair_Generate_ProducesUniqueKeys()
    {
        using var keyPair1 = Ed25519KeyPair.Generate();
        using var keyPair2 = Ed25519KeyPair.Generate();

        Assert.NotEqual(keyPair1.PublicKey, keyPair2.PublicKey);
    }

    [Fact]
    public void Sign_Verify_RoundTrip()
    {
        using var keyPair = Ed25519KeyPair.Generate();
        var data = "message to sign"u8.ToArray();

        var signature = keyPair.Sign(data);
        var isValid = keyPair.Verify(data, signature);

        Assert.True(isValid);
    }

    [Fact]
    public void Verify_WrongData_Fails()
    {
        using var keyPair = Ed25519KeyPair.Generate();
        var originalData = "original message"u8.ToArray();
        var tamperedData = "tampered message"u8.ToArray();

        var signature = keyPair.Sign(originalData);
        var isValid = keyPair.PublicKey.Verify(tamperedData, signature);

        Assert.False(isValid);
    }

    [Fact]
    public void Verify_WrongSignature_Fails()
    {
        using var keyPair = Ed25519KeyPair.Generate();
        var data = "message"u8.ToArray();

        var signature = keyPair.Sign(data);

        // Tamper with signature
        var sigBytes = signature.AsBytes().ToArray();
        sigBytes[0] ^= 0xFF;
        var tamperedSig = Ed25519Signature.FromBytes(sigBytes);

        var isValid = keyPair.PublicKey.Verify(data, tamperedSig);

        Assert.False(isValid);
    }

    [Fact]
    public void Verify_WrongKey_Fails()
    {
        using var keyPair1 = Ed25519KeyPair.Generate();
        using var keyPair2 = Ed25519KeyPair.Generate();
        var data = "message"u8.ToArray();

        var signature = keyPair1.Sign(data);
        var isValid = keyPair2.PublicKey.Verify(data, signature);

        Assert.False(isValid);
    }

    [Fact]
    public void PublicKey_Parse_ToString_RoundTrip()
    {
        using var keyPair = Ed25519KeyPair.Generate();

        var encoded = keyPair.PublicKey.ToString();
        var parsed = Ed25519PublicKey.Parse(encoded);

        Assert.Equal(keyPair.PublicKey, parsed);
    }

    [Fact]
    public void PublicKey_ToString_HasCorrectPrefix()
    {
        using var keyPair = Ed25519KeyPair.Generate();

        var encoded = keyPair.PublicKey.ToString();

        Assert.StartsWith(Ed25519PublicKey.Prefix, encoded);
    }

    [Fact]
    public void PublicKey_Parse_InvalidPrefix_Throws()
    {
        Assert.Throws<FormatException>(() => Ed25519PublicKey.Parse("invalid:AAAA"));
    }

    [Fact]
    public void PublicKey_Parse_InvalidBase64_Throws()
    {
        Assert.Throws<FormatException>(() => Ed25519PublicKey.Parse("ed25519:not-valid-base64!!!"));
    }

    [Fact]
    public void PublicKey_TryParse_Invalid_ReturnsFalse()
    {
        var success = Ed25519PublicKey.TryParse("garbage", out var result);

        Assert.False(success);
        Assert.Null(result);
    }

    [Fact]
    public void PublicKey_TryParse_Null_ReturnsFalse()
    {
        var success = Ed25519PublicKey.TryParse(null, out _);

        Assert.False(success);
    }

    [Fact]
    public void Signature_Parse_ToString_RoundTrip()
    {
        using var keyPair = Ed25519KeyPair.Generate();
        var signature = keyPair.Sign("test"u8.ToArray());

        var base64 = signature.ToString();
        var parsed = Ed25519Signature.Parse(base64);

        Assert.Equal(signature, parsed);
    }

    [Fact]
    public void Signature_TryParse_Invalid_ReturnsFalse()
    {
        var success = Ed25519Signature.TryParse("not-base64!!!", out _);

        Assert.False(success);
    }

    [Fact]
    public void Signature_TryParse_WrongLength_ReturnsFalse()
    {
        var shortBase64 = Convert.ToBase64String(new byte[32]); // Should be 64 bytes

        var success = Ed25519Signature.TryParse(shortBase64, out _);

        Assert.False(success);
    }

    [Fact]
    public void PrivateKey_FromBytes_RoundTrip()
    {
        using var original = Ed25519PrivateKey.Generate();
        var bytes = original.AsBytes().ToArray();

        using var restored = Ed25519PrivateKey.FromBytes(bytes);

        Assert.Equal(original.GetPublicKey(), restored.GetPublicKey());
    }

    [Fact]
    public void PrivateKey_Dispose_ClearsMemory()
    {
        var privateKey = Ed25519PrivateKey.Generate();
        var bytesBeforeDispose = privateKey.AsBytes().ToArray();

        privateKey.Dispose();

        // After dispose, accessing should throw
        Assert.Throws<ObjectDisposedException>(() => privateKey.AsBytes());
    }

    [Fact]
    public void KeyPair_Dispose_ClearsPrivateKey()
    {
        var keyPair = Ed25519KeyPair.Generate();
        keyPair.Dispose();

        Assert.Throws<ObjectDisposedException>(() => keyPair.PrivateKey);
        Assert.Throws<ObjectDisposedException>(() => keyPair.PublicKey);
        Assert.Throws<ObjectDisposedException>(() => keyPair.Sign("test"u8.ToArray()));
    }

    [Fact]
    public void KeyPair_FromPrivateKeyBytes_RestoresKeyPair()
    {
        using var original = Ed25519KeyPair.Generate();
        var seed = original.PrivateKey.AsBytes().ToArray();

        using var restored = Ed25519KeyPair.FromPrivateKeyBytes(seed);

        Assert.Equal(original.PublicKey, restored.PublicKey);
    }

    [Fact]
    public void PublicKey_Equality()
    {
        using var keyPair = Ed25519KeyPair.Generate();
        var pk1 = keyPair.PublicKey;
        var pk2 = Ed25519PublicKey.FromBytes(pk1.AsBytes());

        Assert.True(pk1 == pk2);
        Assert.False(pk1 != pk2);
        Assert.True(pk1.Equals(pk2));
        Assert.Equal(pk1.GetHashCode(), pk2.GetHashCode());
    }

    [Fact]
    public void PublicKey_Null_Equality()
    {
        using var keyPair = Ed25519KeyPair.Generate();
        Ed25519PublicKey? nullKey = null;

        Assert.False(keyPair.PublicKey == nullKey);
        Assert.True(keyPair.PublicKey != nullKey);
        Assert.True(nullKey == null);
    }

    [Fact]
    public void Signature_Equality()
    {
        using var keyPair = Ed25519KeyPair.Generate();
        var sig1 = keyPair.Sign("test"u8.ToArray());
        var sig2 = Ed25519Signature.FromBytes(sig1.AsBytes());

        Assert.True(sig1 == sig2);
        Assert.False(sig1 != sig2);
        Assert.Equal(sig1.GetHashCode(), sig2.GetHashCode());
    }

    [Fact]
    public void Signature_Default_IsEmpty()
    {
        Ed25519Signature defaultSig = default;

        Assert.Equal(string.Empty, defaultSig.ToString());
        Assert.Empty(defaultSig.AsBytes().ToArray());
    }
}
