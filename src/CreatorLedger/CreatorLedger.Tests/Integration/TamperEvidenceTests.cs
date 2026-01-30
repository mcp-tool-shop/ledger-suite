using System.Runtime.Versioning;
using CreatorLedger.Application.Attestation;
using CreatorLedger.Application.Export;
using CreatorLedger.Application.Identity;
using CreatorLedger.Application.Signing;
using CreatorLedger.Application.Verification;
using CreatorLedger.Domain.Trust;
using CreatorLedger.Domain.Primitives;
using CreatorLedger.Infrastructure.Persistence;
using CreatorLedger.Infrastructure.Security;
using Microsoft.Data.Sqlite;
using Shared.Crypto;

namespace CreatorLedger.Tests.Integration;

/// <summary>
/// Tamper evidence tests that prove the system detects data manipulation.
/// These tests directly modify SQLite data to simulate attacks and verify
/// that the verification layer catches them.
///
/// THREAT MODEL:
/// - Attacker has write access to the database file
/// - Attacker cannot forge Ed25519 signatures
/// - System must detect any modification to payload_json
/// </summary>
[SupportedOSPlatform("windows")]
public class TamperEvidenceTests : IDisposable
{
    private readonly SqliteTestFixture _fixture;
    private readonly string _tempKeyDir;
    private readonly DpapiKeyVault _keyVault;

    private readonly CreateIdentityHandler _createIdentityHandler;
    private readonly AttestAssetHandler _attestHandler;
    private readonly VerifyAssetHandler _verifyHandler;
    private readonly ExportProofBundleHandler _exportHandler;

    public TamperEvidenceTests()
    {
        _fixture = new SqliteTestFixture();
        _tempKeyDir = Path.Combine(Path.GetTempPath(), $"tamper_test_{Guid.NewGuid():N}");
        _keyVault = new DpapiKeyVault(_tempKeyDir);

        _createIdentityHandler = new CreateIdentityHandler(
            _keyVault,
            _fixture.IdentityRepository,
            _fixture.LedgerRepository,
            _fixture.Clock);

        _attestHandler = new AttestAssetHandler(
            _keyVault,
            _fixture.IdentityRepository,
            _fixture.LedgerRepository,
            _fixture.Clock);

        _verifyHandler = new VerifyAssetHandler(
            _fixture.LedgerRepository,
            _fixture.IdentityRepository);

        _exportHandler = new ExportProofBundleHandler(
            _fixture.LedgerRepository,
            _fixture.IdentityRepository,
            _fixture.Clock);
    }

    public void Dispose()
    {
        _fixture.Dispose();

        try
        {
            if (Directory.Exists(_tempKeyDir))
                Directory.Delete(_tempKeyDir, recursive: true);
        }
        catch { }
    }

    /// <summary>
    /// Verifies that tampering with payload_json is detected when verifying.
    /// This test bypasses the append-only triggers by using a separate connection
    /// without the triggers to simulate a malicious database edit.
    /// </summary>
    [Fact]
    public async Task TamperedPayload_SignatureVerification_Fails()
    {
        // 1. Create a valid attestation
        var identityResult = await _createIdentityHandler.HandleAsync(
            new CreateIdentityCommand("Victim Artist"));

        var assetId = AssetId.New();
        var originalHash = ContentHash.Compute("original artwork content"u8);

        await _attestHandler.HandleAsync(
            new AttestAssetCommand(assetId, originalHash, identityResult.CreatorId));

        // 2. Verify it works BEFORE tampering
        var verifyBefore = await _verifyHandler.HandleAsync(
            new VerifyAssetQuery(assetId, originalHash));

        Assert.Equal(TrustLevel.Signed, verifyBefore.TrustLevel);
        Assert.True(verifyBefore.SignatureValid, "Signature should be valid before tampering");

        // 3. Tamper with the payload_json directly in SQLite
        // We need to bypass the triggers - create a new DB without triggers
        await TamperWithPayloadAsync(assetId);

        // 4. Verify AFTER tampering - should fail verification
        var verifyAfter = await _verifyHandler.HandleAsync(
            new VerifyAssetQuery(assetId, originalHash));

        // With a tampered CreatorId, either:
        // - The fake creator doesn't exist → Unverified (SignatureValid = null)
        // - Or if somehow it does exist, signature won't match → Broken (SignatureValid = false)
        Assert.True(
            verifyAfter.TrustLevel == TrustLevel.Unverified || verifyAfter.TrustLevel == TrustLevel.Broken,
            $"Expected Unverified or Broken, got {verifyAfter.TrustLevel}. SignatureValid={verifyAfter.SignatureValid}");

        // Should NOT be Signed or VerifiedOriginal after tampering
        Assert.NotEqual(TrustLevel.Signed, verifyAfter.TrustLevel);
        Assert.NotEqual(TrustLevel.VerifiedOriginal, verifyAfter.TrustLevel);
    }

    /// <summary>
    /// Verifies that changing the content hash in payload_json breaks verification.
    /// </summary>
    [Fact]
    public async Task TamperedContentHash_InPayload_Detected()
    {
        // 1. Create a valid attestation
        var identityResult = await _createIdentityHandler.HandleAsync(
            new CreateIdentityCommand("Hash Tamperer Target"));

        var assetId = AssetId.New();
        var originalHash = ContentHash.Compute("real content"u8);

        await _attestHandler.HandleAsync(
            new AttestAssetCommand(assetId, originalHash, identityResult.CreatorId));

        // 2. Tamper: Replace the content hash in payload_json with a different hash
        var fakeHash = ContentHash.Compute("fake content - attacker trying to claim this was the original"u8);
        await TamperContentHashInPayloadAsync(assetId, fakeHash);

        // 3. Verify with the FAKE hash (what attacker wants us to believe)
        var verifyWithFake = await _verifyHandler.HandleAsync(
            new VerifyAssetQuery(assetId, fakeHash));

        // Even though the payload now contains fakeHash, the SIGNATURE was computed
        // over the ORIGINAL payload - so signature verification fails
        Assert.False(verifyWithFake.SignatureValid, "Signature should fail - payload was signed with different hash");
        Assert.Equal(TrustLevel.Broken, verifyWithFake.TrustLevel);
    }

    /// <summary>
    /// Verifies that the exported proof bundle is tamper-evident.
    /// Even if an attacker exports a bundle and modifies it, verification fails.
    /// </summary>
    [Fact]
    public async Task ExportedBundle_TamperedSignature_FailsVerification()
    {
        // 1. Create and attest
        var identityResult = await _createIdentityHandler.HandleAsync(
            new CreateIdentityCommand("Bundle Target"));

        var assetId = AssetId.New();
        var contentHash = ContentHash.Compute("bundle content"u8);

        await _attestHandler.HandleAsync(
            new AttestAssetCommand(assetId, contentHash, identityResult.CreatorId));

        // 2. Export bundle
        var bundle = await _exportHandler.HandleAsync(
            new ExportProofBundleCommand(assetId));

        // 3. Try to verify with a WRONG signature (simulating tampered bundle)
        var attestation = bundle.Attestations[0];
        var publicKey = Ed25519PublicKey.Parse(attestation.CreatorPublicKey);

        // Create a fake signable with different content
        var fakeSignable = SigningService.FromEvent(
            attestation.AssetId,
            ContentHash.Compute("attacker's fake content"u8).ToString(), // Different!
            attestation.CreatorId,
            attestation.CreatorPublicKey,
            attestation.AttestedAtUtc);

        // The original signature won't verify the fake signable
        var originalSignature = Ed25519Signature.Parse(attestation.Signature);
        var isValid = SigningService.Verify(fakeSignable, originalSignature, publicKey);

        Assert.False(isValid, "Signature should NOT verify tampered content");
    }

    /// <summary>
    /// Helper method to tamper with payload_json by bypassing triggers.
    /// Changes the CreatorId field to a different GUID (surgical change that keeps JSON valid).
    /// </summary>
    private async Task TamperWithPayloadAsync(AssetId assetId)
    {
        using var connection = new SqliteConnection($"Data Source={_fixture.DatabasePath}");
        await connection.OpenAsync();

        // Get current payload
        string currentPayload;
        using (var selectCmd = connection.CreateCommand())
        {
            selectCmd.CommandText = "SELECT payload_json FROM ledger_events WHERE asset_id = @assetId";
            selectCmd.Parameters.AddWithValue("@assetId", assetId.ToString());
            currentPayload = (string)(await selectCmd.ExecuteScalarAsync())!;
        }

        // Find and replace CreatorId with a different GUID (keeps JSON valid)
        // This simulates an attacker trying to claim a different creator made this
        var creatorIdPattern = "\"CreatorId\":\"";
        var startIdx = currentPayload.IndexOf(creatorIdPattern) + creatorIdPattern.Length;
        var endIdx = currentPayload.IndexOf("\"", startIdx);
        var originalCreatorId = currentPayload[startIdx..endIdx];

        // Generate a fake creator ID (different from original)
        var fakeCreatorId = Guid.NewGuid().ToString("D");
        var tamperedPayload = currentPayload[..startIdx] + fakeCreatorId + currentPayload[endIdx..];

        // Drop the update trigger temporarily
        using (var dropCmd = connection.CreateCommand())
        {
            dropCmd.CommandText = "DROP TRIGGER IF EXISTS trg_ledger_events_no_update";
            await dropCmd.ExecuteNonQueryAsync();
        }

        // Update with tampered payload
        using (var updateCmd = connection.CreateCommand())
        {
            updateCmd.CommandText = "UPDATE ledger_events SET payload_json = @payload WHERE asset_id = @assetId";
            updateCmd.Parameters.AddWithValue("@payload", tamperedPayload);
            updateCmd.Parameters.AddWithValue("@assetId", assetId.ToString());
            await updateCmd.ExecuteNonQueryAsync();
        }

        // Recreate the trigger
        using (var createCmd = connection.CreateCommand())
        {
            createCmd.CommandText = """
                CREATE TRIGGER IF NOT EXISTS trg_ledger_events_no_update
                BEFORE UPDATE ON ledger_events
                BEGIN
                    SELECT RAISE(ABORT, 'ledger_events is append-only: UPDATE not allowed');
                END
                """;
            await createCmd.ExecuteNonQueryAsync();
        }
    }

    /// <summary>
    /// Helper to replace the content hash in payload_json with a different hash.
    /// </summary>
    private async Task TamperContentHashInPayloadAsync(AssetId assetId, ContentHash fakeHash)
    {
        using var connection = new SqliteConnection($"Data Source={_fixture.DatabasePath}");
        await connection.OpenAsync();

        // Get current payload
        string currentPayload;
        using (var selectCmd = connection.CreateCommand())
        {
            selectCmd.CommandText = "SELECT payload_json FROM ledger_events WHERE asset_id = @assetId";
            selectCmd.Parameters.AddWithValue("@assetId", assetId.ToString());
            currentPayload = (string)(await selectCmd.ExecuteScalarAsync())!;
        }

        // Parse and replace content hash using simple string manipulation
        // (In real attack, attacker would be more sophisticated)
        var hashPattern = "\"ContentHash\":\"";
        var startIdx = currentPayload.IndexOf(hashPattern) + hashPattern.Length;
        var endIdx = currentPayload.IndexOf("\"", startIdx);
        var newPayload = currentPayload[..startIdx] + fakeHash.ToString() + currentPayload[endIdx..];

        // Drop trigger, update, recreate
        using (var dropCmd = connection.CreateCommand())
        {
            dropCmd.CommandText = "DROP TRIGGER IF EXISTS trg_ledger_events_no_update";
            await dropCmd.ExecuteNonQueryAsync();
        }

        using (var updateCmd = connection.CreateCommand())
        {
            updateCmd.CommandText = "UPDATE ledger_events SET payload_json = @payload WHERE asset_id = @assetId";
            updateCmd.Parameters.AddWithValue("@payload", newPayload);
            updateCmd.Parameters.AddWithValue("@assetId", assetId.ToString());
            await updateCmd.ExecuteNonQueryAsync();
        }

        using (var createCmd = connection.CreateCommand())
        {
            createCmd.CommandText = """
                CREATE TRIGGER IF NOT EXISTS trg_ledger_events_no_update
                BEFORE UPDATE ON ledger_events
                BEGIN
                    SELECT RAISE(ABORT, 'ledger_events is append-only: UPDATE not allowed');
                END
                """;
            await createCmd.ExecuteNonQueryAsync();
        }
    }
}
