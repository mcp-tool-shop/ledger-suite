using System.Text.Json;
using CreatorLedger.Application.Attestation;
using CreatorLedger.Application.Export;
using CreatorLedger.Application.Identity;
using CreatorLedger.Domain.Primitives;
using CreatorLedger.Tests.Fakes;
using Shared.Crypto;

namespace CreatorLedger.Tests.Samples;

/// <summary>
/// Generates sample proof bundles for documentation.
/// Run with: dotnet test --filter "FullyQualifiedName~GenerateSampleBundle"
/// </summary>
public class SampleGenerator
{
    [Fact]
    public async Task GenerateSampleBundle()
    {
        // Arrange
        var ledgerRepo = new InMemoryLedgerRepository();
        var identityRepo = new InMemoryCreatorIdentityRepository();
        var keyVault = new InMemoryKeyVault();
        var clock = new FakeClock();

        var createIdentityHandler = new CreateIdentityHandler(keyVault, identityRepo, ledgerRepo, clock);
        var attestHandler = new AttestAssetHandler(keyVault, identityRepo, ledgerRepo, clock);
        var exportHandler = new ExportProofBundleHandler(ledgerRepo, identityRepo, clock);

        // Create identity
        var identity = await createIdentityHandler.HandleAsync(new CreateIdentityCommand("Demo Artist"));

        // Create attestation with known hash
        var assetId = AssetId.New();
        var contentHash = ContentHash.Parse("0f70612ea7528c7383ae17cd9d56d4c4836635ee134ee9d86ee50b6a7c6eb006");

        await attestHandler.HandleAsync(new AttestAssetCommand(assetId, contentHash, identity.CreatorId));

        // Export bundle
        var bundle = await exportHandler.HandleAsync(new ExportProofBundleCommand(assetId));

        // Output to console (captured by test output)
        var json = JsonSerializer.Serialize(bundle, new JsonSerializerOptions { WriteIndented = true });

        // Write to samples directory
        var samplesDir = Path.Combine(
            Directory.GetCurrentDirectory(),
            "..", "..", "..", "..", "samples");

        if (Directory.Exists(samplesDir))
        {
            var bundlePath = Path.Combine(samplesDir, "sample-bundle.json");
            await File.WriteAllTextAsync(bundlePath, json);
        }

        // Assert bundle is valid
        Assert.Equal("proof.v1", bundle.Version);
        Assert.Single(bundle.Attestations);
        Assert.Equal(contentHash.ToString(), bundle.Attestations[0].ContentHash);
    }
}
