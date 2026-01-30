// Run with: dotnet script samples/GenerateSample.cs
// Or integrated into test to generate sample bundle

using System.Text.Json;
using CreatorLedger.Application.Export;
using CreatorLedger.Application.Identity;
using CreatorLedger.Application.Attestation;
using CreatorLedger.Domain.Primitives;
using CreatorLedger.Tests.Fakes;
using Shared.Crypto;

// This script generates a valid sample proof bundle for documentation

var ledgerRepo = new InMemoryLedgerRepository();
var identityRepo = new InMemoryCreatorIdentityRepository();
var keyVault = new InMemoryKeyVault();
var clock = new FakeClock();

// Create identity
var createIdentityHandler = new CreateIdentityHandler(keyVault, identityRepo, ledgerRepo, clock);
var identity = await createIdentityHandler.HandleAsync(new CreateIdentityCommand("Demo Artist"));

// Create attestation
var assetId = AssetId.New();
var contentHash = ContentHash.Parse("0f70612ea7528c7383ae17cd9d56d4c4836635ee134ee9d86ee50b6a7c6eb006");

var attestHandler = new AttestAssetHandler(keyVault, identityRepo, ledgerRepo, clock);
await attestHandler.HandleAsync(new AttestAssetCommand(assetId, contentHash, identity.CreatorId));

// Export bundle
var exportHandler = new ExportProofBundleHandler(ledgerRepo, identityRepo, clock);
var bundle = await exportHandler.HandleAsync(new ExportProofBundleCommand(assetId));

// Output
var json = JsonSerializer.Serialize(bundle, new JsonSerializerOptions { WriteIndented = true });
Console.WriteLine(json);
