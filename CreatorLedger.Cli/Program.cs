using System.CommandLine;
using System.Text.Json;
using CreatorLedger.Cli.Verification;

namespace CreatorLedger.Cli;

/// <summary>
/// CreatorLedger CLI - Standalone proof bundle verification.
/// </summary>
public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        var rootCommand = new RootCommand("CreatorLedger - Cryptographic provenance verification");

        // verify command
        var verifyCommand = CreateVerifyCommand();
        rootCommand.AddCommand(verifyCommand);

        // inspect command
        var inspectCommand = CreateInspectCommand();
        rootCommand.AddCommand(inspectCommand);

        return await rootCommand.InvokeAsync(args);
    }

    private static Command CreateVerifyCommand()
    {
        var bundleArg = new Argument<FileInfo>("proof", "Path to the proof bundle JSON file");
        var assetOption = new Option<FileInfo?>("--asset", "Path to the asset file to verify hash");
        assetOption.AddAlias("-a");
        var verboseOption = new Option<bool>("--verbose", "Show detailed verification steps");
        verboseOption.AddAlias("-v");
        var jsonOption = new Option<bool>("--json", "Output result as JSON");

        var command = new Command("verify", "Verify a proof bundle")
        {
            bundleArg,
            assetOption,
            verboseOption,
            jsonOption
        };

        command.SetHandler(HandleVerify, bundleArg, assetOption, verboseOption, jsonOption);
        return command;
    }

    private static Command CreateInspectCommand()
    {
        var bundleArg = new Argument<FileInfo>("proof", "Path to the proof bundle JSON file");
        var jsonOption = new Option<bool>("--json", "Output result as JSON");

        var command = new Command("inspect", "Inspect a proof bundle structure")
        {
            bundleArg,
            jsonOption
        };

        command.SetHandler(HandleInspect, bundleArg, jsonOption);
        return command;
    }

    private static Task<int> HandleVerify(FileInfo bundleFile, FileInfo? assetFile, bool verbose, bool json)
    {
        var verifier = new BundleVerifier();
        var result = verifier.Verify(bundleFile.FullName, assetFile?.FullName);

        if (json)
        {
            OutputJson(result);
        }
        else
        {
            OutputHuman(result, verbose);
        }

        return Task.FromResult((int)result.Status);
    }

    private static Task<int> HandleInspect(FileInfo bundleFile, bool json)
    {
        var inspector = new BundleInspector();
        var result = inspector.Inspect(bundleFile.FullName, out var error);

        if (result is null)
        {
            if (json)
            {
                Console.WriteLine(JsonSerializer.Serialize(new { error }, JsonOutputOptions));
            }
            else
            {
                Console.Error.WriteLine($"Error: {error}");
            }
            return Task.FromResult((int)VerificationStatus.InvalidInput);
        }

        if (json)
        {
            Console.WriteLine(JsonSerializer.Serialize(result, JsonOutputOptions));
        }
        else
        {
            OutputInspection(result);
        }

        return Task.FromResult(0);
    }

    private static readonly JsonSerializerOptions JsonOutputOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    private static void OutputJson(VerificationResult result)
    {
        var output = new
        {
            status = result.Status.ToString(),
            exitCode = (int)result.Status,
            trustLevel = result.TrustLevel,
            reason = result.Reason,
            assetId = result.AssetId,
            attestedContentHash = result.AttestedContentHash,
            computedContentHash = result.ComputedContentHash,
            hashMatches = result.HashMatches,
            attestationsVerified = result.AttestationsVerified,
            signaturesValid = result.SignaturesValid,
            signaturesFailed = result.SignaturesFailed,
            creator = result.Creator is not null ? new
            {
                creatorId = result.Creator.CreatorId,
                publicKey = result.Creator.PublicKey,
                displayName = result.Creator.DisplayName
            } : null,
            attestedAtUtc = result.AttestedAtUtc,
            anchor = result.Anchor is not null ? new
            {
                chainName = result.Anchor.ChainName,
                transactionId = result.Anchor.TransactionId,
                blockNumber = result.Anchor.BlockNumber,
                anchoredAtUtc = result.Anchor.AnchoredAtUtc
            } : null,
            errors = result.Errors
        };

        Console.WriteLine(JsonSerializer.Serialize(output, JsonOutputOptions));
    }

    private static void OutputHuman(VerificationResult result, bool verbose)
    {
        // Status line with symbol
        var symbol = result.Status == VerificationStatus.Verified ? "✔" : "✘";
        var color = result.Status == VerificationStatus.Verified ? ConsoleColor.Green : ConsoleColor.Red;

        WriteColored($"{symbol} {result.TrustLevel}", color);
        Console.WriteLine();

        // Details
        Console.WriteLine($"  Asset:      {result.AssetId}");

        if (result.Creator is not null)
        {
            var displayName = result.Creator.DisplayName ?? "(no name)";
            Console.WriteLine($"  Creator:    {displayName} ({result.Creator.ShortPublicKey})");
        }

        if (result.AttestedAtUtc is not null)
        {
            Console.WriteLine($"  Attested:   {result.AttestedAtUtc}");
        }

        if (result.HashMatches.HasValue)
        {
            var hashSymbol = result.HashMatches.Value ? "✔" : "✘";
            var hashColor = result.HashMatches.Value ? ConsoleColor.Green : ConsoleColor.Red;
            Console.Write($"  Hash:       SHA-256 ");
            WriteColored(result.HashMatches.Value ? $"{hashSymbol} match" : $"{hashSymbol} MISMATCH", hashColor);
            Console.WriteLine();
        }

        if (result.SignaturesValid > 0 || result.SignaturesFailed > 0)
        {
            var sigSymbol = result.SignaturesFailed == 0 ? "✔" : "✘";
            var sigColor = result.SignaturesFailed == 0 ? ConsoleColor.Green : ConsoleColor.Red;
            Console.Write($"  Signature:  Ed25519 ");
            WriteColored($"{sigSymbol} {result.SignaturesValid} valid", sigColor);
            if (result.SignaturesFailed > 0)
            {
                WriteColored($", {result.SignaturesFailed} failed", ConsoleColor.Red);
            }
            Console.WriteLine();
        }

        if (result.Anchor is not null)
        {
            Console.Write($"  Anchored:   {result.Anchor.ChainName} tx ");
            var shortTx = result.Anchor.TransactionId.Length > 16
                ? result.Anchor.TransactionId[..16] + "..."
                : result.Anchor.TransactionId;
            Console.WriteLine(shortTx);
            if (result.Anchor.BlockNumber.HasValue)
            {
                Console.WriteLine($"              block {result.Anchor.BlockNumber}");
            }
        }

        // Reason
        Console.WriteLine();
        Console.WriteLine($"  {result.Reason}");

        // Verbose: show steps
        if (verbose && result.Steps.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine("  Verification steps:");
            foreach (var step in result.Steps)
            {
                Console.WriteLine($"    - {step}");
            }
        }

        // Errors
        if (result.Errors.Count > 0)
        {
            Console.WriteLine();
            WriteColored("  Errors:", ConsoleColor.Red);
            Console.WriteLine();
            foreach (var error in result.Errors)
            {
                Console.WriteLine($"    - {error}");
            }
        }
    }

    private static void OutputInspection(InspectionResult result)
    {
        Console.WriteLine($"Proof Bundle: {result.Version}");
        Console.WriteLine($"  Asset:       {result.AssetId}");
        Console.WriteLine($"  Exported:    {result.ExportedAtUtc}");
        Console.WriteLine($"  Ledger Tip:  {result.LedgerTipHash[..16]}...");
        Console.WriteLine($"  Algorithms:  {result.Algorithms.Signature}, {result.Algorithms.Hash}, {result.Algorithms.Encoding}");
        Console.WriteLine();

        Console.WriteLine($"Attestations: {result.AttestationCount}");
        foreach (var att in result.Attestations)
        {
            var derivedInfo = att.DerivedFromAssetId is not null ? $" (derived from {att.DerivedFromAssetId[..8]}...)" : "";
            Console.WriteLine($"  - {att.EventType}: {att.AssetId[..8]}... at {att.AttestedAtUtc}{derivedInfo}");
        }
        Console.WriteLine();

        Console.WriteLine($"Creators: {result.CreatorCount}");
        foreach (var creator in result.Creators)
        {
            var name = creator.DisplayName ?? "(no name)";
            Console.WriteLine($"  - {name}: {creator.PublicKeyShort}");
        }
        Console.WriteLine();

        if (result.Anchor is not null)
        {
            Console.WriteLine($"Anchor: {result.Anchor.ChainName}");
            Console.WriteLine($"  Transaction: {result.Anchor.TransactionId}");
            if (result.Anchor.BlockNumber.HasValue)
            {
                Console.WriteLine($"  Block:       {result.Anchor.BlockNumber}");
            }
            Console.WriteLine($"  Anchored:    {result.Anchor.AnchoredAtUtc}");
        }
        else
        {
            Console.WriteLine("Anchor: none");
        }
    }

    private static void WriteColored(string text, ConsoleColor color)
    {
        var original = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.Write(text);
        Console.ForegroundColor = original;
    }
}
