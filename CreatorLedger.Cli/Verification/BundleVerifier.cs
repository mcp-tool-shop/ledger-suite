using System.Text.Json;
using CreatorLedger.Application.Export;
using CreatorLedger.Application.Signing;
using Shared.Crypto;

namespace CreatorLedger.Cli.Verification;

/// <summary>
/// Standalone verifier for proof bundles.
/// Does not require database access - verifies using only the bundle contents.
/// </summary>
public sealed class BundleVerifier
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = false
    };

    /// <summary>
    /// Verifies a proof bundle from a JSON file.
    /// </summary>
    /// <param name="bundlePath">Path to the proof bundle JSON file.</param>
    /// <param name="assetPath">Optional path to the asset file to verify hash.</param>
    /// <returns>Verification result with details.</returns>
    public VerificationResult Verify(string bundlePath, string? assetPath = null)
    {
        var steps = new List<string>();
        var errors = new List<string>();

        // Step 1: Load and parse bundle
        steps.Add("Loading proof bundle...");

        ProofBundle bundle;
        try
        {
            var json = File.ReadAllText(bundlePath);
            bundle = JsonSerializer.Deserialize<ProofBundle>(json, JsonOptions)
                ?? throw new InvalidOperationException("Failed to deserialize proof bundle");
        }
        catch (FileNotFoundException)
        {
            return new VerificationResult
            {
                Status = VerificationStatus.InvalidInput,
                TrustLevel = "Error",
                Reason = $"Proof bundle file not found: {bundlePath}",
                AssetId = "unknown",
                Errors = [$"File not found: {bundlePath}"]
            };
        }
        catch (JsonException ex)
        {
            return new VerificationResult
            {
                Status = VerificationStatus.InvalidInput,
                TrustLevel = "Error",
                Reason = $"Invalid JSON in proof bundle: {ex.Message}",
                AssetId = "unknown",
                Errors = [$"JSON parse error: {ex.Message}"]
            };
        }

        steps.Add($"Bundle loaded: version={bundle.Version}, asset={bundle.AssetId}");

        // Step 2: Validate version and algorithms
        steps.Add("Checking version and algorithms...");

        if (bundle.Version != "proof.v1")
        {
            return new VerificationResult
            {
                Status = VerificationStatus.InvalidInput,
                TrustLevel = "Error",
                Reason = $"Unsupported bundle version: {bundle.Version}",
                AssetId = bundle.AssetId,
                Errors = [$"Expected version 'proof.v1', got '{bundle.Version}'"],
                Steps = steps
            };
        }

        if (!IsAlgorithmSupported(bundle.Algorithms))
        {
            return new VerificationResult
            {
                Status = VerificationStatus.InvalidInput,
                TrustLevel = "Error",
                Reason = "Unsupported cryptographic algorithms",
                AssetId = bundle.AssetId,
                Errors = [$"Unsupported algorithms: Signature={bundle.Algorithms.Signature}, Hash={bundle.Algorithms.Hash}"],
                Steps = steps
            };
        }

        steps.Add($"Algorithms supported: {bundle.Algorithms.Signature}, {bundle.Algorithms.Hash}");

        // Step 3: Find the primary attestation for this asset
        steps.Add("Locating attestations...");

        if (bundle.Attestations.Count == 0)
        {
            return new VerificationResult
            {
                Status = VerificationStatus.Broken,
                TrustLevel = "Broken",
                Reason = "No attestations found in bundle",
                AssetId = bundle.AssetId,
                Errors = ["Bundle contains no attestations"],
                Steps = steps
            };
        }

        // Find attestation for the target asset
        var primaryAttestation = bundle.Attestations
            .Where(a => a.AssetId == bundle.AssetId)
            .OrderByDescending(a => a.AttestedAtUtc)
            .FirstOrDefault();

        if (primaryAttestation is null)
        {
            return new VerificationResult
            {
                Status = VerificationStatus.Broken,
                TrustLevel = "Broken",
                Reason = $"No attestation found for asset {bundle.AssetId}",
                AssetId = bundle.AssetId,
                Errors = [$"Bundle does not contain attestation for asset {bundle.AssetId}"],
                Steps = steps
            };
        }

        steps.Add($"Found {bundle.Attestations.Count} attestation(s), primary: {primaryAttestation.EventType}");

        // Step 4: Verify all signatures
        steps.Add("Verifying signatures...");

        int signaturesValid = 0;
        int signaturesFailed = 0;

        foreach (var attestation in bundle.Attestations)
        {
            var sigResult = VerifyAttestationSignature(attestation, errors);
            if (sigResult)
            {
                signaturesValid++;
            }
            else
            {
                signaturesFailed++;
            }
        }

        steps.Add($"Signatures: {signaturesValid} valid, {signaturesFailed} failed");

        if (signaturesFailed > 0)
        {
            return new VerificationResult
            {
                Status = VerificationStatus.Broken,
                TrustLevel = "Broken",
                Reason = "Signature verification failed - content may have been tampered",
                AssetId = bundle.AssetId,
                AttestedContentHash = primaryAttestation.ContentHash,
                AttestationsVerified = bundle.Attestations.Count,
                SignaturesValid = signaturesValid,
                SignaturesFailed = signaturesFailed,
                Creator = GetCreatorInfo(primaryAttestation, bundle.Creators),
                AttestedAtUtc = primaryAttestation.AttestedAtUtc,
                Steps = steps,
                Errors = errors
            };
        }

        // Step 5: Verify asset hash if provided
        bool? hashMatches = null;
        string? computedHash = null;

        if (assetPath is not null)
        {
            steps.Add($"Computing hash of asset file: {assetPath}");

            try
            {
                var fileBytes = File.ReadAllBytes(assetPath);
                var computed = ContentHash.Compute(fileBytes);
                computedHash = computed.ToString();
                hashMatches = computedHash == primaryAttestation.ContentHash;

                steps.Add($"Computed hash: {computedHash[..16]}...");
                steps.Add($"Attested hash: {primaryAttestation.ContentHash[..Math.Min(16, primaryAttestation.ContentHash.Length)]}...");
                steps.Add($"Hash match: {hashMatches}");

                if (!hashMatches.Value)
                {
                    errors.Add("Content hash mismatch - asset has been modified");
                    return new VerificationResult
                    {
                        Status = VerificationStatus.Broken,
                        TrustLevel = "Broken",
                        Reason = "Content hash mismatch - asset has been modified since attestation",
                        AssetId = bundle.AssetId,
                        AttestedContentHash = primaryAttestation.ContentHash,
                        ComputedContentHash = computedHash,
                        HashMatches = false,
                        AttestationsVerified = bundle.Attestations.Count,
                        SignaturesValid = signaturesValid,
                        SignaturesFailed = signaturesFailed,
                        Creator = GetCreatorInfo(primaryAttestation, bundle.Creators),
                        AttestedAtUtc = primaryAttestation.AttestedAtUtc,
                        Steps = steps,
                        Errors = errors
                    };
                }
            }
            catch (FileNotFoundException)
            {
                return new VerificationResult
                {
                    Status = VerificationStatus.InvalidInput,
                    TrustLevel = "Error",
                    Reason = $"Asset file not found: {assetPath}",
                    AssetId = bundle.AssetId,
                    Errors = [$"Asset file not found: {assetPath}"],
                    Steps = steps
                };
            }
        }

        // Step 6: Determine trust level
        steps.Add("Determining trust level...");

        var trustLevel = DetermineTrustLevel(primaryAttestation, bundle.Anchor);
        var anchorInfo = bundle.Anchor is not null ? new AnchorInfo
        {
            ChainName = bundle.Anchor.ChainName,
            TransactionId = bundle.Anchor.TransactionId,
            BlockNumber = bundle.Anchor.BlockNumber,
            AnchoredAtUtc = bundle.Anchor.AnchoredAtUtc
        } : null;

        steps.Add($"Trust level: {trustLevel}");

        return new VerificationResult
        {
            Status = VerificationStatus.Verified,
            TrustLevel = trustLevel,
            Reason = GetSuccessReason(trustLevel, primaryAttestation, anchorInfo),
            AssetId = bundle.AssetId,
            AttestedContentHash = primaryAttestation.ContentHash,
            ComputedContentHash = computedHash,
            HashMatches = hashMatches,
            AttestationsVerified = bundle.Attestations.Count,
            SignaturesValid = signaturesValid,
            SignaturesFailed = signaturesFailed,
            Creator = GetCreatorInfo(primaryAttestation, bundle.Creators),
            AttestedAtUtc = primaryAttestation.AttestedAtUtc,
            Anchor = anchorInfo,
            Steps = steps,
            Errors = errors
        };
    }

    private static bool IsAlgorithmSupported(AlgorithmsInfo algorithms)
    {
        return algorithms.Signature == "Ed25519"
            && algorithms.Hash == "SHA-256"
            && algorithms.Encoding == "UTF-8";
    }

    private static bool VerifyAttestationSignature(AttestationProof attestation, List<string> errors)
    {
        try
        {
            // Parse public key
            if (string.IsNullOrEmpty(attestation.CreatorPublicKey))
            {
                errors.Add($"Missing public key for attestation {attestation.AttestationId}");
                return false;
            }

            var publicKey = Ed25519PublicKey.Parse(attestation.CreatorPublicKey);

            // Reconstruct the signable
            AttestationSignable signable;
            if (attestation.DerivedFromAssetId is not null)
            {
                // Derived attestation
                signable = SigningService.FromEvent(
                    attestation.AssetId,
                    attestation.ContentHash,
                    attestation.CreatorId,
                    attestation.CreatorPublicKey,
                    attestation.AttestedAtUtc,
                    attestation.DerivedFromAssetId,
                    attestation.DerivedFromAttestationId);
            }
            else
            {
                // Original attestation
                signable = SigningService.FromEvent(
                    attestation.AssetId,
                    attestation.ContentHash,
                    attestation.CreatorId,
                    attestation.CreatorPublicKey,
                    attestation.AttestedAtUtc);
            }

            // Parse signature
            var signature = Ed25519Signature.Parse(attestation.Signature);

            // Verify
            return SigningService.Verify(signable, signature, publicKey);
        }
        catch (Exception ex)
        {
            errors.Add($"Error verifying attestation {attestation.AttestationId}: {ex.Message}");
            return false;
        }
    }

    private static CreatorInfo? GetCreatorInfo(AttestationProof attestation, List<CreatorProof> creators)
    {
        var creator = creators.FirstOrDefault(c => c.CreatorId == attestation.CreatorId);

        return new CreatorInfo
        {
            CreatorId = attestation.CreatorId,
            PublicKey = attestation.CreatorPublicKey,
            DisplayName = creator?.DisplayName
        };
    }

    private static string DetermineTrustLevel(AttestationProof attestation, AnchorProof? anchor)
    {
        // Derived asset
        if (attestation.DerivedFromAssetId is not null)
        {
            return "Derived";
        }

        // Anchored
        if (anchor is not null && anchor.ChainName != "null")
        {
            return "Verified Original";
        }

        // Signed but not anchored
        return "Signed";
    }

    private static string GetSuccessReason(string trustLevel, AttestationProof attestation, AnchorInfo? anchor)
    {
        return trustLevel switch
        {
            "Verified Original" => $"Asset is signed and anchored to {anchor?.ChainName}",
            "Derived" => $"Asset is derived from {attestation.DerivedFromAssetId}",
            "Signed" => "Asset is cryptographically signed but not yet anchored to blockchain",
            _ => "Verification passed"
        };
    }
}
