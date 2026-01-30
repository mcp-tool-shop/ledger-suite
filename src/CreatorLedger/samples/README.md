# Sample Files

This directory contains example files for testing CreatorLedger verification.

## Files

| File | Description |
|------|-------------|
| `sample-artwork.txt` | A sample digital asset (text file) |
| `sample-bundle.json` | Proof bundle for the sample artwork |

## Verification

You can verify the sample using the CLI:

```bash
# Verify the proof bundle
creatorledger verify sample-bundle.json

# Verify with hash check
creatorledger verify sample-bundle.json --asset sample-artwork.txt

# Inspect bundle structure
creatorledger inspect sample-bundle.json
```

## Expected Output

```
✔ Signed
  Asset:      badfa3fb-3297-4a1e-9135-312d003fa79d
  Creator:    Demo Artist (ed25519:QusN...)
  Attested:   2024-06-15T12:00:00.0000000Z
  Hash:       SHA-256 ✔ match
  Signature:  Ed25519 ✔ 1 valid

  Asset is cryptographically signed but not yet anchored to blockchain
```

## Test Tampering Detection

Try modifying `sample-artwork.txt` and re-running verification:

```bash
echo "tampered" >> sample-artwork.txt
creatorledger verify sample-bundle.json --asset sample-artwork.txt
```

Expected: `✗ Broken` with "Content hash mismatch" error.

## Regenerating Samples

To regenerate the sample bundle (after modifying the artwork):

```bash
dotnet test --filter "FullyQualifiedName~GenerateSampleBundle"
```

Note: The sample bundle is generated with deterministic test keys. In production,
bundles are created with DPAPI-protected private keys.
