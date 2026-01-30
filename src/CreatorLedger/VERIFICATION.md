# CreatorLedger Verification Specification

**Version**: 1.0
**Status**: Stable

This document defines how CreatorLedger proofs are created and verified.

## Cryptographic Primitives

| Primitive | Algorithm | Notes |
|-----------|-----------|-------|
| Signature | Ed25519 (RFC 8032) | 32-byte public key, 64-byte signature |
| Content Hash | SHA-256 | 32 bytes, lowercase hex |
| Event Hash | SHA-256 | Over canonical JSON |
| Encoding | UTF-8 | No BOM |

## Canonical JSON

All signed data uses deterministic JSON serialization:

- UTF-8 encoding, no BOM
- No whitespace (compact)
- Null values included explicitly
- Property order controlled by schema
- Numbers: strict (no leading zeros, no trailing decimals)
- Strings: minimal escaping (UnsafeRelaxedJsonEscaping)

## Attestation Signing

### Original Asset Attestation

Signable structure (`attestation.v1`):

```json
{
  "Version": "attestation.v1",
  "AssetId": "<guid-D-format>",
  "ContentHash": "<64-char-hex>",
  "CreatorId": "<guid-D-format>",
  "CreatorPublicKey": "<base64>",
  "AttestedAtUtc": "<ISO-8601-O-format>",
  "DerivedFromAssetId": null,
  "DerivedFromAttestationId": null
}
```

Signature = Ed25519.Sign(PrivateKey, CanonicalJSON(Signable))

### Derived Asset Attestation

Same structure with parent fields populated:

```json
{
  "Version": "attestation.v1",
  "AssetId": "<guid>",
  "ContentHash": "<hex>",
  "CreatorId": "<guid>",
  "CreatorPublicKey": "<base64>",
  "AttestedAtUtc": "<ISO-8601>",
  "DerivedFromAssetId": "<guid>",
  "DerivedFromAttestationId": "<guid-or-null>"
}
```

## Event Hashing

Each ledger event has a deterministic hash computed from `LedgerEventSignable`:

```json
{
  "Version": "event.v1",
  "EventId": "<guid-D-format>",
  "Seq": <integer>,
  "EventType": "<string>",
  "OccurredAtUtc": "<ISO-8601-O-format>",
  "PreviousEventHash": "<64-char-hex>",
  "PayloadJson": "<canonical-json-string>",
  "SignatureBase64": "<base64-or-null>",
  "CreatorPublicKey": "<ed25519:base64-or-null>"
}
```

EventHash = SHA-256(CanonicalJSON(LedgerEventSignable))

## Verification Algorithm

Given a ProofBundle, verify in this order:

### 1. Version Check
```
REQUIRE bundle.version == "proof.v1"
```

### 2. Algorithm Check
```
REQUIRE bundle.algorithms.signature == "Ed25519"
REQUIRE bundle.algorithms.hash == "SHA-256"
REQUIRE bundle.algorithms.encoding == "UTF-8"
```

### 3. Locate Attestation
```
attestation = bundle.attestations
  .filter(a => a.assetId == bundle.assetId)
  .sortByDescending(a => a.attestedAtUtc)
  .first()

REQUIRE attestation != null
```

### 4. Signature Verification

For each attestation:

```
publicKey = Ed25519.ParsePublicKey(attestation.creatorPublicKey)

signable = {
  Version: "attestation.v1",
  AssetId: attestation.assetId,
  ContentHash: attestation.contentHash,
  CreatorId: attestation.creatorId,
  CreatorPublicKey: attestation.creatorPublicKey,
  AttestedAtUtc: attestation.attestedAtUtc,
  DerivedFromAssetId: attestation.derivedFromAssetId,
  DerivedFromAttestationId: attestation.derivedFromAttestationId
}

signatureBytes = Base64.Decode(attestation.signature)
dataBytes = UTF8.Encode(CanonicalJSON(signable))

REQUIRE Ed25519.Verify(publicKey, dataBytes, signatureBytes) == true
```

### 5. Content Hash Verification (if asset provided)

```
computedHash = SHA-256(assetFileBytes).ToLowerHex()
REQUIRE computedHash == attestation.contentHash
```

### 6. Trust Level Determination

```
IF any signature failed:
  RETURN Broken

IF content hash provided AND mismatched:
  RETURN Broken

IF attestation.derivedFromAssetId != null:
  RETURN Derived

IF bundle.anchor != null AND anchor.chainName != "null":
  RETURN VerifiedOriginal

RETURN Signed
```

## Trust Levels

| Level | Signature | Hash | Anchor | Derivation |
|-------|-----------|------|--------|------------|
| Verified Original | ✅ Valid | ✅ Match | ✅ Present | ❌ None |
| Signed | ✅ Valid | ✅ Match | ❌ None | ❌ None |
| Derived | ✅ Valid | ✅ Match | Any | ✅ Has parent |
| Unverified | N/A | N/A | N/A | N/A |
| Broken | ❌ Invalid | ❌ Mismatch | Any | Any |

## Threat Model

### What CreatorLedger Detects

- ✅ Content modification after attestation
- ✅ Signature forgery (without private key)
- ✅ Attestation tampering (payload modification)
- ✅ Event chain manipulation (reordering, deletion)
- ✅ Creator impersonation (wrong key)

### What CreatorLedger Does NOT Detect

- ❌ Original creator lying about authorship
- ❌ Private key compromise
- ❌ Attestation before blockchain anchor (timestamps are self-reported until anchored)
- ❌ Content created by AI vs human

### Security Assumptions

1. Ed25519 is cryptographically secure
2. SHA-256 is collision-resistant
3. Private keys are kept secret
4. Blockchain anchors are immutable once confirmed

## Proof Bundle Schema

```typescript
interface ProofBundle {
  version: "proof.v1";
  algorithms: {
    signature: "Ed25519";
    hash: "SHA-256";
    encoding: "UTF-8";
  };
  exportedAtUtc: string;  // ISO 8601
  assetId: string;        // GUID
  attestations: AttestationProof[];
  creators: CreatorProof[];
  anchor: AnchorProof | null;
  ledgerTipHash: string;  // 64-char hex
}

interface AttestationProof {
  attestationId: string;
  assetId: string;
  contentHash: string;
  creatorId: string;
  creatorPublicKey: string;
  attestedAtUtc: string;
  signature: string;      // Base64
  eventType: string;
  derivedFromAssetId?: string;
  derivedFromAttestationId?: string;
}

interface CreatorProof {
  creatorId: string;
  publicKey: string;
  displayName?: string;
}

interface AnchorProof {
  chainName: string;
  transactionId: string;
  ledgerRootHash: string;
  blockNumber?: number;
  anchoredAtUtc: string;
}
```

## Versioning

- `proof.v1`: Current version
- `attestation.v1`: Current signing format
- `event.v1`: Current event hash format

Breaking changes require new version numbers. Verifiers MUST reject unknown versions.
