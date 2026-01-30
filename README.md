# ledger-suite

Unified monorepo for cryptographic provenance ledgers.

## Projects

| Project | Description | Tests |
|---------|-------------|-------|
| `src/ClaimLedger/` | Scientific claim provenance and verification | 371 |
| `src/CreatorLedger/` | Creator attestation proofs | 219 |
| `src/CreatorLedger/Shared.Crypto/` | Shared Ed25519 cryptography primitives | - |

## Quick Start

```bash
# Clone
git clone https://github.com/mcp-tool-shop/ledger-suite.git
cd ledger-suite

# Build all
dotnet build ledger-suite.sln

# Test all
dotnet test ledger-suite.sln

# Run ClaimLedger CLI
dotnet run --project src/ClaimLedger/ClaimLedger.Cli -- --help

# Run CreatorLedger CLI
dotnet run --project src/CreatorLedger/CreatorLedger.Cli -- --help
```

## Structure

```
ledger-suite/
├── ledger-suite.sln          # Root solution
├── src/
│   ├── ClaimLedger/          # Scientific claims
│   │   ├── ClaimLedger.Domain/
│   │   ├── ClaimLedger.Application/
│   │   ├── ClaimLedger.Infrastructure/
│   │   ├── ClaimLedger.Cli/
│   │   └── ClaimLedger.Tests/
│   └── CreatorLedger/        # Creator proofs
│       ├── CreatorLedger.Domain/
│       ├── CreatorLedger.Application/
│       ├── CreatorLedger.Infrastructure/
│       ├── CreatorLedger.Cli/
│       ├── CreatorLedger.Tests/
│       └── Shared.Crypto/    # Shared crypto
└── docs/                     # Documentation
```

## ClaimLedger Features

- **Claim assertion** with Ed25519 signatures
- **Citations** linking claims with cryptographic proof
- **Attestations** (peer review, reproduction, institutional approval)
- **Revocations** with witness countersignatures
- **RFC 3161 timestamps** for non-repudiation
- **ClaimPacks** for distribution-ready bundles
- **Local registry** for offline citation resolution
- **Publish command** for one-click distribution

## CreatorLedger Features

- **Creator attestation proofs** for digital assets
- **Content hash verification**
- **Multi-party attestation chains**
- **Proof bundles** for portable verification

## License

MIT
