using CreatorLedger.Application.Primitives;
using CreatorLedger.Domain.Identity;
using CreatorLedger.Domain.Ledger;
using CreatorLedger.Domain.Ledger.Events;
using CreatorLedger.Domain.Primitives;
using Shared.Crypto;

namespace CreatorLedger.Application.Export;

/// <summary>
/// Command to export a proof bundle for an asset.
/// </summary>
public sealed record ExportProofBundleCommand(AssetId AssetId);

/// <summary>
/// Handler for exporting proof bundles.
/// </summary>
public sealed class ExportProofBundleHandler
{
    private readonly ILedgerRepository _ledgerRepository;
    private readonly ICreatorIdentityRepository _identityRepository;
    private readonly IClock _clock;

    public ExportProofBundleHandler(
        ILedgerRepository ledgerRepository,
        ICreatorIdentityRepository identityRepository,
        IClock clock)
    {
        _ledgerRepository = ledgerRepository;
        _identityRepository = identityRepository;
        _clock = clock;
    }

    public async Task<ProofBundle> HandleAsync(
        ExportProofBundleCommand command,
        CancellationToken cancellationToken = default)
    {
        // Get all events for this asset
        var events = await _ledgerRepository.GetEventsForAssetAsync(
            command.AssetId, cancellationToken);

        if (events.Count == 0)
            throw NotFoundException.ForAsset(command.AssetId.ToString());

        // Load creator identities first (needed for attestation proofs)
        var creatorIds = new HashSet<CreatorId>();
        CollectCreatorIds(events, creatorIds);

        var creatorMap = new Dictionary<CreatorId, CreatorIdentity>();
        foreach (var creatorId in creatorIds)
        {
            var identity = await _identityRepository.GetAsync(creatorId, cancellationToken);
            if (identity is not null)
            {
                creatorMap[creatorId] = identity;
            }
        }

        // Collect attestation events and their parent chains
        var attestationProofs = new List<AttestationProof>();
        var processedAssets = new HashSet<AssetId>();

        await CollectAttestationsRecursiveAsync(
            command.AssetId,
            attestationProofs,
            creatorIds,
            creatorMap,
            processedAssets,
            cancellationToken);

        // Build creator proofs
        var creatorProofs = creatorMap.Values.Select(identity => new CreatorProof
        {
            CreatorId = identity.Id.ToString(),
            PublicKey = identity.PublicKey.ToString(),
            DisplayName = identity.DisplayName
        }).ToList();

        // Look for any applicable anchor (simplified for now)
        var anchor = await FindApplicableAnchorAsync(cancellationToken);

        // Get ledger tip hash for chain integrity verification
        var ledgerTipHash = await _ledgerRepository.GetLedgerTipAsync(cancellationToken);

        return new ProofBundle
        {
            ExportedAtUtc = CanonicalJson.FormatTimestamp(_clock.UtcNow),
            AssetId = command.AssetId.ToString(),
            Attestations = attestationProofs,
            Creators = creatorProofs,
            Anchor = anchor,
            LedgerTipHash = ledgerTipHash.ToString()
        };
    }

    private static void CollectCreatorIds(IReadOnlyList<LedgerEvent> events, HashSet<CreatorId> creatorIds)
    {
        foreach (var evt in events)
        {
            switch (evt)
            {
                case AssetAttestedEvent e:
                    creatorIds.Add(e.CreatorId);
                    break;
                case AssetDerivedEvent e:
                    creatorIds.Add(e.CreatorId);
                    break;
            }
        }
    }

    private async Task CollectAttestationsRecursiveAsync(
        AssetId assetId,
        List<AttestationProof> attestations,
        HashSet<CreatorId> creatorIds,
        Dictionary<CreatorId, CreatorIdentity> creatorMap,
        HashSet<AssetId> processedAssets,
        CancellationToken cancellationToken)
    {
        if (!processedAssets.Add(assetId))
            return; // Already processed, avoid cycles

        var events = await _ledgerRepository.GetEventsForAssetAsync(assetId, cancellationToken);

        // Collect any new creator IDs from these events
        foreach (var evt in events)
        {
            CreatorId? newCreatorId = evt switch
            {
                AssetAttestedEvent e => e.CreatorId,
                AssetDerivedEvent e => e.CreatorId,
                _ => null
            };

            if (newCreatorId.HasValue && creatorIds.Add(newCreatorId.Value))
            {
                var identity = await _identityRepository.GetAsync(newCreatorId.Value, cancellationToken);
                if (identity is not null)
                {
                    creatorMap[newCreatorId.Value] = identity;
                }
            }
        }

        foreach (var evt in events)
        {
            switch (evt)
            {
                case AssetAttestedEvent e:
                    var creatorPubKey = creatorMap.TryGetValue(e.CreatorId, out var creator)
                        ? creator.PublicKey.ToString()
                        : string.Empty;
                    attestations.Add(CreateAttestationProof(e, creatorPubKey));
                    break;

                case AssetDerivedEvent e:
                    var derivedCreatorPubKey = creatorMap.TryGetValue(e.CreatorId, out var derivedCreator)
                        ? derivedCreator.PublicKey.ToString()
                        : string.Empty;
                    attestations.Add(CreateDerivedProof(e, derivedCreatorPubKey));

                    // Recursively collect parent chain
                    await CollectAttestationsRecursiveAsync(
                        e.ParentAssetId,
                        attestations,
                        creatorIds,
                        creatorMap,
                        processedAssets,
                        cancellationToken);
                    break;
            }
        }
    }

    private static AttestationProof CreateAttestationProof(AssetAttestedEvent e, string creatorPublicKey)
    {
        return new AttestationProof
        {
            AttestationId = e.AttestationId.ToString(),
            AssetId = e.AssetId.ToString(),
            ContentHash = e.ContentHash.ToString(),
            CreatorId = e.CreatorId.ToString(),
            CreatorPublicKey = creatorPublicKey,
            AttestedAtUtc = CanonicalJson.FormatTimestamp(e.OccurredAtUtc),
            Signature = e.Signature.ToString(),
            EventType = AssetAttestedEvent.TypeName
        };
    }

    private static AttestationProof CreateDerivedProof(AssetDerivedEvent e, string creatorPublicKey)
    {
        return new AttestationProof
        {
            AttestationId = e.AttestationId.ToString(),
            AssetId = e.AssetId.ToString(),
            ContentHash = e.ContentHash.ToString(),
            CreatorId = e.CreatorId.ToString(),
            CreatorPublicKey = creatorPublicKey,
            AttestedAtUtc = CanonicalJson.FormatTimestamp(e.OccurredAtUtc),
            Signature = e.Signature.ToString(),
            DerivedFromAssetId = e.ParentAssetId.ToString(),
            DerivedFromAttestationId = e.ParentAttestationId?.ToString(),
            EventType = AssetDerivedEvent.TypeName
        };
    }

    private async Task<AnchorProof?> FindApplicableAnchorAsync(
        CancellationToken cancellationToken)
    {
        // Placeholder: real implementation would find the most recent anchor
        // that includes the attestation in its ledger root
        return null;
    }
}
