using CreatorLedger.Application.Signing;
using CreatorLedger.Domain.Identity;
using CreatorLedger.Domain.Ledger;
using CreatorLedger.Domain.Ledger.Events;
using CreatorLedger.Domain.Primitives;
using CreatorLedger.Domain.Trust;
using Shared.Crypto;

namespace CreatorLedger.Application.Verification;

/// <summary>
/// Query to verify an asset's trust level.
/// </summary>
public sealed record VerifyAssetQuery(
    AssetId AssetId,
    ContentHash CurrentContentHash);

/// <summary>
/// Handler for verifying an asset's trust level.
/// </summary>
public sealed class VerifyAssetHandler
{
    private readonly ILedgerRepository _ledgerRepository;
    private readonly ICreatorIdentityRepository _identityRepository;

    public VerifyAssetHandler(
        ILedgerRepository ledgerRepository,
        ICreatorIdentityRepository identityRepository)
    {
        _ledgerRepository = ledgerRepository;
        _identityRepository = identityRepository;
    }

    public async Task<VerificationReport> HandleAsync(
        VerifyAssetQuery query,
        CancellationToken cancellationToken = default)
    {
        // Get all events for this asset
        var events = await _ledgerRepository.GetEventsForAssetAsync(
            query.AssetId, cancellationToken);

        // No events = unverified
        if (events.Count == 0)
        {
            return new VerificationReport
            {
                TrustLevel = TrustLevel.Unverified,
                Reason = "No attestation found for this asset",
                AssetId = query.AssetId,
                CurrentContentHash = query.CurrentContentHash
            };
        }

        // Find the most recent attestation event
        var attestationEvent = events
            .OfType<AssetAttestedEvent>()
            .OrderByDescending(e => e.OccurredAtUtc)
            .FirstOrDefault();

        var derivedEvent = events
            .OfType<AssetDerivedEvent>()
            .OrderByDescending(e => e.OccurredAtUtc)
            .FirstOrDefault();

        // Use whichever is more recent
        var latestEvent = GetLatestAttestationOrDerived(attestationEvent, derivedEvent);

        if (latestEvent is null)
        {
            return new VerificationReport
            {
                TrustLevel = TrustLevel.Unverified,
                Reason = "No attestation or derivation event found",
                AssetId = query.AssetId,
                CurrentContentHash = query.CurrentContentHash
            };
        }

        // Extract common fields
        var (contentHash, creatorId, signature, attestationId, parentAssetId) = ExtractEventData(latestEvent);

        // Check if hash matches
        bool hashMatches = query.CurrentContentHash == contentHash;

        if (!hashMatches)
        {
            return new VerificationReport
            {
                TrustLevel = TrustLevel.Broken,
                Reason = "Content hash does not match the attested hash. The asset has been modified.",
                AssetId = query.AssetId,
                CurrentContentHash = query.CurrentContentHash,
                AttestedContentHash = contentHash,
                CreatorId = creatorId,
                AttestationId = attestationId,
                HashMatches = false
            };
        }

        // Load creator identity to verify signature
        var identity = await _identityRepository.GetAsync(creatorId, cancellationToken);

        if (identity is null)
        {
            return new VerificationReport
            {
                TrustLevel = TrustLevel.Unverified,
                Reason = "Creator identity not found. Cannot verify signature.",
                AssetId = query.AssetId,
                CurrentContentHash = query.CurrentContentHash,
                AttestedContentHash = contentHash,
                CreatorId = creatorId,
                AttestationId = attestationId,
                HashMatches = true,
                SignatureValid = null
            };
        }

        // Reconstruct signable and verify signature
        var signable = ReconstructSignable(latestEvent, identity.PublicKey);
        bool signatureValid = SigningService.Verify(signable, signature, identity.PublicKey);

        if (!signatureValid)
        {
            return new VerificationReport
            {
                TrustLevel = TrustLevel.Broken,
                Reason = "Signature verification failed. The attestation may have been tampered with.",
                AssetId = query.AssetId,
                CurrentContentHash = query.CurrentContentHash,
                AttestedContentHash = contentHash,
                CreatorId = creatorId,
                AttestationId = attestationId,
                HashMatches = true,
                SignatureValid = false
            };
        }

        // Check for derivation
        if (parentAssetId.HasValue)
        {
            // Verify parent chain
            var parentValid = await VerifyParentChainAsync(
                parentAssetId.Value, cancellationToken);

            return new VerificationReport
            {
                TrustLevel = parentValid ? TrustLevel.Derived : TrustLevel.Broken,
                Reason = parentValid
                    ? "Asset is derived from a valid parent asset"
                    : "Parent asset chain is invalid",
                AssetId = query.AssetId,
                CurrentContentHash = query.CurrentContentHash,
                AttestedContentHash = contentHash,
                CreatorId = creatorId,
                AttestationId = attestationId,
                HashMatches = true,
                SignatureValid = true,
                ParentAssetId = parentAssetId,
                ParentChainValid = parentValid
            };
        }

        // Check for anchoring (look for any anchor event in the ledger)
        var anchorEvent = await FindAnchorForAssetAsync(attestationId, cancellationToken);

        if (anchorEvent is not null)
        {
            return new VerificationReport
            {
                TrustLevel = TrustLevel.VerifiedOriginal,
                Reason = $"Asset is signed and anchored to {anchorEvent.ChainName}",
                AssetId = query.AssetId,
                CurrentContentHash = query.CurrentContentHash,
                AttestedContentHash = contentHash,
                CreatorId = creatorId,
                AttestationId = attestationId,
                HashMatches = true,
                SignatureValid = true,
                IsAnchored = true,
                AnchorInfo = $"{anchorEvent.ChainName}:{anchorEvent.TransactionId}"
            };
        }

        // Valid signature, hash matches, but not anchored
        return new VerificationReport
        {
            TrustLevel = TrustLevel.Signed,
            Reason = "Asset is signed locally but not yet anchored to blockchain",
            AssetId = query.AssetId,
            CurrentContentHash = query.CurrentContentHash,
            AttestedContentHash = contentHash,
            CreatorId = creatorId,
            AttestationId = attestationId,
            HashMatches = true,
            SignatureValid = true,
            IsAnchored = false
        };
    }

    private static LedgerEvent? GetLatestAttestationOrDerived(
        AssetAttestedEvent? attested,
        AssetDerivedEvent? derived)
    {
        if (attested is null) return derived;
        if (derived is null) return attested;
        return attested.OccurredAtUtc > derived.OccurredAtUtc ? attested : derived;
    }

    private static (ContentHash, CreatorId, Ed25519Signature, AttestationId, AssetId?) ExtractEventData(
        LedgerEvent evt)
    {
        return evt switch
        {
            AssetAttestedEvent e => (e.ContentHash, e.CreatorId, e.Signature, e.AttestationId, null),
            AssetDerivedEvent e => (e.ContentHash, e.CreatorId, e.Signature, e.AttestationId, e.ParentAssetId),
            _ => throw new InvalidOperationException($"Unexpected event type: {evt.GetType().Name}")
        };
    }

    private static AttestationSignable ReconstructSignable(LedgerEvent evt, Ed25519PublicKey creatorPublicKey)
    {
        return evt switch
        {
            AssetAttestedEvent e => SigningService.FromEvent(
                e.AssetId.ToString(),
                e.ContentHash.ToString(),
                e.CreatorId.ToString(),
                creatorPublicKey.ToString(),
                CanonicalJson.FormatTimestamp(e.OccurredAtUtc)),

            AssetDerivedEvent e => SigningService.FromEvent(
                e.AssetId.ToString(),
                e.ContentHash.ToString(),
                e.CreatorId.ToString(),
                creatorPublicKey.ToString(),
                CanonicalJson.FormatTimestamp(e.OccurredAtUtc),
                e.ParentAssetId.ToString(),
                e.ParentAttestationId?.ToString()),

            _ => throw new InvalidOperationException($"Unexpected event type: {evt.GetType().Name}")
        };
    }

    private async Task<bool> VerifyParentChainAsync(
        AssetId parentAssetId,
        CancellationToken cancellationToken)
    {
        // Simple check: parent has at least one valid attestation event
        var parentEvents = await _ledgerRepository.GetEventsForAssetAsync(
            parentAssetId, cancellationToken);

        return parentEvents.Any(e => e is AssetAttestedEvent or AssetDerivedEvent);
    }

    private async Task<LedgerAnchoredEvent?> FindAnchorForAssetAsync(
        AttestationId attestationId,
        CancellationToken cancellationToken)
    {
        // For now, simplified: check if any anchor event exists
        // Full implementation would check if the anchor's ledger root
        // includes the attestation event
        var eventCount = await _ledgerRepository.GetEventCountAsync(cancellationToken);

        // This is a placeholder - real implementation would walk the chain
        // and verify the attestation is included in an anchored ledger root
        return null;
    }
}
