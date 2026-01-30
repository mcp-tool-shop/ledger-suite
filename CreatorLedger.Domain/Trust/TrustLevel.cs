namespace CreatorLedger.Domain.Trust;

/// <summary>
/// Trust level for an asset based on its verification status.
///
/// TRUST LEVEL SEMANTICS:
///
/// These levels form a partial order - not a strict hierarchy. The verification
/// process considers three independent factors:
///   1. Hash integrity (does the current content match the attested hash?)
///   2. Signature validity (is the attestation cryptographically signed by the creator?)
///   3. External anchoring (is the attestation anchored to an immutable timestamping service?)
///
/// LEVEL DEFINITIONS:
///
/// Unverified (0): No attestation exists for this asset. The content has never been
///   cryptographically attested by any creator. This is the starting state for all
///   imported content.
///
/// Signed (1): The asset has a valid Ed25519 signature from its creator, and the
///   current content hash matches the attested hash. This proves the content existed
///   in this exact form when the creator signed it, but does not prove WHEN that
///   signature was created.
///
/// Derived (2): The asset is a derivative work, cryptographically linked to a parent
///   asset. The derived asset has its own signature, and the parent chain is valid.
///   This preserves provenance chains (e.g., remixes, adaptations).
///
/// VerifiedOriginal (3): The asset is Signed AND has been anchored to an external
///   timestamping service (e.g., blockchain). This provides both authorship proof
///   AND temporal proof - the signature provably existed before the anchor time.
///
/// Broken (4): Verification FAILED. Either the content hash doesn't match the
///   attestation (content was modified), or the signature verification failed
///   (attestation was tampered with). This is a hard failure - the asset's
///   integrity cannot be trusted.
///
/// IMPORTANT DISTINCTIONS:
///
/// - Signed vs VerifiedOriginal: Both have valid signatures. The difference is
///   temporal proof. Signed proves authorship; VerifiedOriginal proves authorship
///   AND that the signature existed before a specific time.
///
/// - Derived vs Signed: Derived has a parent chain; Signed is an "original" work.
///   A derived asset can be anchored (becoming Derived + anchored), but this is
///   tracked separately via IsAnchored in the verification report.
///
/// - Unverified vs Broken: Unverified means "no claim exists". Broken means
///   "a claim exists but is FALSE". Broken is worse - it indicates tampering.
/// </summary>
public enum TrustLevel
{
    /// <summary>
    /// ⚠️ No attestation exists for this asset.
    /// The content has never been cryptographically attested.
    /// </summary>
    Unverified = 0,

    /// <summary>
    /// 🔵 Asset has a valid signature and matching content hash.
    /// Proves authorship but NOT timestamp.
    /// </summary>
    Signed = 1,

    /// <summary>
    /// 🟡 Asset is a valid derivative work with verified parent chain.
    /// Preserves provenance/remix lineage.
    /// </summary>
    Derived = 2,

    /// <summary>
    /// 🟢 Asset is signed AND anchored to external timestamping service.
    /// Proves authorship AND temporal existence.
    /// </summary>
    VerifiedOriginal = 3,

    /// <summary>
    /// 🔴 Verification FAILED: hash mismatch or invalid signature.
    /// Indicates tampering or corruption - do not trust.
    /// </summary>
    Broken = 4
}
