//! Confirming a reporting peer's actual *standing* in the cluster it self-asserts -- the half of
//! the "is this claim real" gap that `bridge::MeshTree::is_attested_base_cluster` and
//! `corroboration::ClaimCorroboration::best_corroborated_value_cross_checked` both explicitly
//! leave open in their own doc comments: a `BridgeDeclaration` only ever attests that a cluster
//! *name* is nested under some mesh-group, signed by whichever peer felt like asserting it -- it
//! never records which peers actually belong to the cluster itself. This module adds the new,
//! separate kind of signed fact both of those doc comments said would be needed: a
//! `MembershipAttestation`, signed by *some other* peer, saying "I attest that `subject_peer_id`
//! is a genuine member of `cluster`."
//!
//! Same self-declared, corroborate-by-distinct-signer shape every other fact in this crate
//! already uses (`bridge::BridgeDeclaration`'s edges, `corroboration::ClaimReport`'s cluster
//! weighting): one attestation alone is exactly as unauthenticated as a bare label; weight grows
//! with how many *distinct* attesting peers independently agree. Same anti-sybil proof-of-work
//! treatment too, keyed to the resource this corroboration count depends on -- becoming a new
//! distinct attester for one `(cluster, subject_peer_id)` pair, mirroring
//! `bridge::BridgeProofOfWork`'s and `corroboration::ClaimReportProofOfWork`'s identical shape.
//!
//! **What this does not close, stated as plainly as `bridge.rs`'s and `corroboration.rs`'s own
//! remaining gaps are:** nothing here verifies that the *attesting* peer itself has any more
//! standing in `cluster` than the subject it's vouching for -- an attester is just another
//! self-asserting `PeerIdentity`, exactly like a `BridgeDeclaration`'s signer. Proof-of-work
//! taxes the cost of minting fresh attesting identities to vouch for a fabricated member; it does
//! not verify those attesters are themselves genuinely established members of `cluster` either.
//! This is the same "proof-of-work bounds cost, not identity" gap `spec/01-overview.md` already
//! names for the other two mechanisms, applying here one level deeper: real root-of-trust
//! bootstrapping (binding a cluster identity to an operator's existing PKI, DNS, or other
//! out-of-band credential) is out of scope for this protocol layer. A chain of attestations is
//! still turtles all the way down without it.

use std::collections::{HashMap, HashSet};

use oag_crypto::{sign_with_domain, verify_with_domain, PeerId, PeerIdentity, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const MEMBERSHIP_ATTESTATION_DOMAIN: &str = "OAG-MESH:MEMBERSHIP_ATTESTATION:v1:";

/// Same tolerance every other signed message in this crate (and the base project) uses.
pub const MAX_CLOCK_SKEW_SECONDS: i64 = 300;

/// The difficulty (in required leading zero bits, same `blake3`-based scheme as
/// `bridge::BridgeProofOfWork`/`corroboration::ClaimReportProofOfWork`) for the *first* peer to
/// attest a given `(cluster, subject_peer_id)` membership fact. See
/// `MembershipRegistry::required_difficulty_bits` for why every other attestation of the same
/// fact -- by an attester that already attested it -- costs nothing at all.
pub const BASE_MEMBERSHIP_DIFFICULTY_BITS: u32 = 16;

/// How much the required difficulty grows for each additional distinct attester already vouching
/// for a given `(cluster, subject_peer_id)` pair before this one. Mirrors
/// `bridge::BRIDGE_DIFFICULTY_STEP_BITS`'s shape exactly, substituting "distinct attester already
/// corroborating this membership claim" for "distinct peer already corroborating this edge".
pub const MEMBERSHIP_DIFFICULTY_STEP_BITS: u32 = 4;

/// The difficulty required to be the `existing_attesters`-th distinct attester (0-indexed) to
/// vouch for one `(cluster, subject_peer_id)` pair -- the first attester needs
/// `BASE_MEMBERSHIP_DIFFICULTY_BITS`, each one after that needs `MEMBERSHIP_DIFFICULTY_STEP_BITS`
/// more.
pub fn difficulty_bits_for_attester_number(existing_attesters: usize) -> u32 {
    BASE_MEMBERSHIP_DIFFICULTY_BITS + (existing_attesters as u32) * MEMBERSHIP_DIFFICULTY_STEP_BITS
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedMembershipAttestation {
    pub attester_peer_id: String,
    /// Hex-encoded Ed25519 public key -- same convention every other signed message in this
    /// crate uses.
    pub attester_public_key: String,
    /// The peer being vouched for. Deliberately *not* required to sign anything itself here --
    /// an attestation is a claim another peer makes about the subject, not something the subject
    /// consents to or participates in producing (a subject could just as well be the target of a
    /// malicious attestation; `MembershipRegistry::is_attested_member` is a corroboration count,
    /// not proof of consent).
    pub subject_peer_id: String,
    pub cluster: String,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipAttestation {
    #[serde(flatten)]
    pub unsigned: UnsignedMembershipAttestation,
    pub signature: String,
}

#[derive(Debug, thiserror::Error)]
pub enum MembershipError {
    #[error("invalid attester peer id: {0}")]
    AttesterPeerId(oag_crypto::PeerIdParseError),
    #[error("invalid subject peer id: {0}")]
    SubjectPeerId(oag_crypto::PeerIdParseError),
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("attester_peer_id does not match the derived hash of attester_public_key")]
    PeerIdKeyMismatch,
    #[error("bad signature encoding")]
    BadSignatureEncoding,
    #[error("signature verification failed")]
    BadSignature,
    #[error("timestamp is too far from now")]
    ClockSkew,
    #[error("a peer cannot attest its own membership (self-attestation does not corroborate anything)")]
    SelfAttestation,
    #[error("proof of work does not meet the required {required_bits} leading zero bits for this (cluster, subject_peer_id) pair")]
    InsufficientProofOfWork { required_bits: u32 },
    #[error("internal error: {0}")]
    Internal(String),
}

/// Anti-sybil proof-of-work for a `MembershipAttestation` -- same motivation as
/// `bridge::BridgeProofOfWork`: signature verification alone doesn't bound how many fresh
/// `PeerIdentity`s one actor can mint to independently "attest" the same `(cluster,
/// subject_peer_id)` fact, inflating `MembershipRegistry`'s distinct-attester count for free, and
/// therefore inflating how confidently a reporting peer's claimed membership can be trusted.
/// Same "raises cost, doesn't eliminate" caveat as every other proof-of-work in this crate.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct MembershipProofOfWork {
    pub nonce: u64,
}

/// Binds the proof to this specific `(attester_peer_id, subject_peer_id, cluster)` combination --
/// a solved proof for one attestation cannot be replayed for a different attester, subject, or
/// cluster.
fn membership_pow_hash(unsigned: &UnsignedMembershipAttestation, pow: &MembershipProofOfWork) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"OAG-MESH:MEMBERSHIP_ATTESTATION_POW:v1:");
    hasher.update(unsigned.attester_peer_id.as_bytes());
    hasher.update(unsigned.subject_peer_id.as_bytes());
    hasher.update(unsigned.cluster.as_bytes());
    hasher.update(&pow.nonce.to_le_bytes());
    hasher.finalize()
}

fn leading_zero_bits(hash: &blake3::Hash) -> u32 {
    let mut count = 0;
    for &byte in hash.as_bytes() {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

impl MembershipProofOfWork {
    /// The client-side work: searches for a `nonce` whose `membership_pow_hash` has at least
    /// `difficulty_bits` leading zero bits. A real submitting client calls
    /// `MembershipRegistry::required_difficulty_bits` first to know what to solve for.
    pub fn solve(unsigned: &UnsignedMembershipAttestation, difficulty_bits: u32) -> Self {
        let mut nonce = 0u64;
        loop {
            let candidate = MembershipProofOfWork { nonce };
            if leading_zero_bits(&membership_pow_hash(unsigned, &candidate)) >= difficulty_bits {
                return candidate;
            }
            nonce += 1;
        }
    }

    fn satisfies(&self, unsigned: &UnsignedMembershipAttestation, difficulty_bits: u32) -> bool {
        leading_zero_bits(&membership_pow_hash(unsigned, self)) >= difficulty_bits
    }
}

fn decode_32(s: &str) -> Option<[u8; 32]> {
    hex::decode(s).ok().and_then(|v| v.try_into().ok())
}

fn decode_64(s: &str) -> Option<[u8; 64]> {
    hex::decode(s).ok().and_then(|v| v.try_into().ok())
}

/// Sign an attestation that `subject_peer_id` is a genuine member of `cluster`. Takes
/// `timestamp` explicitly (rather than reading the clock itself) so tests can exercise `verify`'s
/// clock-skew check deterministically -- same reasoning as every signed-message constructor in
/// this crate.
pub fn build_and_sign(
    attester: &PeerIdentity,
    subject_peer_id: PeerId,
    cluster: &str,
    timestamp: i64,
) -> Result<MembershipAttestation, MembershipError> {
    if attester.peer_id() == subject_peer_id {
        return Err(MembershipError::SelfAttestation);
    }
    let unsigned = UnsignedMembershipAttestation {
        attester_peer_id: attester.peer_id().to_string(),
        attester_public_key: hex::encode(attester.verifying_key().to_bytes()),
        subject_peer_id: subject_peer_id.to_string(),
        cluster: cluster.to_string(),
        timestamp,
    };
    let canonical =
        oag_core::canonical_json_bytes(&unsigned).map_err(|e| MembershipError::Internal(e.to_string()))?;
    let signature = sign_with_domain(attester.signing_key(), MEMBERSHIP_ATTESTATION_DOMAIN, &canonical);
    Ok(MembershipAttestation { unsigned, signature: hex::encode(signature.to_bytes()) })
}

/// Verifies an attestation's `(attester_peer_id, attester_public_key)` pairing, its Ed25519
/// signature, timestamp freshness, and that it isn't a self-attestation. Returns
/// `(attester_peer_id, subject_peer_id)`. Does **not** check corroboration, or whether the
/// attester itself has any real standing in `cluster` -- see this module's own top-level doc
/// comment for why that's a deliberate, stated gap, and `MembershipRegistry::add` for the
/// separate step that weighs multiple attestations against each other.
pub fn verify(attestation: &MembershipAttestation, now: i64) -> Result<(PeerId, PeerId), MembershipError> {
    let attester_peer_id: PeerId =
        attestation.unsigned.attester_peer_id.parse().map_err(MembershipError::AttesterPeerId)?;
    let subject_peer_id: PeerId =
        attestation.unsigned.subject_peer_id.parse().map_err(MembershipError::SubjectPeerId)?;
    if attester_peer_id == subject_peer_id {
        return Err(MembershipError::SelfAttestation);
    }

    let pk_bytes = decode_32(&attestation.unsigned.attester_public_key).ok_or(MembershipError::InvalidPublicKey)?;
    let verifying_key = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| MembershipError::InvalidPublicKey)?;
    if attester_peer_id != PeerId::from_public_key(&verifying_key) {
        return Err(MembershipError::PeerIdKeyMismatch);
    }

    let canonical = oag_core::canonical_json_bytes(&attestation.unsigned)
        .map_err(|e| MembershipError::Internal(e.to_string()))?;
    let sig_bytes = decode_64(&attestation.signature).ok_or(MembershipError::BadSignatureEncoding)?;
    let signature = Signature::from_bytes(&sig_bytes);
    verify_with_domain(&verifying_key, MEMBERSHIP_ATTESTATION_DOMAIN, &canonical, &signature)
        .map_err(|_| MembershipError::BadSignature)?;

    if (attestation.unsigned.timestamp - now).abs() > MAX_CLOCK_SKEW_SECONDS {
        return Err(MembershipError::ClockSkew);
    }

    Ok((attester_peer_id, subject_peer_id))
}

/// A collected set of verified attestations, resolved into queryable membership-standing facts.
/// Built purely in memory from whatever attestations the caller has gathered, same posture as
/// `bridge::MeshTree` and `corroboration::ClaimCorroboration`.
#[derive(Debug, Default)]
pub struct MembershipRegistry {
    /// (cluster, subject_peer_id) -> set of distinct attesting peer ids. A `HashSet`, not a
    /// count, for the same reason `bridge::MeshTree::edges` is -- the same attester re-asserting
    /// the same fact must not inflate corroboration.
    attestations: HashMap<(String, PeerId), HashSet<PeerId>>,
}

impl MembershipRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// The proof-of-work difficulty an attestation of `(cluster, subject_peer_id)` by
    /// `attester_peer_id` must currently meet, per `difficulty_bits_for_attester_number`.
    /// **Free (`0` bits, always satisfied) if `attester_peer_id` has already attested this
    /// exact fact** -- re-attesting it doesn't increase the distinct-attester count, so there is
    /// nothing to tax.
    pub fn required_difficulty_bits(&self, cluster: &str, subject_peer_id: &PeerId, attester_peer_id: &PeerId) -> u32 {
        let Some(attesters) = self.attestations.get(&(cluster.to_string(), *subject_peer_id)) else {
            return BASE_MEMBERSHIP_DIFFICULTY_BITS;
        };
        if attesters.contains(attester_peer_id) {
            return 0;
        }
        difficulty_bits_for_attester_number(attesters.len())
    }

    /// Verifies `attestation`, checks `pow` against `required_difficulty_bits` for this
    /// attestation's `(cluster, subject_peer_id, attester_peer_id)` *at the moment this is
    /// called*, and if both pass, records it. Returns `(attester_peer_id, subject_peer_id)` on
    /// success. An attestation that fails verification, or whose proof-of-work is insufficient,
    /// is never recorded.
    pub fn add(
        &mut self,
        attestation: &MembershipAttestation,
        pow: MembershipProofOfWork,
        now: i64,
    ) -> Result<(PeerId, PeerId), MembershipError> {
        let (attester_peer_id, subject_peer_id) = verify(attestation, now)?;
        let required_bits =
            self.required_difficulty_bits(&attestation.unsigned.cluster, &subject_peer_id, &attester_peer_id);
        if !pow.satisfies(&attestation.unsigned, required_bits) {
            return Err(MembershipError::InsufficientProofOfWork { required_bits });
        }
        self.attestations
            .entry((attestation.unsigned.cluster.clone(), subject_peer_id))
            .or_default()
            .insert(attester_peer_id);
        Ok((attester_peer_id, subject_peer_id))
    }

    /// How many *distinct* peers have attested that `subject_peer_id` belongs to `cluster`. `0`
    /// if nothing has ever attested this.
    pub fn attester_count(&self, cluster: &str, subject_peer_id: &PeerId) -> usize {
        self.attestations.get(&(cluster.to_string(), *subject_peer_id)).map(HashSet::len).unwrap_or(0)
    }

    /// Whether `subject_peer_id` is attested as a genuine member of `cluster` by at least
    /// `min_corroboration` distinct attesting peers. See this module's own top-level doc comment
    /// for the gap this does not close: it says nothing about whether those attesters themselves
    /// have any real standing in `cluster`.
    pub fn is_attested_member(&self, cluster: &str, subject_peer_id: &PeerId, min_corroboration: usize) -> bool {
        self.attester_count(cluster, subject_peer_id) >= min_corroboration
    }

    /// A persistable snapshot of every attestation this registry currently holds. `PeerId` has
    /// no `Serialize`/`Deserialize` of its own, so peer ids round-trip through their
    /// `Display`/`FromStr` string form -- same convention as `bridge::MeshTree::snapshot`. See
    /// `MembershipRegistry::from_snapshot` for the inverse.
    pub fn snapshot(&self) -> Vec<MembershipSnapshot> {
        self.attestations
            .iter()
            .map(|((cluster, subject_peer_id), attesters)| MembershipSnapshot {
                cluster: cluster.clone(),
                subject_peer_id: subject_peer_id.to_string(),
                attesters: attesters.iter().map(|p| p.to_string()).collect(),
            })
            .collect()
    }

    /// Rebuilds a `MembershipRegistry` from `snapshot` (e.g. loaded from disk via
    /// `persistence::load_json`). A peer id string that fails to parse is dropped with a warning
    /// rather than failing the whole load -- same posture as `bridge::MeshTree::from_snapshot`.
    /// A snapshot entry whose `subject_peer_id` itself fails to parse drops the whole entry, for
    /// the same reason.
    pub fn from_snapshot(snapshot: Vec<MembershipSnapshot>) -> Self {
        let mut registry = Self::new();
        registry.merge_snapshot(snapshot);
        registry
    }

    /// Merges `snapshot` into this registry's existing attestations -- unions each `(cluster,
    /// subject_peer_id)` pair's attesting-peer set rather than replacing it, so merging the same
    /// snapshot repeatedly (or merging snapshots from several different peers) is idempotent and
    /// additive. The building block for `transport::pull_and_merge`'s pull-based anti-entropy
    /// (`spec/10-anti-entropy.md`). Same peer-id-string-parse-failure handling as
    /// `from_snapshot`.
    ///
    /// **Trust note**: same as `bridge::MeshTree::merge_snapshot` -- no signature or
    /// proof-of-work is re-checked here, because a snapshot has already collapsed each
    /// attestation down past its original signed `MembershipAttestation`. This trusts the source
    /// peer the same way `MeshState.peers`'s static configuration already does, but it is a
    /// weaker guarantee than `add`'s own independent verification. See `spec/10-anti-entropy.md`.
    pub fn merge_snapshot(&mut self, snapshot: Vec<MembershipSnapshot>) {
        for entry in snapshot {
            let subject_peer_id: PeerId = match entry.subject_peer_id.parse() {
                Ok(peer_id) => peer_id,
                Err(e) => {
                    tracing::warn!(peer_id = %entry.subject_peer_id, error = %e, "dropping unparsable subject peer id from persisted membership snapshot");
                    continue;
                }
            };
            let mut attesters = HashSet::new();
            for peer_id_str in entry.attesters {
                match peer_id_str.parse::<PeerId>() {
                    Ok(peer_id) => {
                        attesters.insert(peer_id);
                    }
                    Err(e) => tracing::warn!(peer_id = %peer_id_str, error = %e, "dropping unparsable attester peer id from persisted membership snapshot"),
                }
            }
            self.attestations.entry((entry.cluster, subject_peer_id)).or_default().extend(attesters);
        }
    }
}

/// See `MembershipRegistry::snapshot`/`MembershipRegistry::from_snapshot`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipSnapshot {
    pub cluster: String,
    pub subject_peer_id: String,
    pub attesters: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Solves whatever proof-of-work `registry` currently requires for `attestation`'s
    /// `(cluster, subject_peer_id, attester_peer_id)`, then adds it -- mirrors `bridge.rs`'s and
    /// `corroboration.rs`'s own identical test helpers.
    fn add_with_fresh_pow(
        registry: &mut MembershipRegistry,
        attestation: &MembershipAttestation,
        now: i64,
    ) -> Result<(PeerId, PeerId), MembershipError> {
        let attester_peer_id: PeerId = attestation.unsigned.attester_peer_id.parse().unwrap();
        let subject_peer_id: PeerId = attestation.unsigned.subject_peer_id.parse().unwrap();
        let required = registry.required_difficulty_bits(&attestation.unsigned.cluster, &subject_peer_id, &attester_peer_id);
        let pow = MembershipProofOfWork::solve(&attestation.unsigned, required);
        registry.add(attestation, pow, now)
    }

    /// Solves for a nonce whose hash has *exactly* `exact_bits` leading zero bits, not merely at
    /// least -- same determinism fix as `bridge.rs`'s/`corroboration.rs`'s own `solve_*_exact`
    /// helpers, needed so a "stale proof should now be rejected" assertion can't flake from an
    /// `>=` search occasionally overshooting a higher threshold by chance.
    fn solve_membership_pow_exact(unsigned: &UnsignedMembershipAttestation, exact_bits: u32) -> MembershipProofOfWork {
        let mut nonce = 0u64;
        loop {
            let candidate = MembershipProofOfWork { nonce };
            if leading_zero_bits(&membership_pow_hash(unsigned, &candidate)) == exact_bits {
                return candidate;
            }
            nonce += 1;
        }
    }

    #[test]
    fn attestation_sign_and_verify_round_trip() {
        let attester = PeerIdentity::generate();
        let subject = PeerIdentity::generate();
        let attestation = build_and_sign(&attester, subject.peer_id(), "cluster-a", 1_000).unwrap();
        let (attester_peer_id, subject_peer_id) = verify(&attestation, 1_010).unwrap();
        assert_eq!(attester_peer_id, attester.peer_id());
        assert_eq!(subject_peer_id, subject.peer_id());
    }

    #[test]
    fn self_attestation_is_rejected_at_build_time() {
        let attester = PeerIdentity::generate();
        let err = build_and_sign(&attester, attester.peer_id(), "cluster-a", 1_000).unwrap_err();
        assert!(matches!(err, MembershipError::SelfAttestation));
    }

    #[test]
    fn self_attestation_is_rejected_at_verify_time_too() {
        // Hand-construct a self-attestation that skipped build_and_sign's own check, to prove
        // verify() enforces this independently rather than trusting the constructor.
        let attester = PeerIdentity::generate();
        let unsigned = UnsignedMembershipAttestation {
            attester_peer_id: attester.peer_id().to_string(),
            attester_public_key: hex::encode(attester.verifying_key().to_bytes()),
            subject_peer_id: attester.peer_id().to_string(),
            cluster: "cluster-a".to_string(),
            timestamp: 1_000,
        };
        let canonical = oag_core::canonical_json_bytes(&unsigned).unwrap();
        let signature = sign_with_domain(attester.signing_key(), MEMBERSHIP_ATTESTATION_DOMAIN, &canonical);
        let attestation = MembershipAttestation { unsigned, signature: hex::encode(signature.to_bytes()) };
        assert!(matches!(verify(&attestation, 1_010), Err(MembershipError::SelfAttestation)));
    }

    #[test]
    fn tampered_cluster_fails_verification() {
        let attester = PeerIdentity::generate();
        let subject = PeerIdentity::generate();
        let mut attestation = build_and_sign(&attester, subject.peer_id(), "cluster-a", 1_000).unwrap();
        attestation.unsigned.cluster = "cluster-b".to_string();
        assert!(matches!(verify(&attestation, 1_010), Err(MembershipError::BadSignature)));
    }

    #[test]
    fn mismatched_attester_peer_id_and_public_key_is_rejected() {
        let victim = PeerIdentity::generate();
        let attacker = PeerIdentity::generate();
        let subject = PeerIdentity::generate();
        let mut attestation = build_and_sign(&victim, subject.peer_id(), "cluster-a", 1_000).unwrap();
        attestation.unsigned.attester_public_key = hex::encode(attacker.verifying_key().to_bytes());
        let canonical = oag_core::canonical_json_bytes(&attestation.unsigned).unwrap();
        let sig = sign_with_domain(attacker.signing_key(), MEMBERSHIP_ATTESTATION_DOMAIN, &canonical);
        attestation.signature = hex::encode(sig.to_bytes());
        assert!(matches!(verify(&attestation, 1_010), Err(MembershipError::PeerIdKeyMismatch)));
    }

    #[test]
    fn stale_timestamp_is_rejected() {
        let attester = PeerIdentity::generate();
        let subject = PeerIdentity::generate();
        let attestation = build_and_sign(&attester, subject.peer_id(), "cluster-a", 1_000).unwrap();
        let far_future = 1_000 + MAX_CLOCK_SKEW_SECONDS + 1;
        assert!(matches!(verify(&attestation, far_future), Err(MembershipError::ClockSkew)));
    }

    #[test]
    fn corroboration_counts_distinct_attesters_not_repeated_attestations() {
        let attester_a = PeerIdentity::generate();
        let attester_b = PeerIdentity::generate();
        let subject = PeerIdentity::generate();
        let mut registry = MembershipRegistry::new();

        let a1 = build_and_sign(&attester_a, subject.peer_id(), "cluster-a", 1_000).unwrap();
        add_with_fresh_pow(&mut registry, &a1, 1_010).unwrap();
        assert_eq!(registry.attester_count("cluster-a", &subject.peer_id()), 1);

        // The same attester re-attesting the identical fact must not inflate corroboration.
        let a1_again = build_and_sign(&attester_a, subject.peer_id(), "cluster-a", 1_001).unwrap();
        add_with_fresh_pow(&mut registry, &a1_again, 1_011).unwrap();
        assert_eq!(registry.attester_count("cluster-a", &subject.peer_id()), 1);

        // A genuinely different attester vouching for the same subject does.
        let a2 = build_and_sign(&attester_b, subject.peer_id(), "cluster-a", 1_000).unwrap();
        add_with_fresh_pow(&mut registry, &a2, 1_010).unwrap();
        assert_eq!(registry.attester_count("cluster-a", &subject.peer_id()), 2);
    }

    #[test]
    fn is_attested_member_checks_existence_and_minimum_corroboration() {
        let attester_a = PeerIdentity::generate();
        let attester_b = PeerIdentity::generate();
        let subject = PeerIdentity::generate();
        let stranger = PeerIdentity::generate();
        let mut registry = MembershipRegistry::new();

        add_with_fresh_pow(&mut registry, &build_and_sign(&attester_a, subject.peer_id(), "cluster-a", 1_000).unwrap(), 1_010).unwrap();

        assert!(registry.is_attested_member("cluster-a", &subject.peer_id(), 1));
        assert!(!registry.is_attested_member("cluster-a", &subject.peer_id(), 2));
        assert!(!registry.is_attested_member("cluster-a", &stranger.peer_id(), 1));
        assert!(!registry.is_attested_member("cluster-b", &subject.peer_id(), 1));

        add_with_fresh_pow(&mut registry, &build_and_sign(&attester_b, subject.peer_id(), "cluster-a", 1_000).unwrap(), 1_010).unwrap();
        assert!(registry.is_attested_member("cluster-a", &subject.peer_id(), 2));
    }

    #[test]
    fn an_invalid_attestation_is_never_recorded() {
        let attester = PeerIdentity::generate();
        let subject = PeerIdentity::generate();
        let mut attestation = build_and_sign(&attester, subject.peer_id(), "cluster-a", 1_000).unwrap();
        attestation.unsigned.cluster = "tampered".to_string();
        let mut registry = MembershipRegistry::new();
        // A tampered attestation fails signature verification before proof-of-work is even
        // checked, so an unsolved (zero) nonce is fine here -- it must never be reached.
        assert!(registry.add(&attestation, MembershipProofOfWork { nonce: 0 }, 1_010).is_err());
        assert_eq!(registry.attester_count("tampered", &subject.peer_id()), 0);
    }

    #[test]
    fn an_attestation_with_no_proof_of_work_is_rejected() {
        let attester = PeerIdentity::generate();
        let subject = PeerIdentity::generate();
        let attestation = build_and_sign(&attester, subject.peer_id(), "pow-test-cluster", 1_000).unwrap();
        let mut registry = MembershipRegistry::new();
        let err = registry.add(&attestation, MembershipProofOfWork { nonce: 0 }, 1_010).unwrap_err();
        assert!(matches!(
            err,
            MembershipError::InsufficientProofOfWork { required_bits } if required_bits == BASE_MEMBERSHIP_DIFFICULTY_BITS
        ));
        assert_eq!(registry.attester_count("pow-test-cluster", &subject.peer_id()), 0);
    }

    #[test]
    fn an_attester_re_attesting_the_same_fact_requires_no_proof_of_work() {
        let attester = PeerIdentity::generate();
        let subject = PeerIdentity::generate();
        let mut registry = MembershipRegistry::new();

        let attestation = build_and_sign(&attester, subject.peer_id(), "re-attest-test", 1_000).unwrap();
        add_with_fresh_pow(&mut registry, &attestation, 1_010).unwrap();

        let attestation_again = build_and_sign(&attester, subject.peer_id(), "re-attest-test", 1_001).unwrap();
        assert_eq!(
            registry.required_difficulty_bits("re-attest-test", &subject.peer_id(), &attester.peer_id()),
            0
        );
        registry.add(&attestation_again, MembershipProofOfWork { nonce: 0 }, 1_011).unwrap();
        assert_eq!(registry.attester_count("re-attest-test", &subject.peer_id()), 1);
    }

    #[test]
    fn required_difficulty_escalates_with_each_additional_distinct_attester_on_one_subject() {
        let attester_a = PeerIdentity::generate();
        let attester_b = PeerIdentity::generate();
        let subject = PeerIdentity::generate();
        let mut registry = MembershipRegistry::new();

        assert_eq!(
            registry.required_difficulty_bits("escalation-cluster", &subject.peer_id(), &attester_a.peer_id()),
            BASE_MEMBERSHIP_DIFFICULTY_BITS
        );

        add_with_fresh_pow(
            &mut registry,
            &build_and_sign(&attester_a, subject.peer_id(), "escalation-cluster", 1_000).unwrap(),
            1_010,
        )
        .unwrap();

        // A second, genuinely new attester now costs one extra step.
        assert_eq!(
            registry.required_difficulty_bits("escalation-cluster", &subject.peer_id(), &attester_b.peer_id()),
            BASE_MEMBERSHIP_DIFFICULTY_BITS + MEMBERSHIP_DIFFICULTY_STEP_BITS
        );

        let attestation_b = build_and_sign(&attester_b, subject.peer_id(), "escalation-cluster", 1_000).unwrap();
        let stale_pow = solve_membership_pow_exact(&attestation_b.unsigned, BASE_MEMBERSHIP_DIFFICULTY_BITS);
        let err = registry.add(&attestation_b, stale_pow, 1_010).unwrap_err();
        let expected_bits = BASE_MEMBERSHIP_DIFFICULTY_BITS + MEMBERSHIP_DIFFICULTY_STEP_BITS;
        assert!(matches!(err, MembershipError::InsufficientProofOfWork { required_bits } if required_bits == expected_bits));
    }

    #[test]
    fn a_membership_proof_of_work_is_bound_to_its_own_attestation_and_cannot_be_reused() {
        let attester_a = PeerIdentity::generate();
        let attester_b = PeerIdentity::generate();
        let subject_a = PeerIdentity::generate();
        let subject_b = PeerIdentity::generate();
        let attestation_a = build_and_sign(&attester_a, subject_a.peer_id(), "binding-test-a", 1_000).unwrap();
        let attestation_b = build_and_sign(&attester_b, subject_b.peer_id(), "binding-test-b", 1_000).unwrap();
        let pow_for_a = MembershipProofOfWork::solve(&attestation_a.unsigned, BASE_MEMBERSHIP_DIFFICULTY_BITS);

        let mut registry = MembershipRegistry::new();
        let err = registry.add(&attestation_b, pow_for_a, 1_010).unwrap_err();
        assert!(matches!(
            err,
            MembershipError::InsufficientProofOfWork { required_bits } if required_bits == BASE_MEMBERSHIP_DIFFICULTY_BITS
        ));
    }

    #[test]
    fn merge_snapshot_unions_attester_sets_rather_than_replacing_them() {
        let attester_a = PeerIdentity::generate();
        let attester_b = PeerIdentity::generate();
        let subject = PeerIdentity::generate();
        let mut local = MembershipRegistry::new();
        let mut remote = MembershipRegistry::new();

        add_with_fresh_pow(&mut local, &build_and_sign(&attester_a, subject.peer_id(), "cluster-a", 1_000).unwrap(), 1_010).unwrap();
        add_with_fresh_pow(&mut remote, &build_and_sign(&attester_b, subject.peer_id(), "cluster-a", 1_000).unwrap(), 1_010).unwrap();

        local.merge_snapshot(remote.snapshot());
        assert_eq!(local.attester_count("cluster-a", &subject.peer_id()), 2);

        // Merging the identical snapshot again must not double-count.
        local.merge_snapshot(remote.snapshot());
        assert_eq!(local.attester_count("cluster-a", &subject.peer_id()), 2);
    }

    #[test]
    fn snapshot_round_trips_through_from_snapshot() {
        let attester = PeerIdentity::generate();
        let subject = PeerIdentity::generate();
        let mut registry = MembershipRegistry::new();
        add_with_fresh_pow(&mut registry, &build_and_sign(&attester, subject.peer_id(), "cluster-a", 1_000).unwrap(), 1_010).unwrap();

        let snapshot = registry.snapshot();
        let restored = MembershipRegistry::from_snapshot(snapshot);
        assert!(restored.is_attested_member("cluster-a", &subject.peer_id(), 1));
    }
}
