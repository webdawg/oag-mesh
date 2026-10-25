//! Federated corroboration: nodes across different (self-declared) clusters each independently
//! report what they observed for the same claim, and agreement is weighted by how many
//! *distinct clusters* -- not merely distinct peers -- agree. This generalizes
//! `spec/32-verified-internet-gateway.md`'s quorum fan-out from the base project (one peer
//! comparing answers from its own configured `query_peers`) across organizational/cluster
//! boundaries instead: here, the question is not "did enough of *my* peers agree" but "did
//! enough *independent organizations* agree."
//!
//! A `ClaimReport` is signed with the same `oag_crypto::PeerIdentity` every other mechanism in
//! this crate reuses -- but unlike `bridge::BridgeDeclaration` (which places a cluster *into* a
//! mesh-group) or `anonymous_event::AnonymousEvent` (which carries no identity at all), this one
//! needs identity specifically so `reporter_cluster` means something: weighting by distinct
//! cluster requires knowing which cluster a reporter claims to be from.
//!
//! `reporter_cluster` is a bare self-assertion, exactly like the base project's own
//! `[cluster].name` (`spec/26-peer-clustering.md` there) -- not verified against anything,
//! not cross-checked against `bridge::MeshTree`. A caller deciding how much to trust a given
//! corroboration count should weigh that the same way the base project's own docs ask an
//! operator to weigh a bare cluster name: "treat it like a weak shared secret, not a security
//! boundary." See this file's own module-level "Open questions" cross-reference in
//! `spec/05-federated-corroboration.md`.

use std::collections::{HashMap, HashSet};

use oag_crypto::{sign_with_domain, verify_with_domain, PeerId, PeerIdentity, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::bridge::MeshTree;

pub const CLAIM_REPORT_DOMAIN: &str = "OAG-MESH:CLAIM_REPORT:v1:";

/// Same tolerance every other signed message in this crate (and the base project) uses.
pub const MAX_CLOCK_SKEW_SECONDS: i64 = 300;

/// The difficulty (in required leading zero bits, same `blake3`-based scheme as
/// `anonymous_event::ProofOfWork`) for the *first* report under a fresh `reporter_cluster` for a
/// given `claim_id` -- i.e. the cost of being the cluster that establishes a brand-new
/// `distinct_clusters` count of `1` for this claim. See `ClaimCorroboration::required_difficulty_bits`
/// for why every other report (same cluster re-reporting, or a different peer within an
/// already-counted cluster) costs nothing at all.
pub const BASE_CLAIM_REPORT_DIFFICULTY_BITS: u32 = 16;

/// How much the required difficulty grows for each *additional distinct cluster* already
/// corroborating a claim before this one. Mirrors `anonymous_event::DIFFICULTY_STEP_BITS`'s
/// escalation shape, but keyed to distinct-cluster count rather than raw report count -- the
/// resource this mechanism actually needs to tax, see `ClaimCorroboration::required_difficulty_bits`.
pub const CLAIM_REPORT_DIFFICULTY_STEP_BITS: u32 = 4;

/// The difficulty required to be the `existing_distinct_clusters`-th *new* cluster to corroborate
/// a claim (0-indexed) -- the first new cluster needs `BASE_CLAIM_REPORT_DIFFICULTY_BITS`, each
/// one after that needs `CLAIM_REPORT_DIFFICULTY_STEP_BITS` more. Mirrors
/// `anonymous_event::difficulty_bits_for_report_number`'s shape exactly, substituting "distinct
/// cluster already on this claim" for "report already under this nonce".
pub fn difficulty_bits_for_new_cluster_number(existing_distinct_clusters: usize) -> u32 {
    BASE_CLAIM_REPORT_DIFFICULTY_BITS + (existing_distinct_clusters as u32) * CLAIM_REPORT_DIFFICULTY_STEP_BITS
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedClaimReport {
    pub peer_id: String,
    pub public_key: String,
    /// What's being corroborated -- a URL, a gateway query key, a content identifier, any
    /// opaque string callers agree on out of band. This crate does not interpret it.
    pub claim_id: String,
    /// Self-asserted, same bare-assertion posture as `[cluster].name` in the base project.
    pub reporter_cluster: String,
    /// What the reporter independently observed/fetched/computed for `claim_id`, reduced to a
    /// comparable hash (e.g. `blake3_content_hash` of a fetched page, or of a serialized
    /// gateway answer) -- never the raw content itself, this message is for comparison, not
    /// transport.
    pub observed_value_hash: String,
    pub observed_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimReport {
    #[serde(flatten)]
    pub unsigned: UnsignedClaimReport,
    pub signature: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ClaimReportError {
    #[error("invalid peer id: {0}")]
    PeerId(#[from] oag_crypto::PeerIdParseError),
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("peer_id does not match the derived hash of public_key")]
    PeerIdKeyMismatch,
    #[error("bad signature encoding")]
    BadSignatureEncoding,
    #[error("signature verification failed")]
    BadSignature,
    #[error("timestamp is too far from now")]
    ClockSkew,
    #[error("proof of work does not meet the required {required_bits} leading zero bits for this (claim_id, reporter_cluster)")]
    InsufficientProofOfWork { required_bits: u32 },
    #[error("internal error: {0}")]
    Internal(String),
}

/// Anti-sybil proof-of-work for a `ClaimReport` -- unlike `anonymous_event::ProofOfWork` (which
/// exists *because* that schema has no identity to lean on), this mechanism already has a real,
/// signed `PeerIdentity` behind every report. What identity alone does **not** stop is an actor
/// minting many fresh `PeerIdentity`s, each self-asserting a different fabricated
/// `reporter_cluster`, to inflate a claim's apparent `distinct_clusters` count for free --
/// `spec/05-federated-corroboration.md`'s own previously-open anti-sybil question. Signature
/// verification alone doesn't bound this because minting a new identity costs nothing; what this
/// proof-of-work taxes instead is the specific resource being counted: becoming a *new* distinct
/// cluster on a claim. It does **not**, and cannot, stop a well-resourced attacker -- same
/// "raises cost, doesn't eliminate" caveat as `anonymous_event::ProofOfWork`'s own doc comment.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClaimReportProofOfWork {
    pub nonce: u64,
}

/// Binds the proof to this specific `(peer_id, claim_id, reporter_cluster, observed_value_hash)`
/// combination -- a solved proof for one report cannot be replayed for a different claim,
/// cluster, value, or reporting peer, mirroring `anonymous_event::proof_of_work_hash`'s binding
/// of a proof to one event's exact content.
fn claim_report_pow_hash(report: &UnsignedClaimReport, pow: &ClaimReportProofOfWork) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"OAG-MESH:CLAIM_REPORT_POW:v1:");
    hasher.update(report.peer_id.as_bytes());
    hasher.update(report.claim_id.as_bytes());
    hasher.update(report.reporter_cluster.as_bytes());
    hasher.update(report.observed_value_hash.as_bytes());
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

impl ClaimReportProofOfWork {
    /// The client-side work: searches for a `nonce` whose `claim_report_pow_hash` has at least
    /// `difficulty_bits` leading zero bits. A real submitting client calls
    /// `ClaimCorroboration::required_difficulty_bits` first to know what to solve for --
    /// over-solving wastes work, under-solving gets rejected.
    pub fn solve(report: &UnsignedClaimReport, difficulty_bits: u32) -> Self {
        let mut nonce = 0u64;
        loop {
            let candidate = ClaimReportProofOfWork { nonce };
            if leading_zero_bits(&claim_report_pow_hash(report, &candidate)) >= difficulty_bits {
                return candidate;
            }
            nonce += 1;
        }
    }

    fn satisfies(&self, report: &UnsignedClaimReport, difficulty_bits: u32) -> bool {
        leading_zero_bits(&claim_report_pow_hash(report, self)) >= difficulty_bits
    }
}

fn decode_32(s: &str) -> Option<[u8; 32]> {
    hex::decode(s).ok().and_then(|v| v.try_into().ok())
}

fn decode_64(s: &str) -> Option<[u8; 64]> {
    hex::decode(s).ok().and_then(|v| v.try_into().ok())
}

pub fn build_and_sign(
    identity: &PeerIdentity,
    claim_id: &str,
    reporter_cluster: &str,
    observed_value_hash: &str,
    observed_at: i64,
) -> Result<ClaimReport, ClaimReportError> {
    let unsigned = UnsignedClaimReport {
        peer_id: identity.peer_id().to_string(),
        public_key: hex::encode(identity.verifying_key().to_bytes()),
        claim_id: claim_id.to_string(),
        reporter_cluster: reporter_cluster.to_string(),
        observed_value_hash: observed_value_hash.to_string(),
        observed_at,
    };
    let canonical =
        oag_core::canonical_json_bytes(&unsigned).map_err(|e| ClaimReportError::Internal(e.to_string()))?;
    let signature = sign_with_domain(identity.signing_key(), CLAIM_REPORT_DOMAIN, &canonical);
    Ok(ClaimReport { unsigned, signature: hex::encode(signature.to_bytes()) })
}

/// Verifies `(peer_id, public_key)` pairing, the Ed25519 signature, and timestamp freshness --
/// the same three checks every signed message in this crate makes, nothing more. Does **not**
/// check whether `reporter_cluster` is real, whether this peer is actually a member of it, or
/// anything about corroboration -- see `ClaimCorroboration` for that, a strictly separate step.
pub fn verify(report: &ClaimReport, now: i64) -> Result<PeerId, ClaimReportError> {
    let peer_id: PeerId = report.unsigned.peer_id.parse()?;
    let pk_bytes = decode_32(&report.unsigned.public_key).ok_or(ClaimReportError::InvalidPublicKey)?;
    let verifying_key = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| ClaimReportError::InvalidPublicKey)?;
    if peer_id != PeerId::from_public_key(&verifying_key) {
        return Err(ClaimReportError::PeerIdKeyMismatch);
    }

    let canonical =
        oag_core::canonical_json_bytes(&report.unsigned).map_err(|e| ClaimReportError::Internal(e.to_string()))?;
    let sig_bytes = decode_64(&report.signature).ok_or(ClaimReportError::BadSignatureEncoding)?;
    let signature = Signature::from_bytes(&sig_bytes);
    verify_with_domain(&verifying_key, CLAIM_REPORT_DOMAIN, &canonical, &signature)
        .map_err(|_| ClaimReportError::BadSignature)?;

    if (report.unsigned.observed_at - now).abs() > MAX_CLOCK_SKEW_SECONDS {
        return Err(ClaimReportError::ClockSkew);
    }

    Ok(peer_id)
}

/// A verified report, reduced to what `ClaimCorroboration` needs to aggregate -- kept separate
/// from `ClaimReport` itself so storage doesn't need to re-verify a signature on every read.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordedReport {
    peer_id: PeerId,
    reporter_cluster: String,
    observed_value_hash: String,
}

/// The result of aggregating every verified report for one `claim_id`: the value the most
/// distinct clusters agree on, how many distinct clusters that is, and how many distinct peers
/// (which may double- or triple-count a cluster if several of its peers reported) that is.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClaimAgreement {
    pub observed_value_hash: String,
    pub distinct_clusters: usize,
    pub distinct_peers: usize,
}

/// The result of `ClaimCorroboration::best_corroborated_value_cross_checked` -- the same kind
/// of `ClaimAgreement` `best_corroborated_value` would return, but computed only from reports
/// whose `reporter_cluster` is attested in a `bridge::MeshTree`, plus how many reports were
/// dropped for failing that check. `best` is `None` exactly when every report recorded for the
/// claim got dropped by the cross-check -- in which case `reports_dropped_unattested_cluster`
/// is always greater than `0`, since a claim with zero reports ever recorded returns `None`
/// from the method itself rather than `Some(CrossCheckedAgreement { best: None, .. })`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrossCheckedAgreement {
    pub best: Option<ClaimAgreement>,
    pub reports_dropped_unattested_cluster: usize,
}

/// Collects verified `ClaimReport`s, grouped by `claim_id`, and aggregates them weighted by
/// distinct reporting *cluster* -- the mechanism-level answer to `spec/01-overview.md`'s "what
/// counts as independent enough" question: two reports from the same self-asserted cluster
/// corroborate each other no more than one report alone does.
#[derive(Debug, Default)]
pub struct ClaimCorroboration {
    reports: HashMap<String, Vec<RecordedReport>>,
}

impl ClaimCorroboration {
    pub fn new() -> Self {
        Self::default()
    }

    /// The proof-of-work difficulty a `ClaimReport` for `(claim_id, reporter_cluster)` must
    /// currently meet, per `difficulty_bits_for_new_cluster_number`. **Free (`0` bits, always
    /// satisfied) if `reporter_cluster` has already reported for `claim_id` at all** -- a repeat
    /// report from an already-counted cluster (the same peer, or a different peer within that
    /// same self-asserted cluster) does not increase `distinct_clusters`, so there is nothing to
    /// tax. Otherwise, the cost of becoming the next *new* distinct cluster on this claim, scaled
    /// by how many distinct clusters already corroborate it. A submitting client should call this
    /// before spending work solving a `ClaimReportProofOfWork`.
    pub fn required_difficulty_bits(&self, claim_id: &str, reporter_cluster: &str) -> u32 {
        let Some(reports) = self.reports.get(claim_id) else {
            return BASE_CLAIM_REPORT_DIFFICULTY_BITS;
        };
        if reports.iter().any(|r| r.reporter_cluster == reporter_cluster) {
            return 0;
        }
        let distinct_clusters = reports.iter().map(|r| r.reporter_cluster.as_str()).collect::<HashSet<_>>().len();
        difficulty_bits_for_new_cluster_number(distinct_clusters)
    }

    /// Verifies `report`, checks `pow` against `required_difficulty_bits` for this report's
    /// `(claim_id, reporter_cluster)` *at the moment this is called* (the escalation means this
    /// must happen here, inside the struct, not in a standalone validation function -- only this
    /// struct knows how many distinct clusters already corroborate the claim), and if both pass,
    /// records it. A peer re-reporting the same `(claim_id, observed_value_hash)` more than once
    /// does not inflate anything further -- see `best_corroborated_value`'s distinct-peer/
    /// distinct-cluster counting, which deduplicates by peer regardless of how many times that
    /// peer reported the same value.
    pub fn add(&mut self, report: &ClaimReport, pow: ClaimReportProofOfWork, now: i64) -> Result<PeerId, ClaimReportError> {
        let peer_id = verify(report, now)?;
        let required_bits = self.required_difficulty_bits(&report.unsigned.claim_id, &report.unsigned.reporter_cluster);
        if !pow.satisfies(&report.unsigned, required_bits) {
            return Err(ClaimReportError::InsufficientProofOfWork { required_bits });
        }
        self.reports.entry(report.unsigned.claim_id.clone()).or_default().push(RecordedReport {
            peer_id,
            reporter_cluster: report.unsigned.reporter_cluster.clone(),
            observed_value_hash: report.unsigned.observed_value_hash.clone(),
        });
        Ok(peer_id)
    }

    /// Groups every report recorded for `claim_id` by `observed_value_hash`, counts the number
    /// of *distinct clusters* and *distinct peers* behind each value (deduplicated -- the same
    /// peer, or the same cluster via several of its peers, reporting the same value repeatedly
    /// counts once), and returns the value with the most distinct corroborating clusters
    /// (ties broken by distinct peer count, then arbitrarily). `None` if nothing has been
    /// reported for this claim at all.
    pub fn best_corroborated_value(&self, claim_id: &str) -> Option<ClaimAgreement> {
        let reports = self.reports.get(claim_id)?;
        let mut by_value: HashMap<&str, (HashSet<&str>, HashSet<PeerId>)> = HashMap::new();
        for r in reports {
            let entry = by_value.entry(&r.observed_value_hash).or_default();
            entry.0.insert(&r.reporter_cluster);
            entry.1.insert(r.peer_id);
        }
        by_value
            .into_iter()
            .map(|(value, (clusters, peers))| ClaimAgreement {
                observed_value_hash: value.to_string(),
                distinct_clusters: clusters.len(),
                distinct_peers: peers.len(),
            })
            .max_by_key(|agreement| (agreement.distinct_clusters, agreement.distinct_peers))
    }

    /// Like `best_corroborated_value`, but first drops every recorded report whose self-asserted
    /// `reporter_cluster` is not attested anywhere in `mesh_tree` as a real base-layer cluster
    /// (`bridge::MeshTree::is_attested_base_cluster`, requiring at least
    /// `min_bridge_corroboration` distinct `BridgeDeclaration`s). This closes half of
    /// `spec/05-federated-corroboration.md`'s "no cross-check against real cluster nesting" gap:
    /// a report claiming a cluster name that was never attested by any bridge declaration no
    /// longer counts toward corroboration at all.
    ///
    /// It does **not** close the other half. Nothing in this crate -- not `BridgeDeclaration`,
    /// not anything else -- records which peers actually belong to a given base-layer cluster;
    /// a `BridgeDeclaration` only ever asserts that a cluster *name* is nested under some
    /// mesh-group, signed by whichever peer felt like asserting it, not by every member of that
    /// cluster. So a reporting peer that picks a real, attested cluster name it has no actual
    /// standing in still passes this check. Fully closing that gap would need a new kind of
    /// signed fact this crate doesn't have yet -- something like "I attest peer X is a genuine
    /// member of cluster C," itself signed by other members of C -- which is a real, separate,
    /// unbuilt mechanism, not a refinement of this one.
    ///
    /// Returns `None` only if nothing has ever been reported for `claim_id` at all (same as
    /// `best_corroborated_value`). If every report for a known `claim_id` gets dropped for an
    /// unattested cluster claim, returns `Some` with `best: None` and a non-zero
    /// `reports_dropped_unattested_cluster`, so a caller can tell "nothing survived the
    /// cross-check" apart from "nothing was ever reported."
    pub fn best_corroborated_value_cross_checked(
        &self,
        claim_id: &str,
        mesh_tree: &MeshTree,
        min_bridge_corroboration: usize,
    ) -> Option<CrossCheckedAgreement> {
        let reports = self.reports.get(claim_id)?;
        let mut by_value: HashMap<&str, (HashSet<&str>, HashSet<PeerId>)> = HashMap::new();
        let mut reports_dropped_unattested_cluster = 0usize;
        for r in reports {
            if !mesh_tree.is_attested_base_cluster(&r.reporter_cluster, min_bridge_corroboration) {
                reports_dropped_unattested_cluster += 1;
                continue;
            }
            let entry = by_value.entry(&r.observed_value_hash).or_default();
            entry.0.insert(&r.reporter_cluster);
            entry.1.insert(r.peer_id);
        }
        let best = by_value
            .into_iter()
            .map(|(value, (clusters, peers))| ClaimAgreement {
                observed_value_hash: value.to_string(),
                distinct_clusters: clusters.len(),
                distinct_peers: peers.len(),
            })
            .max_by_key(|agreement| (agreement.distinct_clusters, agreement.distinct_peers));
        Some(CrossCheckedAgreement { best, reports_dropped_unattested_cluster })
    }

    /// The distinct-cluster corroboration count for one specific `(claim_id,
    /// observed_value_hash)` pair -- `0` if nothing matches.
    pub fn cluster_corroboration_for(&self, claim_id: &str, observed_value_hash: &str) -> usize {
        self.reports
            .get(claim_id)
            .map(|reports| {
                reports
                    .iter()
                    .filter(|r| r.observed_value_hash == observed_value_hash)
                    .map(|r| r.reporter_cluster.as_str())
                    .collect::<HashSet<_>>()
                    .len()
            })
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> i64 {
        1_700_000_000
    }

    /// Solves whatever proof-of-work `corroboration` currently requires for `report`'s
    /// `(claim_id, reporter_cluster)`, then adds it -- the test-side equivalent of a real client
    /// calling `required_difficulty_bits` before submitting (mirrors `anonymous_event.rs`'s own
    /// `record_with_fresh_pow` test helper).
    fn add_with_fresh_pow(
        corroboration: &mut ClaimCorroboration,
        report: &ClaimReport,
        now: i64,
    ) -> Result<PeerId, ClaimReportError> {
        let required = corroboration.required_difficulty_bits(&report.unsigned.claim_id, &report.unsigned.reporter_cluster);
        let pow = ClaimReportProofOfWork::solve(&report.unsigned, required);
        corroboration.add(report, pow, now)
    }

    #[test]
    fn report_sign_and_verify_round_trip() {
        let identity = PeerIdentity::generate();
        let report = build_and_sign(&identity, "https://example.com/page", "cluster-a", "blake3:abc", now()).unwrap();
        let peer_id = verify(&report, now() + 10).unwrap();
        assert_eq!(peer_id, identity.peer_id());
    }

    #[test]
    fn tampered_observed_value_fails_verification() {
        let identity = PeerIdentity::generate();
        let mut report =
            build_and_sign(&identity, "https://example.com/page", "cluster-a", "blake3:abc", now()).unwrap();
        report.unsigned.observed_value_hash = "blake3:tampered".to_string();
        assert!(matches!(verify(&report, now() + 10), Err(ClaimReportError::BadSignature)));
    }

    #[test]
    fn mismatched_peer_id_and_public_key_is_rejected() {
        let victim = PeerIdentity::generate();
        let attacker = PeerIdentity::generate();
        let mut report = build_and_sign(&victim, "claim-1", "cluster-a", "blake3:abc", now()).unwrap();
        report.unsigned.public_key = hex::encode(attacker.verifying_key().to_bytes());
        let canonical = oag_core::canonical_json_bytes(&report.unsigned).unwrap();
        let sig = sign_with_domain(attacker.signing_key(), CLAIM_REPORT_DOMAIN, &canonical);
        report.signature = hex::encode(sig.to_bytes());
        assert!(matches!(verify(&report, now() + 10), Err(ClaimReportError::PeerIdKeyMismatch)));
    }

    #[test]
    fn stale_timestamp_is_rejected() {
        let identity = PeerIdentity::generate();
        let report = build_and_sign(&identity, "claim-1", "cluster-a", "blake3:abc", now()).unwrap();
        assert!(matches!(
            verify(&report, now() + MAX_CLOCK_SKEW_SECONDS + 1),
            Err(ClaimReportError::ClockSkew)
        ));
    }

    #[test]
    fn two_reports_from_the_same_cluster_count_as_one_cluster() {
        let peer_a1 = PeerIdentity::generate();
        let peer_a2 = PeerIdentity::generate();
        let mut corroboration = ClaimCorroboration::new();

        add_with_fresh_pow(&mut corroboration, &build_and_sign(&peer_a1, "claim-1", "cluster-a", "blake3:abc", now()).unwrap(), now())
            .unwrap();
        add_with_fresh_pow(&mut corroboration, &build_and_sign(&peer_a2, "claim-1", "cluster-a", "blake3:abc", now()).unwrap(), now())
            .unwrap();

        // Two different peers, but the same self-asserted cluster -- one cluster's worth of
        // corroboration, not two.
        assert_eq!(corroboration.cluster_corroboration_for("claim-1", "blake3:abc"), 1);
        let best = corroboration.best_corroborated_value("claim-1").unwrap();
        assert_eq!(best.distinct_clusters, 1);
        assert_eq!(best.distinct_peers, 2);
    }

    #[test]
    fn reports_from_different_clusters_corroborate_more_strongly() {
        let peer_a = PeerIdentity::generate();
        let peer_b = PeerIdentity::generate();
        let peer_c = PeerIdentity::generate();
        let mut corroboration = ClaimCorroboration::new();

        add_with_fresh_pow(&mut corroboration, &build_and_sign(&peer_a, "claim-1", "cluster-a", "blake3:abc", now()).unwrap(), now()).unwrap();
        add_with_fresh_pow(&mut corroboration, &build_and_sign(&peer_b, "claim-1", "cluster-b", "blake3:abc", now()).unwrap(), now()).unwrap();
        // A lone dissenting report from a third cluster, on a different value -- must not win.
        add_with_fresh_pow(&mut corroboration, &build_and_sign(&peer_c, "claim-1", "cluster-c", "blake3:xyz", now()).unwrap(), now()).unwrap();

        assert_eq!(corroboration.cluster_corroboration_for("claim-1", "blake3:abc"), 2);
        assert_eq!(corroboration.cluster_corroboration_for("claim-1", "blake3:xyz"), 1);

        let best = corroboration.best_corroborated_value("claim-1").unwrap();
        assert_eq!(best.observed_value_hash, "blake3:abc");
        assert_eq!(best.distinct_clusters, 2);
    }

    #[test]
    fn a_peer_re_reporting_the_same_value_does_not_inflate_its_own_count() {
        let peer_a = PeerIdentity::generate();
        let mut corroboration = ClaimCorroboration::new();

        add_with_fresh_pow(&mut corroboration, &build_and_sign(&peer_a, "claim-1", "cluster-a", "blake3:abc", now()).unwrap(), now()).unwrap();
        add_with_fresh_pow(
            &mut corroboration,
            &build_and_sign(&peer_a, "claim-1", "cluster-a", "blake3:abc", now() + 1).unwrap(),
            now() + 1,
        )
        .unwrap();

        let best = corroboration.best_corroborated_value("claim-1").unwrap();
        assert_eq!(best.distinct_peers, 1);
        assert_eq!(best.distinct_clusters, 1);
    }

    #[test]
    fn an_unknown_claim_has_no_best_value() {
        let corroboration = ClaimCorroboration::new();
        assert!(corroboration.best_corroborated_value("never-reported").is_none());
        assert_eq!(corroboration.cluster_corroboration_for("never-reported", "blake3:abc"), 0);
    }

    #[test]
    fn cross_check_drops_reports_claiming_an_unattested_cluster() {
        use crate::bridge::{self, MeshMember};

        let peer_a = PeerIdentity::generate();
        let peer_b = PeerIdentity::generate();
        let bridge_signer = PeerIdentity::generate();
        let mut corroboration = ClaimCorroboration::new();
        let mut tree = bridge::MeshTree::new();

        // Only "cluster-a" is ever attested by a real BridgeDeclaration.
        tree.add(
            &bridge::build_and_sign(&bridge_signer, "global", MeshMember::BaseCluster("cluster-a".into()), now())
                .unwrap(),
            now(),
        )
        .unwrap();

        add_with_fresh_pow(&mut corroboration, &build_and_sign(&peer_a, "claim-1", "cluster-a", "blake3:abc", now()).unwrap(), now()).unwrap();
        // cluster-b is never attested anywhere in the tree -- a fabricated cluster claim.
        add_with_fresh_pow(&mut corroboration, &build_and_sign(&peer_b, "claim-1", "cluster-b", "blake3:abc", now()).unwrap(), now()).unwrap();

        // Without the cross-check, both reports count -- two distinct clusters.
        let uncross_checked = corroboration.best_corroborated_value("claim-1").unwrap();
        assert_eq!(uncross_checked.distinct_clusters, 2);

        // With the cross-check, only cluster-a's report survives.
        let cross_checked = corroboration.best_corroborated_value_cross_checked("claim-1", &tree, 1).unwrap();
        let best = cross_checked.best.unwrap();
        assert_eq!(best.distinct_clusters, 1);
        assert_eq!(best.distinct_peers, 1);
        assert_eq!(cross_checked.reports_dropped_unattested_cluster, 1);
    }

    #[test]
    fn cross_check_returns_none_best_when_every_report_is_unattested() {
        use crate::bridge;

        let peer_a = PeerIdentity::generate();
        let mut corroboration = ClaimCorroboration::new();
        let empty_tree = bridge::MeshTree::new();

        add_with_fresh_pow(&mut corroboration, &build_and_sign(&peer_a, "claim-1", "cluster-a", "blake3:abc", now()).unwrap(), now()).unwrap();

        let cross_checked = corroboration.best_corroborated_value_cross_checked("claim-1", &empty_tree, 1).unwrap();
        assert!(cross_checked.best.is_none());
        assert_eq!(cross_checked.reports_dropped_unattested_cluster, 1);
    }

    #[test]
    fn cross_check_against_an_unknown_claim_returns_none() {
        use crate::bridge;

        let corroboration = ClaimCorroboration::new();
        let empty_tree = bridge::MeshTree::new();
        assert!(corroboration
            .best_corroborated_value_cross_checked("never-reported", &empty_tree, 1)
            .is_none());
    }

    #[test]
    fn an_invalid_report_is_never_recorded() {
        let identity = PeerIdentity::generate();
        let mut report = build_and_sign(&identity, "claim-1", "cluster-a", "blake3:abc", now()).unwrap();
        report.unsigned.claim_id = "tampered".to_string();
        let mut corroboration = ClaimCorroboration::new();
        // A tampered report fails signature verification before proof-of-work is even checked,
        // so an unsolved (zero) nonce is fine here -- it must never be reached.
        assert!(corroboration.add(&report, ClaimReportProofOfWork { nonce: 0 }, now()).is_err());
        assert_eq!(corroboration.cluster_corroboration_for("tampered", "blake3:abc"), 0);
    }

    #[test]
    fn a_report_with_no_proof_of_work_is_rejected() {
        let identity = PeerIdentity::generate();
        let report = build_and_sign(&identity, "claim-pow-test", "cluster-a", "blake3:abc", now()).unwrap();
        let mut corroboration = ClaimCorroboration::new();
        // Difficulty 0 is never a real solution against BASE_CLAIM_REPORT_DIFFICULTY_BITS = 16
        // for a brand-new claim/cluster pair.
        let err = corroboration.add(&report, ClaimReportProofOfWork { nonce: 0 }, now()).unwrap_err();
        assert!(matches!(
            err,
            ClaimReportError::InsufficientProofOfWork { required_bits } if required_bits == BASE_CLAIM_REPORT_DIFFICULTY_BITS
        ));
        assert_eq!(corroboration.cluster_corroboration_for("claim-pow-test", "blake3:abc"), 0);
    }

    #[test]
    fn a_second_report_from_an_already_counted_cluster_requires_no_proof_of_work() {
        let peer_a1 = PeerIdentity::generate();
        let peer_a2 = PeerIdentity::generate();
        let mut corroboration = ClaimCorroboration::new();

        add_with_fresh_pow(&mut corroboration, &build_and_sign(&peer_a1, "claim-1", "cluster-a", "blake3:abc", now()).unwrap(), now()).unwrap();
        // A second peer, but the SAME already-counted cluster -- required difficulty is 0, so
        // even a completely unsolved proof is accepted.
        assert_eq!(corroboration.required_difficulty_bits("claim-1", "cluster-a"), 0);
        let report = build_and_sign(&peer_a2, "claim-1", "cluster-a", "blake3:abc", now()).unwrap();
        corroboration.add(&report, ClaimReportProofOfWork { nonce: 0 }, now()).unwrap();
        assert_eq!(corroboration.cluster_corroboration_for("claim-1", "blake3:abc"), 1);
    }

    #[test]
    fn required_difficulty_escalates_with_each_additional_distinct_cluster_on_one_claim() {
        let peer_a = PeerIdentity::generate();
        let peer_b = PeerIdentity::generate();
        let mut corroboration = ClaimCorroboration::new();

        assert_eq!(corroboration.required_difficulty_bits("claim-1", "cluster-a"), BASE_CLAIM_REPORT_DIFFICULTY_BITS);

        add_with_fresh_pow(&mut corroboration, &build_and_sign(&peer_a, "claim-1", "cluster-a", "blake3:abc", now()).unwrap(), now()).unwrap();
        // A brand-new cluster now costs one extra step -- one distinct cluster already exists.
        assert_eq!(
            corroboration.required_difficulty_bits("claim-1", "cluster-b"),
            BASE_CLAIM_REPORT_DIFFICULTY_BITS + CLAIM_REPORT_DIFFICULTY_STEP_BITS
        );

        // A stale proof solved at the base difficulty is no longer enough for this new cluster.
        let report_b = build_and_sign(&peer_b, "claim-1", "cluster-b", "blake3:abc", now()).unwrap();
        let stale_pow = ClaimReportProofOfWork::solve(&report_b.unsigned, BASE_CLAIM_REPORT_DIFFICULTY_BITS);
        let err = corroboration.add(&report_b, stale_pow, now()).unwrap_err();
        let expected_bits = BASE_CLAIM_REPORT_DIFFICULTY_BITS + CLAIM_REPORT_DIFFICULTY_STEP_BITS;
        assert!(matches!(err, ClaimReportError::InsufficientProofOfWork { required_bits } if required_bits == expected_bits));
    }

    #[test]
    fn a_claim_report_proof_of_work_is_bound_to_its_own_report_and_cannot_be_reused() {
        let peer_a = PeerIdentity::generate();
        let peer_b = PeerIdentity::generate();
        let report_a = build_and_sign(&peer_a, "claim-1", "cluster-a", "blake3:abc", now()).unwrap();
        let report_b = build_and_sign(&peer_b, "claim-1", "cluster-b", "blake3:abc", now()).unwrap();
        let pow_for_a = ClaimReportProofOfWork::solve(&report_a.unsigned, BASE_CLAIM_REPORT_DIFFICULTY_BITS);

        let mut corroboration = ClaimCorroboration::new();
        // Reusing report_a's proof for report_b's (different peer/cluster) must not satisfy it.
        let err = corroboration.add(&report_b, pow_for_a, now()).unwrap_err();
        assert!(matches!(
            err,
            ClaimReportError::InsufficientProofOfWork { required_bits } if required_bits == BASE_CLAIM_REPORT_DIFFICULTY_BITS
        ));
    }
}
