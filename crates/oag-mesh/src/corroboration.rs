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
    #[error("internal error: {0}")]
    Internal(String),
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

    /// Verifies `report` and, if valid, records it. A peer re-reporting the same
    /// `(claim_id, observed_value_hash)` more than once does not inflate anything further --
    /// see `best_corroborated_value`'s distinct-peer/distinct-cluster counting, which
    /// deduplicates by peer regardless of how many times that peer reported the same value.
    pub fn add(&mut self, report: &ClaimReport, now: i64) -> Result<PeerId, ClaimReportError> {
        let peer_id = verify(report, now)?;
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

        corroboration
            .add(&build_and_sign(&peer_a1, "claim-1", "cluster-a", "blake3:abc", now()).unwrap(), now())
            .unwrap();
        corroboration
            .add(&build_and_sign(&peer_a2, "claim-1", "cluster-a", "blake3:abc", now()).unwrap(), now())
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

        corroboration.add(&build_and_sign(&peer_a, "claim-1", "cluster-a", "blake3:abc", now()).unwrap(), now()).unwrap();
        corroboration.add(&build_and_sign(&peer_b, "claim-1", "cluster-b", "blake3:abc", now()).unwrap(), now()).unwrap();
        // A lone dissenting report from a third cluster, on a different value -- must not win.
        corroboration.add(&build_and_sign(&peer_c, "claim-1", "cluster-c", "blake3:xyz", now()).unwrap(), now()).unwrap();

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

        corroboration.add(&build_and_sign(&peer_a, "claim-1", "cluster-a", "blake3:abc", now()).unwrap(), now()).unwrap();
        corroboration
            .add(&build_and_sign(&peer_a, "claim-1", "cluster-a", "blake3:abc", now() + 1).unwrap(), now() + 1)
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

        corroboration.add(&build_and_sign(&peer_a, "claim-1", "cluster-a", "blake3:abc", now()).unwrap(), now()).unwrap();
        // cluster-b is never attested anywhere in the tree -- a fabricated cluster claim.
        corroboration.add(&build_and_sign(&peer_b, "claim-1", "cluster-b", "blake3:abc", now()).unwrap(), now()).unwrap();

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

        corroboration.add(&build_and_sign(&peer_a, "claim-1", "cluster-a", "blake3:abc", now()).unwrap(), now()).unwrap();

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
        assert!(corroboration.add(&report, now()).is_err());
        assert_eq!(corroboration.cluster_corroboration_for("tampered", "blake3:abc"), 0);
    }
}
