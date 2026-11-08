//! Responder acknowledgments -- the one piece of `spec/11-responder-search.md`'s own "what this
//! explicitly is not" section this crate now answers: "no claim-to-avoid-duplicate-response."
//! A responder who finds a relevant event via `anonymous_event::AnonymousEventLog::search` can
//! sign a `ResponderAcknowledgment` ("I am handling the event at this `corroboration_nonce`"),
//! so another responder running the same search sees it's already being handled before
//! duplicating the effort.
//!
//! **Why this one carries a real signed identity, unlike `AnonymousEvent`.** The anonymity
//! constraint on `anonymous_event.rs`'s own schema exists to protect the *reporter* -- someone
//! who may be in danger, or reporting on someone else's behalf, and whose identity or precise
//! location is itself sensitive. A responder is the opposite case: an organization or individual
//! choosing to act, not a vulnerable party being reported on or about. Nothing about "who is
//! responding to this" needs the same protection "who is reporting this" does, so this reuses
//! the same `oag_crypto::PeerIdentity` every other signed mechanism in this crate does, under
//! its own domain string -- the same accountability trade-off `bridge::BridgeDeclaration` makes.
//!
//! **Deliberately carries no proof-of-work, unlike every other signed mechanism here.** Every
//! other mechanism's proof-of-work taxes the cost of inflating a *corroboration count* --
//! becoming a new distinct peer/cluster/attester. An acknowledgment has no such count to
//! protect: more identities claiming to handle the same event isn't a signal worth more trust,
//! it's just noise, so there's nothing proportionate to escalate difficulty against. Requiring
//! proof-of-work here would also actively work against this mechanism's purpose -- slowing down
//! a genuine responder's ability to claim a life-safety event they're about to act on, in
//! exchange for protection against a threat (fake acknowledgments) proof-of-work can't actually
//! stop anyway (see "What this explicitly is not" below). The only protection here is a signed
//! identity's accountability, same as `bridge::BridgeDeclaration`'s own pre-proof-of-work
//! posture, with the identical caveat that accountability is only as strong as whatever
//! real-world consequence, outside this protocol, following a bad-faith `PeerIdentity` later.

use std::collections::HashMap;

use oag_crypto::{sign_with_domain, verify_with_domain, PeerId, PeerIdentity, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const RESPONDER_ACKNOWLEDGMENT_DOMAIN: &str = "OAG-MESH:RESPONDER_ACKNOWLEDGMENT:v1:";

/// Same tolerance every other signed message in this crate uses.
pub const MAX_CLOCK_SKEW_SECONDS: i64 = 300;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedResponderAcknowledgment {
    pub responder_peer_id: String,
    /// Hex-encoded Ed25519 public key -- same convention every other signed message in this
    /// crate uses.
    pub responder_public_key: String,
    /// The event being acknowledged, identified by its `corroboration_nonce` -- the stable value
    /// shared across every independent report of the same real event, not any one report's
    /// random `event_id`. Not checked against any `AnonymousEventLog` at verify time; same
    /// "verify doesn't check cross-references" posture as every other mechanism here (a
    /// `ClaimReport`'s `claim_id`, a `BridgeDeclaration`'s cluster name) -- acknowledging a
    /// nonce that no event ever used is accepted as structurally valid, just useless.
    pub corroboration_nonce: String,
    /// `true` to claim "I am handling this"; `false` to stand down from a claim made earlier.
    /// There is no separate "retract" message type -- a responder signs a fresh acknowledgment
    /// with `active: false` instead, same "latest signed statement wins" shape `ResponderAcknowledgmentLog::add`
    /// implements.
    pub active: bool,
    pub acknowledged_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponderAcknowledgment {
    #[serde(flatten)]
    pub unsigned: UnsignedResponderAcknowledgment,
    pub signature: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ResponderAcknowledgmentError {
    #[error("invalid responder peer id: {0}")]
    PeerId(#[from] oag_crypto::PeerIdParseError),
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("responder_peer_id does not match the derived hash of responder_public_key")]
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

/// Sign an acknowledgment for `corroboration_nonce`. Takes `timestamp` explicitly (rather than
/// reading the clock itself) so tests can exercise `verify`'s clock-skew check deterministically
/// -- same reasoning as every signed-message constructor in this crate.
pub fn build_and_sign(
    responder: &PeerIdentity,
    corroboration_nonce: &str,
    active: bool,
    timestamp: i64,
) -> Result<ResponderAcknowledgment, ResponderAcknowledgmentError> {
    let unsigned = UnsignedResponderAcknowledgment {
        responder_peer_id: responder.peer_id().to_string(),
        responder_public_key: hex::encode(responder.verifying_key().to_bytes()),
        corroboration_nonce: corroboration_nonce.to_string(),
        active,
        acknowledged_at: timestamp,
    };
    let canonical = oag_core::canonical_json_bytes(&unsigned)
        .map_err(|e| ResponderAcknowledgmentError::Internal(e.to_string()))?;
    let signature = sign_with_domain(responder.signing_key(), RESPONDER_ACKNOWLEDGMENT_DOMAIN, &canonical);
    Ok(ResponderAcknowledgment { unsigned, signature: hex::encode(signature.to_bytes()) })
}

/// Verifies an acknowledgment's `(responder_peer_id, responder_public_key)` pairing, its Ed25519
/// signature, and timestamp freshness -- the same three checks every signed message in this
/// crate makes, nothing more. Does **not** check whether `corroboration_nonce` corresponds to
/// any real event, or anything about who else has acknowledged it -- see
/// `ResponderAcknowledgmentLog` for that, a strictly separate step.
pub fn verify(ack: &ResponderAcknowledgment, now: i64) -> Result<PeerId, ResponderAcknowledgmentError> {
    let peer_id: PeerId = ack.unsigned.responder_peer_id.parse()?;
    let pk_bytes =
        decode_32(&ack.unsigned.responder_public_key).ok_or(ResponderAcknowledgmentError::InvalidPublicKey)?;
    let verifying_key = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| ResponderAcknowledgmentError::InvalidPublicKey)?;
    if peer_id != PeerId::from_public_key(&verifying_key) {
        return Err(ResponderAcknowledgmentError::PeerIdKeyMismatch);
    }

    let canonical = oag_core::canonical_json_bytes(&ack.unsigned)
        .map_err(|e| ResponderAcknowledgmentError::Internal(e.to_string()))?;
    let sig_bytes = decode_64(&ack.signature).ok_or(ResponderAcknowledgmentError::BadSignatureEncoding)?;
    let signature = Signature::from_bytes(&sig_bytes);
    verify_with_domain(&verifying_key, RESPONDER_ACKNOWLEDGMENT_DOMAIN, &canonical, &signature)
        .map_err(|_| ResponderAcknowledgmentError::BadSignature)?;

    if (ack.unsigned.acknowledged_at - now).abs() > MAX_CLOCK_SKEW_SECONDS {
        return Err(ResponderAcknowledgmentError::ClockSkew);
    }

    Ok(peer_id)
}

/// A verified acknowledgment, reduced to what the log needs to keep -- kept separate from
/// `ResponderAcknowledgment` itself so storage doesn't need to re-verify a signature on every
/// read, same reasoning as `corroboration::RecordedReport`.
#[derive(Debug, Clone)]
struct RecordedAcknowledgment {
    active: bool,
    acknowledged_at: i64,
}

/// Collects verified acknowledgments, keyed by `(corroboration_nonce, responder_peer_id)`, one
/// per responder per event -- a responder re-acknowledging the same event replaces its own prior
/// acknowledgment rather than adding a second one, since there's nothing to corroborate here
/// (see this module's own top-level doc comment for why counting distinct responders would be
/// noise, not signal).
#[derive(Debug, Default)]
pub struct ResponderAcknowledgmentLog {
    acknowledgments: HashMap<String, HashMap<PeerId, RecordedAcknowledgment>>,
    /// Monotonic version, bumped whenever `acknowledgments` actually changes -- the heads check
    /// in `transport::pull_and_merge`; see `spec/10-anti-entropy.md`.
    sequence: u64,
}

impl ResponderAcknowledgmentLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Verifies `ack`, and if it passes, records it -- replacing this responder's own prior
    /// acknowledgment for this `corroboration_nonce` only if `ack.unsigned.acknowledged_at` is at
    /// least as recent as what's already recorded, so a stale, out-of-order delivery (e.g. a
    /// retried push that arrives after a newer one already landed) can't silently undo a more
    /// recent stand-down or re-claim. Returns the responder's `PeerId` on success.
    pub fn add(&mut self, ack: &ResponderAcknowledgment, now: i64) -> Result<PeerId, ResponderAcknowledgmentError> {
        let peer_id = verify(ack, now)?;
        self.add_verified(ack, peer_id);
        Ok(peer_id)
    }

    /// Records an already-verified acknowledgment. The transport handler verifies once, checks
    /// the per-identity rate limit, then calls this -- so a submission is never verified twice.
    pub fn add_verified(&mut self, ack: &ResponderAcknowledgment, peer_id: PeerId) {
        let entry = self.acknowledgments.entry(ack.unsigned.corroboration_nonce.clone()).or_default();
        let candidate = RecordedAcknowledgment { active: ack.unsigned.active, acknowledged_at: ack.unsigned.acknowledged_at };
        match entry.get(&peer_id) {
            Some(existing) if existing.acknowledged_at > candidate.acknowledged_at => {
                // A newer acknowledgment from this same responder already exists -- ignore the
                // stale one rather than regressing state.
            }
            _ => {
                entry.insert(peer_id, candidate);
                self.sequence += 1;
            }
        }
    }

    /// The current version stamp for the heads check -- see `transport::pull_and_merge` and
    /// `spec/10-anti-entropy.md`.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Every responder currently claiming to handle `corroboration_nonce` (`active == true` in
    /// their most recent acknowledgment) -- the one query this mechanism exists to answer:
    /// "is someone already on this?" **Advisory only** -- see this module's own top-level doc
    /// comment and "What this explicitly is not" below for why a `true` result here is a claim,
    /// not a guarantee that real action is actually happening.
    pub fn active_responders_for(&self, corroboration_nonce: &str) -> Vec<PeerId> {
        self.acknowledgments
            .get(corroboration_nonce)
            .map(|by_peer| by_peer.iter().filter(|(_, rec)| rec.active).map(|(peer_id, _)| *peer_id).collect())
            .unwrap_or_default()
    }

    /// A persistable snapshot of every acknowledgment this log currently holds. `PeerId` has no
    /// `Serialize`/`Deserialize` of its own, so it round-trips through its `Display`/`FromStr`
    /// string form -- same convention every other store in this crate already uses. See
    /// `ResponderAcknowledgmentLog::from_snapshot` for the inverse.
    pub fn snapshot(&self) -> Vec<ResponderAcknowledgmentSnapshot> {
        self.acknowledgments
            .iter()
            .map(|(nonce, by_peer)| ResponderAcknowledgmentSnapshot {
                corroboration_nonce: nonce.clone(),
                acknowledgments: by_peer
                    .iter()
                    .map(|(peer_id, rec)| RecordedAcknowledgmentSnapshot {
                        responder_peer_id: peer_id.to_string(),
                        active: rec.active,
                        acknowledged_at: rec.acknowledged_at,
                    })
                    .collect(),
            })
            .collect()
    }

    /// Rebuilds a `ResponderAcknowledgmentLog` from `snapshot` (e.g. loaded from disk via
    /// `persistence::load_json`). A peer id string that fails to parse is dropped with a
    /// `tracing::warn!` rather than failing the whole load -- same posture as every other
    /// `from_snapshot` in this crate.
    pub fn from_snapshot(snapshot: Vec<ResponderAcknowledgmentSnapshot>) -> Self {
        let mut log = Self::new();
        log.merge_snapshot(snapshot);
        log
    }

    /// Merges `snapshot` into this log's existing acknowledgments -- per `(corroboration_nonce,
    /// responder_peer_id)`, keeping whichever of the existing and incoming entries has the more
    /// recent `acknowledged_at`, same freshness rule `add` applies. The building block for
    /// `transport::pull_and_merge`'s pull-based anti-entropy (`spec/10-anti-entropy.md`). Same
    /// trust note as every other `merge_snapshot` in this crate: no signature is re-checked here,
    /// because a snapshot has already collapsed past the original signed
    /// `ResponderAcknowledgment` -- merging trusts the source peer's own prior verification.
    pub fn merge_snapshot(&mut self, snapshot: Vec<ResponderAcknowledgmentSnapshot>) -> bool {
        let mut changed = false;
        for entry in snapshot {
            let by_peer = self.acknowledgments.entry(entry.corroboration_nonce).or_default();
            for rec in entry.acknowledgments {
                let peer_id: PeerId = match rec.responder_peer_id.parse() {
                    Ok(peer_id) => peer_id,
                    Err(e) => {
                        tracing::warn!(peer_id = %rec.responder_peer_id, error = %e, "dropping unparsable responder peer id from persisted acknowledgment snapshot");
                        continue;
                    }
                };
                let candidate = RecordedAcknowledgment { active: rec.active, acknowledged_at: rec.acknowledged_at };
                match by_peer.get(&peer_id) {
                    Some(existing) if existing.acknowledged_at > candidate.acknowledged_at => {}
                    _ => {
                        by_peer.insert(peer_id, candidate);
                        changed = true;
                        self.sequence += 1;
                    }
                }
            }
        }
        changed
    }
}

/// See `ResponderAcknowledgmentLog::snapshot`/`ResponderAcknowledgmentLog::from_snapshot`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordedAcknowledgmentSnapshot {
    pub responder_peer_id: String,
    pub active: bool,
    pub acknowledged_at: i64,
}

/// See `ResponderAcknowledgmentLog::snapshot`/`ResponderAcknowledgmentLog::from_snapshot`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponderAcknowledgmentSnapshot {
    pub corroboration_nonce: String,
    pub acknowledgments: Vec<RecordedAcknowledgmentSnapshot>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acknowledgment_sign_and_verify_round_trip() {
        let responder = PeerIdentity::generate();
        let ack = build_and_sign(&responder, "nonce-1", true, 1_000).unwrap();
        let peer_id = verify(&ack, 1_010).unwrap();
        assert_eq!(peer_id, responder.peer_id());
    }

    #[test]
    fn tampered_nonce_fails_verification() {
        let responder = PeerIdentity::generate();
        let mut ack = build_and_sign(&responder, "nonce-1", true, 1_000).unwrap();
        ack.unsigned.corroboration_nonce = "nonce-2".to_string();
        assert!(matches!(verify(&ack, 1_010), Err(ResponderAcknowledgmentError::BadSignature)));
    }

    #[test]
    fn mismatched_peer_id_and_public_key_is_rejected() {
        let victim = PeerIdentity::generate();
        let attacker = PeerIdentity::generate();
        let mut ack = build_and_sign(&victim, "nonce-1", true, 1_000).unwrap();
        ack.unsigned.responder_public_key = hex::encode(attacker.verifying_key().to_bytes());
        let canonical = oag_core::canonical_json_bytes(&ack.unsigned).unwrap();
        let sig = sign_with_domain(attacker.signing_key(), RESPONDER_ACKNOWLEDGMENT_DOMAIN, &canonical);
        ack.signature = hex::encode(sig.to_bytes());
        assert!(matches!(verify(&ack, 1_010), Err(ResponderAcknowledgmentError::PeerIdKeyMismatch)));
    }

    #[test]
    fn stale_timestamp_is_rejected() {
        let responder = PeerIdentity::generate();
        let ack = build_and_sign(&responder, "nonce-1", true, 1_000).unwrap();
        let far_future = 1_000 + MAX_CLOCK_SKEW_SECONDS + 1;
        assert!(matches!(verify(&ack, far_future), Err(ResponderAcknowledgmentError::ClockSkew)));
    }

    #[test]
    fn an_invalid_acknowledgment_is_never_recorded() {
        let responder = PeerIdentity::generate();
        let mut ack = build_and_sign(&responder, "nonce-1", true, 1_000).unwrap();
        ack.unsigned.corroboration_nonce = "tampered".to_string();
        let mut log = ResponderAcknowledgmentLog::new();
        assert!(log.add(&ack, 1_010).is_err());
        assert!(log.active_responders_for("tampered").is_empty());
    }

    #[test]
    fn active_responders_for_lists_only_active_claims() {
        let responder_a = PeerIdentity::generate();
        let responder_b = PeerIdentity::generate();
        let mut log = ResponderAcknowledgmentLog::new();

        log.add(&build_and_sign(&responder_a, "nonce-1", true, 1_000).unwrap(), 1_010).unwrap();
        log.add(&build_and_sign(&responder_b, "nonce-1", false, 1_000).unwrap(), 1_010).unwrap();

        let active = log.active_responders_for("nonce-1");
        assert_eq!(active, vec![responder_a.peer_id()]);
    }

    #[test]
    fn a_fresh_acknowledgment_from_the_same_responder_replaces_the_prior_one() {
        let responder = PeerIdentity::generate();
        let mut log = ResponderAcknowledgmentLog::new();

        log.add(&build_and_sign(&responder, "nonce-1", true, 1_000).unwrap(), 1_010).unwrap();
        assert_eq!(log.active_responders_for("nonce-1"), vec![responder.peer_id()]);

        // The same responder standing down -- a fresh, later acknowledgment with active: false.
        log.add(&build_and_sign(&responder, "nonce-1", false, 2_000).unwrap(), 2_010).unwrap();
        assert!(log.active_responders_for("nonce-1").is_empty());
    }

    #[test]
    fn an_out_of_order_stale_acknowledgment_does_not_regress_a_newer_one() {
        let responder = PeerIdentity::generate();
        let mut log = ResponderAcknowledgmentLog::new();

        // The responder stands down at t=1200...
        log.add(&build_and_sign(&responder, "nonce-1", false, 1_200).unwrap(), 1_210).unwrap();
        // ...but a retried copy of their original t=1000 claim arrives after, out of order
        // (still within MAX_CLOCK_SKEW_SECONDS of "now" so it passes freshness on its own).
        log.add(&build_and_sign(&responder, "nonce-1", true, 1_000).unwrap(), 1_220).unwrap();

        // The newer (stand-down) state must win, not the stale claim.
        assert!(log.active_responders_for("nonce-1").is_empty());
    }

    #[test]
    fn two_different_responders_can_both_claim_the_same_event() {
        let responder_a = PeerIdentity::generate();
        let responder_b = PeerIdentity::generate();
        let mut log = ResponderAcknowledgmentLog::new();

        log.add(&build_and_sign(&responder_a, "nonce-1", true, 1_000).unwrap(), 1_010).unwrap();
        log.add(&build_and_sign(&responder_b, "nonce-1", true, 1_000).unwrap(), 1_010).unwrap();

        let mut active = log.active_responders_for("nonce-1");
        active.sort_by_key(|p| p.to_string());
        let mut expected = vec![responder_a.peer_id(), responder_b.peer_id()];
        expected.sort_by_key(|p| p.to_string());
        assert_eq!(active, expected);
    }

    #[test]
    fn snapshot_round_trips_through_from_snapshot() {
        let responder = PeerIdentity::generate();
        let mut log = ResponderAcknowledgmentLog::new();
        log.add(&build_and_sign(&responder, "nonce-1", true, 1_000).unwrap(), 1_010).unwrap();

        let restored = ResponderAcknowledgmentLog::from_snapshot(log.snapshot());
        assert_eq!(restored.active_responders_for("nonce-1"), vec![responder.peer_id()]);
    }

    #[test]
    fn merge_snapshot_keeps_the_more_recent_acknowledgment_per_responder() {
        let responder = PeerIdentity::generate();
        let mut local = ResponderAcknowledgmentLog::new();
        local.add(&build_and_sign(&responder, "nonce-1", true, 1_000).unwrap(), 1_010).unwrap();

        let mut remote = ResponderAcknowledgmentLog::new();
        remote.add(&build_and_sign(&responder, "nonce-1", false, 5_000).unwrap(), 5_010).unwrap();

        local.merge_snapshot(remote.snapshot());
        // The remote's newer stand-down must win.
        assert!(local.active_responders_for("nonce-1").is_empty());

        // Merging a snapshot with an *older* claim than what's already local must not regress it.
        let mut stale_remote = ResponderAcknowledgmentLog::new();
        stale_remote.add(&build_and_sign(&responder, "nonce-1", true, 1_000).unwrap(), 1_010).unwrap();
        local.merge_snapshot(stale_remote.snapshot());
        assert!(local.active_responders_for("nonce-1").is_empty());
    }
}
