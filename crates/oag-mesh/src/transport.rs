//! A real peer-to-peer transport for all four of this crate's message types -- its own HTTP wire
//! protocol, on its own listen address/port, separate from the base project's
//! `/oag/sync/v1/*` or `/oag/gateway/v1/query` entirely. Same "separate concern, separate
//! endpoint" posture the base repo's `spec/32-verified-internet-gateway.md` used for its own
//! query protocol, one layer up: this is `oag-mesh`'s own Layer-3-equivalent, structurally
//! parallel to the base project's `oag-sync`, not a part of it.
//!
//! The four message types get genuinely different transport treatment, because they have
//! genuinely different requirements:
//!
//! - `BridgeDeclaration` is signed by a real identity and loses nothing by ordinary propagation
//!   -- push it to known mesh peers, store what verifies, nothing about this needs hiding.
//! - `AnonymousEvent` carries no identity in its *payload*, but a plain HTTP POST still reveals
//!   the submitting connection's source IP to whoever receives it. **This transport does not
//!   hide that.** See `receive_anonymous_event`'s doc comment and `spec/04-transport.md` for
//!   exactly what is, and is not, achieved here -- this is a real, open gap, not an oversight.
//! - `ClaimReport` is signed by a real identity, same as `BridgeDeclaration` -- it needs to be,
//!   since `corroboration::ClaimCorroboration` weighs reports by the reporter's self-asserted
//!   cluster, which only means anything if the reporter is identified at all. Identity alone
//!   doesn't bound how many distinct (fabricated) clusters one actor can claim, though, so a
//!   `ClaimReport` submission also carries a `corroboration::ClaimReportProofOfWork` -- see
//!   `receive_claim_report`'s doc comment.
//! - `MembershipAttestation` closes the other half of the cross-check gap `ClaimReport`'s own
//!   cluster-name check leaves open -- see `membership.rs`'s own doc comment for what it does
//!   and does not verify, and `receive_membership_attestation`'s doc comment for its transport
//!   treatment (signed, same as `BridgeDeclaration`/`ClaimReport`, same proof-of-work posture).

use std::sync::{Arc, RwLock};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};

use oag_crypto::PeerId;
use serde::{Deserialize, Serialize};

use crate::anonymous_event::{AnonymousEvent, AnonymousEventLog, EventFilter, ProofOfWork};
use crate::bridge::{BridgeDeclaration, BridgeError, BridgeProofOfWork, MeshTree};
use crate::corroboration::{ClaimCorroboration, ClaimReport, ClaimReportError, ClaimReportProofOfWork};
use crate::membership::{MembershipAttestation, MembershipError, MembershipProofOfWork, MembershipRegistry};
use crate::responder::{ResponderAcknowledgment, ResponderAcknowledgmentError, ResponderAcknowledgmentLog};

/// The wire shape for `POST /oag-mesh/v1/anonymous-event` -- the event plus the proof-of-work
/// that must satisfy `AnonymousEventLog::required_difficulty_bits` for this event's nonce
/// (`anonymous_event.rs`'s own anti-spam/anti-replay mechanism) before it's recorded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymousEventSubmission {
    pub event: AnonymousEvent,
    pub pow: ProofOfWork,
}

/// The wire shape for `POST /oag-mesh/v1/claim-report` -- the report plus the proof-of-work that
/// must satisfy `corroboration::ClaimCorroboration::required_difficulty_bits` for this report's
/// `(claim_id, reporter_cluster)` (`corroboration.rs`'s own anti-sybil mechanism) before it's
/// recorded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimReportSubmission {
    pub report: ClaimReport,
    pub pow: ClaimReportProofOfWork,
}

/// The wire shape for `POST /oag-mesh/v1/bridge-declaration` -- the declaration plus the
/// proof-of-work that must satisfy `bridge::MeshTree::required_difficulty_bits` for this
/// declaration's `(mesh_group, member, peer_id)` (`bridge.rs`'s own anti-sybil mechanism)
/// before it's recorded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeDeclarationSubmission {
    pub declaration: BridgeDeclaration,
    pub pow: BridgeProofOfWork,
}

/// The wire shape for `POST /oag-mesh/v1/membership-attestation` -- the attestation plus the
/// proof-of-work that must satisfy `membership::MembershipRegistry::required_difficulty_bits`
/// for this attestation's `(cluster, subject_peer_id, attester_peer_id)` (`membership.rs`'s own
/// anti-sybil mechanism) before it's recorded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipAttestationSubmission {
    pub attestation: MembershipAttestation,
    pub pow: MembershipProofOfWork,
}

/// The wire shape for `POST /oag-mesh/v1/responder-acknowledgment` -- just the signed
/// acknowledgment, no proof-of-work alongside it. See `responder.rs`'s own top-level doc comment
/// for why this mechanism deliberately carries none, unlike the other three signed submission
/// types above.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponderAcknowledgmentSubmission {
    pub acknowledgment: ResponderAcknowledgment,
}

fn now_unix() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as i64
}

#[derive(Clone)]
pub struct MeshState {
    pub identity: Arc<oag_crypto::PeerIdentity>,
    pub tree: Arc<RwLock<MeshTree>>,
    pub event_log: Arc<RwLock<AnonymousEventLog>>,
    pub claim_corroboration: Arc<RwLock<ClaimCorroboration>>,
    pub membership_registry: Arc<RwLock<MembershipRegistry>>,
    pub responder_acknowledgments: Arc<RwLock<ResponderAcknowledgmentLog>>,
    /// Other mesh nodes this one pushes its own declarations/events/reports to -- static,
    /// operator-configured, the same "hand-written topology, no automatic discovery" posture as
    /// the base project's own `[transfer].relay_peers`/`[gateway].query_peers`.
    pub peers: Arc<Vec<String>>,
    pub http: Arc<reqwest::Client>,
}

impl MeshState {
    pub fn new(identity: oag_crypto::PeerIdentity, peers: Vec<String>) -> Self {
        Self {
            identity: Arc::new(identity),
            tree: Arc::new(RwLock::new(MeshTree::new())),
            event_log: Arc::new(RwLock::new(AnonymousEventLog::new())),
            claim_corroboration: Arc::new(RwLock::new(ClaimCorroboration::new())),
            membership_registry: Arc::new(RwLock::new(MembershipRegistry::new())),
            responder_acknowledgments: Arc::new(RwLock::new(ResponderAcknowledgmentLog::new())),
            peers: Arc::new(peers),
            http: Arc::new(reqwest::Client::new()),
        }
    }

    /// Snapshots all five in-memory stores to `bridge_tree.json`, `claim_corroboration.json`,
    /// `anonymous_events.json`, `membership_registry.json`, and
    /// `responder_acknowledgments.json` under `dir`, overwriting whatever was there -- see
    /// `persistence`'s own module doc comment for what this does and does not guarantee (not
    /// atomic, not crash-safe, rewrites the whole file every call). This crate doesn't call this
    /// automatically on any write; a caller decides when to save (periodically, on a clean
    /// shutdown, after every N writes -- whatever fits its own deployment).
    pub fn save_to_dir(&self, dir: &std::path::Path) -> Result<(), crate::persistence::PersistenceError> {
        crate::persistence::save_json(&dir.join("bridge_tree.json"), &self.tree.read().unwrap().snapshot())?;
        crate::persistence::save_json(
            &dir.join("claim_corroboration.json"),
            &self.claim_corroboration.read().unwrap().snapshot(),
        )?;
        crate::persistence::save_json(&dir.join("anonymous_events.json"), &*self.event_log.read().unwrap())?;
        crate::persistence::save_json(
            &dir.join("membership_registry.json"),
            &self.membership_registry.read().unwrap().snapshot(),
        )?;
        crate::persistence::save_json(
            &dir.join("responder_acknowledgments.json"),
            &self.responder_acknowledgments.read().unwrap().snapshot(),
        )?;
        Ok(())
    }

    /// Builds a fresh `MeshState` for `identity`/`peers`, loading each of the five stores from
    /// whatever `save_to_dir` previously wrote to `dir` -- or starting empty for any file that
    /// doesn't exist yet (a brand-new node's first run).
    pub fn load_from_dir(
        identity: oag_crypto::PeerIdentity,
        peers: Vec<String>,
        dir: &std::path::Path,
    ) -> Result<Self, crate::persistence::PersistenceError> {
        let tree = crate::persistence::load_json(&dir.join("bridge_tree.json"))?
            .map(MeshTree::from_snapshot)
            .unwrap_or_default();
        let claim_corroboration = crate::persistence::load_json(&dir.join("claim_corroboration.json"))?
            .map(ClaimCorroboration::from_snapshot)
            .unwrap_or_default();
        let event_log: AnonymousEventLog =
            crate::persistence::load_json(&dir.join("anonymous_events.json"))?.unwrap_or_default();
        let membership_registry = crate::persistence::load_json(&dir.join("membership_registry.json"))?
            .map(MembershipRegistry::from_snapshot)
            .unwrap_or_default();
        let responder_acknowledgments =
            crate::persistence::load_json(&dir.join("responder_acknowledgments.json"))?
                .map(ResponderAcknowledgmentLog::from_snapshot)
                .unwrap_or_default();
        Ok(Self {
            identity: Arc::new(identity),
            tree: Arc::new(RwLock::new(tree)),
            event_log: Arc::new(RwLock::new(event_log)),
            claim_corroboration: Arc::new(RwLock::new(claim_corroboration)),
            membership_registry: Arc::new(RwLock::new(membership_registry)),
            responder_acknowledgments: Arc::new(RwLock::new(responder_acknowledgments)),
            peers: Arc::new(peers),
            http: Arc::new(reqwest::Client::new()),
        })
    }
}

pub fn router(state: MeshState) -> Router {
    Router::new()
        .route("/oag-mesh/v1/bridge-declaration", post(receive_bridge_declaration))
        .route("/oag-mesh/v1/anonymous-event", post(receive_anonymous_event))
        .route("/oag-mesh/v1/anonymous-event/search", get(search_anonymous_events))
        .route("/oag-mesh/v1/claim-report", post(receive_claim_report))
        .route("/oag-mesh/v1/membership-attestation", post(receive_membership_attestation))
        .route("/oag-mesh/v1/responder-acknowledgment", post(receive_responder_acknowledgment))
        .route(
            "/oag-mesh/v1/responder-acknowledgment/{corroboration_nonce}",
            get(get_active_responders),
        )
        .route("/oag-mesh/v1/claim-report/{claim_id}/best", get(get_best_corroborated_value))
        .route(
            "/oag-mesh/v1/claim-report/{claim_id}/best-cross-checked",
            get(get_best_corroborated_value_cross_checked),
        )
        .route(
            "/oag-mesh/v1/claim-report/{claim_id}/best-fully-cross-checked",
            get(get_best_corroborated_value_fully_cross_checked),
        )
        .route("/oag-mesh/v1/sync/bridge-tree", get(get_bridge_tree_snapshot))
        .route("/oag-mesh/v1/sync/claim-corroboration", get(get_claim_corroboration_snapshot))
        .route("/oag-mesh/v1/sync/membership-registry", get(get_membership_registry_snapshot))
        .route("/oag-mesh/v1/sync/anonymous-events", get(get_anonymous_event_log_snapshot))
        .route("/oag-mesh/v1/sync/responder-acknowledgments", get(get_responder_acknowledgment_snapshot))
        .with_state(state)
}

/// Binds `listen_addr` and serves `router(state)` until the process stops. A thin convenience
/// wrapper -- a caller embedding this in a larger application is free to build the router itself
/// and merge it with other routes instead.
pub async fn run(state: MeshState, listen_addr: &str) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    tracing::info!(listen_addr, "oag-mesh transport listening");
    axum::serve(listener, router(state)).await
}

/// Receives a `BridgeDeclarationSubmission` (the declaration plus its proof-of-work) and
/// records it into `state.tree` -- same signature/pairing/clock-skew checks as before, plus the
/// escalating proof-of-work check (`bridge::MeshTree::required_difficulty_bits`) that taxes
/// becoming a *new* distinct peer corroborating a `(mesh_group, member)` edge, rejecting an
/// insufficient proof with `400` the same way the other two mechanisms' proofs are.
async fn receive_bridge_declaration(
    State(state): State<MeshState>,
    Json(submission): Json<BridgeDeclarationSubmission>,
) -> Response {
    let now = now_unix();
    let result = {
        let mut tree = state.tree.write().unwrap();
        tree.add(&submission.declaration, submission.pow, now)
    };
    match result {
        Ok(peer_id) => {
            tracing::info!(%peer_id, mesh_group = %submission.declaration.unsigned.mesh_group, "bridge declaration recorded");
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => bridge_error_response(e),
    }
}

fn bridge_error_response(e: BridgeError) -> Response {
    let status = match &e {
        BridgeError::PeerId(_)
        | BridgeError::InvalidPublicKey
        | BridgeError::PeerIdKeyMismatch
        | BridgeError::BadSignatureEncoding
        | BridgeError::BadSignature
        | BridgeError::ClockSkew
        | BridgeError::SelfReference
        | BridgeError::InsufficientProofOfWork { .. } => StatusCode::BAD_REQUEST,
        BridgeError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
}

/// Receives an `AnonymousEventSubmission` (the event plus its proof-of-work) and records it
/// into `state.event_log` -- which itself enforces the escalating difficulty check, rejecting
/// insufficient proof-of-work with a `400` naming the `required_bits` a retry would need.
///
/// **Does not, and cannot, hide the submitting connection's source IP from this peer** -- that's
/// an inherent property of a plain HTTP POST, not a choice this handler makes. The payload
/// itself carries no identity by `anonymous_event.rs`'s own design; the *transport* carrying it
/// here is not anonymous at the network level. A real anonymizing submission path (routing
/// through an intermediary that doesn't log source-to-content correlation, onion-style layered
/// relaying, or similar) is explicitly not built -- see `spec/04-transport.md`'s open questions.
/// Treat this endpoint as "gets the (already-anonymous) payload from A to B," not as "hides who
/// submitted it."
async fn receive_anonymous_event(
    State(state): State<MeshState>,
    Json(submission): Json<AnonymousEventSubmission>,
) -> Response {
    let result = {
        let mut log = state.event_log.write().unwrap();
        log.record(submission.event, submission.pow)
    };
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e.to_string() }))).into_response(),
    }
}

/// Read-only: every event in this node's own `AnonymousEventLog` matching the query-string filter
/// (`kind`, `min_severity`, `location_prefix`, `since` -- see `anonymous_event::EventFilter`).
/// This is the one piece of `spec/03-anonymous-event-rfc.md`'s "Reaching a responder" open
/// question this crate actually answers, and it is a narrow one -- see
/// `spec/11-responder-search.md` for exactly what it is and is not. Same node-local-only,
/// no-auth scope as every other `GET` endpoint in this file: it searches this node's own log,
/// not the wider mesh, and anyone who can reach the listen address can run any search.
async fn search_anonymous_events(State(state): State<MeshState>, Query(filter): Query<EventFilter>) -> Response {
    let log = state.event_log.read().unwrap();
    Json(serde_json::json!({ "events": log.search(&filter) })).into_response()
}

/// Receives a `ClaimReportSubmission` (the report plus its proof-of-work) and records it into
/// `state.claim_corroboration` -- same signature/pairing/clock-skew checks as a
/// `BridgeDeclaration`, plus the escalating proof-of-work check
/// (`corroboration::ClaimCorroboration::required_difficulty_bits`) that taxes becoming a *new*
/// distinct cluster on a claim, rejecting an insufficient proof with `400` the same way an
/// insufficient `AnonymousEvent` proof is. `reporter_cluster` itself is still never verified
/// against anything (see `corroboration.rs`'s own doc comment on why that's a bare
/// self-assertion, by design) -- proof-of-work taxes *how many* distinct clusters an actor can
/// claim for free, not *which* cluster names are real (that's `best_corroborated_value_cross_checked`'s
/// job, a separate check against `bridge::MeshTree`).
async fn receive_claim_report(
    State(state): State<MeshState>,
    Json(submission): Json<ClaimReportSubmission>,
) -> Response {
    let now = now_unix();
    let result = {
        let mut corroboration = state.claim_corroboration.write().unwrap();
        corroboration.add(&submission.report, submission.pow, now)
    };
    match result {
        Ok(peer_id) => {
            tracing::info!(%peer_id, claim_id = %submission.report.unsigned.claim_id, "claim report recorded");
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => claim_report_error_response(e),
    }
}

fn claim_report_error_response(e: ClaimReportError) -> Response {
    let status = match &e {
        ClaimReportError::PeerId(_)
        | ClaimReportError::InvalidPublicKey
        | ClaimReportError::PeerIdKeyMismatch
        | ClaimReportError::BadSignatureEncoding
        | ClaimReportError::BadSignature
        | ClaimReportError::ClockSkew
        | ClaimReportError::InsufficientProofOfWork { .. } => StatusCode::BAD_REQUEST,
        ClaimReportError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
}

/// Receives a `MembershipAttestationSubmission` (the attestation plus its proof-of-work) and
/// records it into `state.membership_registry` -- same signature/pairing/clock-skew/
/// self-attestation checks as `membership::verify`, plus the escalating proof-of-work check
/// (`membership::MembershipRegistry::required_difficulty_bits`) that taxes becoming a *new*
/// distinct attester for a `(cluster, subject_peer_id)` fact, rejecting an insufficient proof
/// with `400` the same way the other mechanisms' proofs are.
async fn receive_membership_attestation(
    State(state): State<MeshState>,
    Json(submission): Json<MembershipAttestationSubmission>,
) -> Response {
    let now = now_unix();
    let result = {
        let mut registry = state.membership_registry.write().unwrap();
        registry.add(&submission.attestation, submission.pow, now)
    };
    match result {
        Ok((attester_peer_id, subject_peer_id)) => {
            tracing::info!(%attester_peer_id, %subject_peer_id, cluster = %submission.attestation.unsigned.cluster, "membership attestation recorded");
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => membership_error_response(e),
    }
}

fn membership_error_response(e: MembershipError) -> Response {
    let status = match &e {
        MembershipError::AttesterPeerId(_)
        | MembershipError::SubjectPeerId(_)
        | MembershipError::InvalidPublicKey
        | MembershipError::PeerIdKeyMismatch
        | MembershipError::BadSignatureEncoding
        | MembershipError::BadSignature
        | MembershipError::ClockSkew
        | MembershipError::SelfAttestation
        | MembershipError::InsufficientProofOfWork { .. } => StatusCode::BAD_REQUEST,
        MembershipError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
}

/// Receives a `ResponderAcknowledgmentSubmission` (just the signed acknowledgment, no
/// proof-of-work -- see `responder.rs`'s own doc comment for why) and records it into
/// `state.responder_acknowledgments`, same signature/pairing/clock-skew checks as every other
/// signed mechanism's receiver.
async fn receive_responder_acknowledgment(
    State(state): State<MeshState>,
    Json(submission): Json<ResponderAcknowledgmentSubmission>,
) -> Response {
    let now = now_unix();
    let result = {
        let mut log = state.responder_acknowledgments.write().unwrap();
        log.add(&submission.acknowledgment, now)
    };
    match result {
        Ok(peer_id) => {
            tracing::info!(%peer_id, corroboration_nonce = %submission.acknowledgment.unsigned.corroboration_nonce, "responder acknowledgment recorded");
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => responder_acknowledgment_error_response(e),
    }
}

fn responder_acknowledgment_error_response(e: ResponderAcknowledgmentError) -> Response {
    let status = match &e {
        ResponderAcknowledgmentError::PeerId(_)
        | ResponderAcknowledgmentError::InvalidPublicKey
        | ResponderAcknowledgmentError::PeerIdKeyMismatch
        | ResponderAcknowledgmentError::BadSignatureEncoding
        | ResponderAcknowledgmentError::BadSignature
        | ResponderAcknowledgmentError::ClockSkew => StatusCode::BAD_REQUEST,
        ResponderAcknowledgmentError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
}

/// Read-only: every responder currently claiming to be handling `corroboration_nonce`, per
/// `responder::ResponderAcknowledgmentLog::active_responders_for` -- **advisory only**, see
/// `responder.rs`'s own doc comment and `spec/12-responder-acknowledgment.md` for exactly what
/// a non-empty result does and does not guarantee. Same node-local-only, no-auth scope as every
/// other `GET` endpoint here.
async fn get_active_responders(State(state): State<MeshState>, Path(corroboration_nonce): Path<String>) -> Response {
    let log = state.responder_acknowledgments.read().unwrap();
    let responders: Vec<String> =
        log.active_responders_for(&corroboration_nonce).into_iter().map(|p| p.to_string()).collect();
    Json(serde_json::json!({ "active_responders": responders })).into_response()
}

/// Read-only: this node's own current view of `corroboration::ClaimCorroboration::
/// best_corroborated_value` for `claim_id`, from whatever `ClaimReport`s it has received so far
/// (its own, and anything pushed to it). `null` if nothing has been reported for this claim to
/// *this* node yet -- there is no cross-node query fan-out here, a caller wanting a network-wide
/// view has to ask multiple mesh nodes itself.
async fn get_best_corroborated_value(State(state): State<MeshState>, Path(claim_id): Path<String>) -> Response {
    let corroboration = state.claim_corroboration.read().unwrap();
    Json(serde_json::json!({ "best": corroboration.best_corroborated_value(&claim_id) })).into_response()
}

#[derive(Debug, Deserialize)]
struct CrossCheckQuery {
    /// How many distinct `BridgeDeclaration`s must attest a `reporter_cluster` name before a
    /// report claiming it counts. Defaults to `1` -- any real attestation at all, the weakest
    /// bar `bridge::MeshTree::is_attested_base_cluster` supports.
    #[serde(default = "default_min_bridge_corroboration")]
    min_bridge_corroboration: usize,
}

fn default_min_bridge_corroboration() -> usize {
    1
}

/// Read-only, same node-local-only scope as `get_best_corroborated_value`, but cross-checked
/// against this node's own `state.tree` -- see `corroboration::ClaimCorroboration::
/// best_corroborated_value_cross_checked` for exactly what that does and does not verify (the
/// cluster *name* being real, never the reporting peer's actual standing in it).
async fn get_best_corroborated_value_cross_checked(
    State(state): State<MeshState>,
    Path(claim_id): Path<String>,
    Query(query): Query<CrossCheckQuery>,
) -> Response {
    let corroboration = state.claim_corroboration.read().unwrap();
    let tree = state.tree.read().unwrap();
    let result =
        corroboration.best_corroborated_value_cross_checked(&claim_id, &tree, query.min_bridge_corroboration);
    Json(serde_json::json!({ "result": result })).into_response()
}

#[derive(Debug, Deserialize)]
struct FullyCrossCheckQuery {
    #[serde(default = "default_min_bridge_corroboration")]
    min_bridge_corroboration: usize,
    /// How many distinct `MembershipAttestation`s must vouch for a reporting peer's claimed
    /// cluster membership before its report counts. Defaults to `1`, the weakest bar
    /// `membership::MembershipRegistry::is_attested_member` supports.
    #[serde(default = "default_min_membership_corroboration")]
    min_membership_corroboration: usize,
}

fn default_min_membership_corroboration() -> usize {
    1
}

/// Read-only, same node-local-only scope as `get_best_corroborated_value_cross_checked`, but
/// additionally cross-checked against this node's own `state.membership_registry` -- see
/// `corroboration::ClaimCorroboration::best_corroborated_value_fully_cross_checked` for exactly
/// what that closes (the reporting peer's actual standing in its claimed cluster, not just the
/// cluster name being real) and what it still does not (the attesters' own standing).
async fn get_best_corroborated_value_fully_cross_checked(
    State(state): State<MeshState>,
    Path(claim_id): Path<String>,
    Query(query): Query<FullyCrossCheckQuery>,
) -> Response {
    let corroboration = state.claim_corroboration.read().unwrap();
    let tree = state.tree.read().unwrap();
    let registry = state.membership_registry.read().unwrap();
    let result = corroboration.best_corroborated_value_fully_cross_checked(
        &claim_id,
        &tree,
        &registry,
        query.min_bridge_corroboration,
        query.min_membership_corroboration,
    );
    Json(serde_json::json!({ "result": result })).into_response()
}

/// Read-only: this node's entire current `bridge::MeshTree`, as a snapshot -- the pull side of
/// pull-based anti-entropy (`spec/10-anti-entropy.md`). Unlike the `best`/`best-cross-checked`
/// endpoints, this isn't a computed answer to one query, it's this node's whole store, meant to
/// be merged wholesale into a puller's own via `MeshTree::merge_snapshot`.
async fn get_bridge_tree_snapshot(State(state): State<MeshState>) -> Response {
    Json(state.tree.read().unwrap().snapshot()).into_response()
}

/// Read-only: this node's entire current `corroboration::ClaimCorroboration`, as a snapshot --
/// see `get_bridge_tree_snapshot`'s doc comment for the shape of what this is for.
async fn get_claim_corroboration_snapshot(State(state): State<MeshState>) -> Response {
    Json(state.claim_corroboration.read().unwrap().snapshot()).into_response()
}

/// Read-only: this node's entire current `membership::MembershipRegistry`, as a snapshot -- see
/// `get_bridge_tree_snapshot`'s doc comment for the shape of what this is for.
async fn get_membership_registry_snapshot(State(state): State<MeshState>) -> Response {
    Json(state.membership_registry.read().unwrap().snapshot()).into_response()
}

/// Read-only: this node's entire current `anonymous_event::AnonymousEventLog` -- serialized
/// directly (no snapshot-type indirection needed, same reason `persistence` doesn't need one for
/// this store) -- see `get_bridge_tree_snapshot`'s doc comment for the shape of what this is for.
async fn get_anonymous_event_log_snapshot(State(state): State<MeshState>) -> Response {
    Json(&*state.event_log.read().unwrap()).into_response()
}

/// Read-only: this node's entire current `responder::ResponderAcknowledgmentLog`, as a snapshot
/// -- see `get_bridge_tree_snapshot`'s doc comment for the shape of what this is for.
async fn get_responder_acknowledgment_snapshot(State(state): State<MeshState>) -> Response {
    Json(state.responder_acknowledgments.read().unwrap().snapshot()).into_response()
}

#[derive(Debug, thiserror::Error)]
pub enum PushError {
    #[error("request to {0} failed: {1}")]
    Request(String, reqwest::Error),
    #[error("{0} rejected the submission with status {1}")]
    Rejected(String, StatusCode),
}

pub async fn push_bridge_declaration(
    http: &reqwest::Client,
    address: &str,
    decl: &BridgeDeclaration,
    pow: BridgeProofOfWork,
) -> Result<(), PushError> {
    let url = format!("{}/oag-mesh/v1/bridge-declaration", address.trim_end_matches('/'));
    let submission = BridgeDeclarationSubmission { declaration: decl.clone(), pow };
    let response =
        http.post(&url).json(&submission).send().await.map_err(|e| PushError::Request(address.to_string(), e))?;
    if !response.status().is_success() {
        return Err(PushError::Rejected(address.to_string(), response.status()));
    }
    Ok(())
}

pub async fn push_membership_attestation(
    http: &reqwest::Client,
    address: &str,
    attestation: &MembershipAttestation,
    pow: MembershipProofOfWork,
) -> Result<(), PushError> {
    let url = format!("{}/oag-mesh/v1/membership-attestation", address.trim_end_matches('/'));
    let submission = MembershipAttestationSubmission { attestation: attestation.clone(), pow };
    let response =
        http.post(&url).json(&submission).send().await.map_err(|e| PushError::Request(address.to_string(), e))?;
    if !response.status().is_success() {
        return Err(PushError::Rejected(address.to_string(), response.status()));
    }
    Ok(())
}

/// Same best-effort push, for a membership attestation -- solves proof-of-work once, against
/// *this sending node's own* `state.membership_registry` view of `(cluster, subject_peer_id,
/// attester_peer_id)`, and sends the identical `(attestation, pow)` pair to every configured
/// peer. Same caveat as `broadcast_bridge_declaration`'s and `broadcast_claim_report`'s own: a
/// receiving peer with more existing distinct attesters already recorded for this fact may
/// require a higher difficulty than this node did, and will reject this submission if so.
pub async fn broadcast_membership_attestation(state: &MeshState, attestation: &MembershipAttestation) {
    let attester_peer_id: PeerId = match attestation.unsigned.attester_peer_id.parse() {
        Ok(peer_id) => peer_id,
        Err(_) => return,
    };
    let subject_peer_id: PeerId = match attestation.unsigned.subject_peer_id.parse() {
        Ok(peer_id) => peer_id,
        Err(_) => return,
    };
    let required = {
        let registry = state.membership_registry.read().unwrap();
        registry.required_difficulty_bits(&attestation.unsigned.cluster, &subject_peer_id, &attester_peer_id)
    };
    let pow = MembershipProofOfWork::solve(&attestation.unsigned, required);
    for peer in state.peers.iter() {
        if let Err(e) = push_membership_attestation(&state.http, peer, attestation, pow).await {
            tracing::warn!(peer, error = %e, "failed to push membership attestation to peer");
        }
    }
}

pub async fn push_responder_acknowledgment(
    http: &reqwest::Client,
    address: &str,
    acknowledgment: &ResponderAcknowledgment,
) -> Result<(), PushError> {
    let url = format!("{}/oag-mesh/v1/responder-acknowledgment", address.trim_end_matches('/'));
    let submission = ResponderAcknowledgmentSubmission { acknowledgment: acknowledgment.clone() };
    let response =
        http.post(&url).json(&submission).send().await.map_err(|e| PushError::Request(address.to_string(), e))?;
    if !response.status().is_success() {
        return Err(PushError::Rejected(address.to_string(), response.status()));
    }
    Ok(())
}

/// Same best-effort push, for a responder acknowledgment -- no proof-of-work to solve first,
/// unlike every other broadcast function here (see `responder.rs`'s own doc comment for why).
pub async fn broadcast_responder_acknowledgment(state: &MeshState, acknowledgment: &ResponderAcknowledgment) {
    for peer in state.peers.iter() {
        if let Err(e) = push_responder_acknowledgment(&state.http, peer, acknowledgment).await {
            tracing::warn!(peer, error = %e, "failed to push responder acknowledgment to peer");
        }
    }
}

pub async fn push_anonymous_event(
    http: &reqwest::Client,
    address: &str,
    event: &AnonymousEvent,
    pow: ProofOfWork,
) -> Result<(), PushError> {
    let url = format!("{}/oag-mesh/v1/anonymous-event", address.trim_end_matches('/'));
    let submission = AnonymousEventSubmission { event: event.clone(), pow };
    let response =
        http.post(&url).json(&submission).send().await.map_err(|e| PushError::Request(address.to_string(), e))?;
    if !response.status().is_success() {
        return Err(PushError::Rejected(address.to_string(), response.status()));
    }
    Ok(())
}

/// Pushes `decl` to every configured mesh peer, best-effort -- one unreachable peer doesn't stop
/// the others. This is currently the *only* way a declaration reaches the rest of the mesh:
/// there is no pull-based anti-entropy here yet (see `spec/04-transport.md`'s open questions), so
/// a peer that's offline when this runs simply never gets it unless something else re-pushes it
/// later.
///
/// Solves proof-of-work once, against *this sending node's own* `state.tree` view of
/// `(mesh_group, member, peer_id)`, and sends the identical `(decl, pow)` pair to every
/// configured peer -- same caveat `broadcast_claim_report` documents for its own proof-of-work:
/// a receiving peer with more existing distinct peers already corroborating this edge may
/// require a higher difficulty than this node did, and will reject this submission if so.
pub async fn broadcast_bridge_declaration(state: &MeshState, decl: &BridgeDeclaration) {
    let peer_id: PeerId = match decl.unsigned.peer_id.parse() {
        Ok(peer_id) => peer_id,
        Err(_) => return, // malformed peer_id -- nothing to broadcast, verify() will reject it anyway
    };
    let required = {
        let tree = state.tree.read().unwrap();
        tree.required_difficulty_bits(&decl.unsigned.mesh_group, &decl.unsigned.member, &peer_id)
    };
    let pow = BridgeProofOfWork::solve(&decl.unsigned, required);
    for peer in state.peers.iter() {
        if let Err(e) = push_bridge_declaration(&state.http, peer, decl, pow).await {
            tracing::warn!(peer, error = %e, "failed to push bridge declaration to peer");
        }
    }
}

/// Same best-effort push, for an anonymous event -- same source-IP caveat as
/// `receive_anonymous_event` applies at every hop this reaches.
///
/// Solves proof-of-work once, at `anonymous_event::BASE_DIFFICULTY_BITS` (the cost for a
/// *fresh* nonce), and sends the identical `(event, pow)` pair to every configured peer. Each
/// receiving peer's own log tracks this nonce independently, so if one of them already has
/// existing reports for it (e.g. relayed from elsewhere) and therefore requires a higher,
/// escalated difficulty, that specific peer will reject this submission -- logged as a warning,
/// the same best-effort semantics as every other failure here, not retried with a harder proof.
pub async fn broadcast_anonymous_event(state: &MeshState, event: &AnonymousEvent) {
    let pow = ProofOfWork::solve(event, crate::anonymous_event::BASE_DIFFICULTY_BITS);
    for peer in state.peers.iter() {
        if let Err(e) = push_anonymous_event(&state.http, peer, event, pow).await {
            tracing::warn!(peer, error = %e, "failed to push anonymous event to peer");
        }
    }
}

pub async fn push_claim_report(
    http: &reqwest::Client,
    address: &str,
    report: &ClaimReport,
    pow: ClaimReportProofOfWork,
) -> Result<(), PushError> {
    let url = format!("{}/oag-mesh/v1/claim-report", address.trim_end_matches('/'));
    let submission = ClaimReportSubmission { report: report.clone(), pow };
    let response =
        http.post(&url).json(&submission).send().await.map_err(|e| PushError::Request(address.to_string(), e))?;
    if !response.status().is_success() {
        return Err(PushError::Rejected(address.to_string(), response.status()));
    }
    Ok(())
}

/// Same best-effort push, for a claim report -- a cluster's own corroboration signal only
/// strengthens across the mesh once its reports actually reach nodes in *other* clusters, which
/// is exactly what broadcasting to every configured peer does (and, same as the other two
/// broadcast functions, all it does -- no pull-based anti-entropy here either).
///
/// Solves proof-of-work once, against *this sending node's own* `state.claim_corroboration`
/// view of `(claim_id, reporter_cluster)`, and sends the identical `(report, pow)` pair to every
/// configured peer -- same caveat `broadcast_anonymous_event` documents for its own proof-of-work:
/// a receiving peer with more existing distinct clusters already recorded for this claim may
/// require a higher difficulty than this node did, and will reject this submission if so, logged
/// as a warning like any other per-peer push failure, not retried with a harder proof.
pub async fn broadcast_claim_report(state: &MeshState, report: &ClaimReport) {
    let required = {
        let corroboration = state.claim_corroboration.read().unwrap();
        corroboration.required_difficulty_bits(&report.unsigned.claim_id, &report.unsigned.reporter_cluster)
    };
    let pow = ClaimReportProofOfWork::solve(&report.unsigned, required);
    for peer in state.peers.iter() {
        if let Err(e) = push_claim_report(&state.http, peer, report, pow).await {
            tracing::warn!(peer, error = %e, "failed to push claim report to peer");
        }
    }
}

/// Pull-based anti-entropy (`spec/10-anti-entropy.md`): unlike every `push_*`/`broadcast_*`
/// function above, which only reach a peer that's online at the moment of a specific
/// declaration/event/report/attestation, this pulls a peer's *entire* current view of all four
/// stores and merges it into `state`'s own -- closing the gap a peer that was offline during a
/// broadcast is left in otherwise. Best-effort per store: one store's pull failing (e.g. a
/// network error) doesn't stop the others from being attempted, logged as a warning like every
/// other per-peer failure in this file.
///
/// **Trust note, stated as plainly as every other partial guarantee in this crate**: this merges
/// `address`'s own already-verified state wholesale, via `merge_snapshot`/`merge`, **without**
/// re-checking any underlying signature or proof-of-work -- a snapshot has already collapsed
/// past the original signed messages, so there's nothing left here to independently re-verify.
/// This is *not* the same guarantee `receive_bridge_declaration`/`receive_claim_report`/
/// `receive_membership_attestation`/`receive_anonymous_event` give a push: those re-verify every
/// message at the border. Pulling instead trusts that `address` -- already a peer on
/// `MeshState.peers`'s static, operator-configured list, the same trust boundary every push
/// target already sits inside -- did its own verification honestly. A compromised or malicious
/// peer on that list could report corroboration it never actually received proof of; this
/// function has no way to catch that. See `spec/10-anti-entropy.md` for this stated in full.
pub async fn pull_and_merge(state: &MeshState, address: &str) {
    match pull_bridge_tree(&state.http, address).await {
        Ok(snapshot) => state.tree.write().unwrap().merge_snapshot(snapshot),
        Err(e) => tracing::warn!(address, error = %e, "failed to pull bridge tree from peer"),
    }
    match pull_claim_corroboration(&state.http, address).await {
        Ok(snapshot) => state.claim_corroboration.write().unwrap().merge_snapshot(snapshot),
        Err(e) => tracing::warn!(address, error = %e, "failed to pull claim corroboration from peer"),
    }
    match pull_membership_registry(&state.http, address).await {
        Ok(snapshot) => state.membership_registry.write().unwrap().merge_snapshot(snapshot),
        Err(e) => tracing::warn!(address, error = %e, "failed to pull membership registry from peer"),
    }
    match pull_anonymous_events(&state.http, address).await {
        Ok(log) => state.event_log.write().unwrap().merge(log),
        Err(e) => tracing::warn!(address, error = %e, "failed to pull anonymous events from peer"),
    }
    match pull_responder_acknowledgments(&state.http, address).await {
        Ok(snapshot) => state.responder_acknowledgments.write().unwrap().merge_snapshot(snapshot),
        Err(e) => tracing::warn!(address, error = %e, "failed to pull responder acknowledgments from peer"),
    }
}

/// Same best-effort pull-and-merge as `pull_and_merge`, against every peer on `state.peers` in
/// turn -- the periodic, pull-side counterpart to the `broadcast_*` functions' push-side
/// best-effort fan-out. A caller decides when and how often to call this (e.g. on a timer);
/// nothing in this crate schedules it automatically.
pub async fn sync_with_all_peers(state: &MeshState) {
    for peer in state.peers.iter() {
        pull_and_merge(state, peer).await;
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PullError {
    #[error("request to {0} failed: {1}")]
    Request(String, reqwest::Error),
    #[error("{0} rejected the request with status {1}")]
    Rejected(String, StatusCode),
}

pub async fn pull_bridge_tree(
    http: &reqwest::Client,
    address: &str,
) -> Result<Vec<crate::bridge::BridgeEdgeSnapshot>, PullError> {
    let url = format!("{}/oag-mesh/v1/sync/bridge-tree", address.trim_end_matches('/'));
    let response = http.get(&url).send().await.map_err(|e| PullError::Request(address.to_string(), e))?;
    if !response.status().is_success() {
        return Err(PullError::Rejected(address.to_string(), response.status()));
    }
    response.json().await.map_err(|e| PullError::Request(address.to_string(), e))
}

pub async fn pull_claim_corroboration(
    http: &reqwest::Client,
    address: &str,
) -> Result<Vec<crate::corroboration::ClaimSnapshot>, PullError> {
    let url = format!("{}/oag-mesh/v1/sync/claim-corroboration", address.trim_end_matches('/'));
    let response = http.get(&url).send().await.map_err(|e| PullError::Request(address.to_string(), e))?;
    if !response.status().is_success() {
        return Err(PullError::Rejected(address.to_string(), response.status()));
    }
    response.json().await.map_err(|e| PullError::Request(address.to_string(), e))
}

pub async fn pull_membership_registry(
    http: &reqwest::Client,
    address: &str,
) -> Result<Vec<crate::membership::MembershipSnapshot>, PullError> {
    let url = format!("{}/oag-mesh/v1/sync/membership-registry", address.trim_end_matches('/'));
    let response = http.get(&url).send().await.map_err(|e| PullError::Request(address.to_string(), e))?;
    if !response.status().is_success() {
        return Err(PullError::Rejected(address.to_string(), response.status()));
    }
    response.json().await.map_err(|e| PullError::Request(address.to_string(), e))
}

pub async fn pull_anonymous_events(http: &reqwest::Client, address: &str) -> Result<AnonymousEventLog, PullError> {
    let url = format!("{}/oag-mesh/v1/sync/anonymous-events", address.trim_end_matches('/'));
    let response = http.get(&url).send().await.map_err(|e| PullError::Request(address.to_string(), e))?;
    if !response.status().is_success() {
        return Err(PullError::Rejected(address.to_string(), response.status()));
    }
    response.json().await.map_err(|e| PullError::Request(address.to_string(), e))
}

pub async fn pull_responder_acknowledgments(
    http: &reqwest::Client,
    address: &str,
) -> Result<Vec<crate::responder::ResponderAcknowledgmentSnapshot>, PullError> {
    let url = format!("{}/oag-mesh/v1/sync/responder-acknowledgments", address.trim_end_matches('/'));
    let response = http.get(&url).send().await.map_err(|e| PullError::Request(address.to_string(), e))?;
    if !response.status().is_success() {
        return Err(PullError::Rejected(address.to_string(), response.status()));
    }
    response.json().await.map_err(|e| PullError::Request(address.to_string(), e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anonymous_event::{CoarseLocation, EventKind, Severity};
    use crate::bridge::MeshMember;
    use oag_crypto::PeerIdentity;

    async fn spawn(peers: Vec<String>) -> (String, MeshState) {
        let state = MeshState::new(PeerIdentity::generate(), peers);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = router(state.clone());
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (format!("http://{addr}"), state)
    }

    #[tokio::test]
    async fn a_pushed_bridge_declaration_is_recorded_and_corroborated() {
        let (addr_a, _state_a) = spawn(vec![]).await;
        let (_addr_b, state_b) = spawn(vec![]).await;

        let identity = PeerIdentity::generate();
        let decl =
            crate::bridge::build_and_sign(&identity, "global", MeshMember::BaseCluster("ny-dc1".into()), now_unix())
                .unwrap();

        let pow = solve_bridge_pow(&_state_a, &decl);
        push_bridge_declaration(&state_b.http, &addr_a, &decl, pow).await.unwrap();

        let tree = _state_a.tree.read().unwrap();
        assert_eq!(tree.corroboration_for("global", &MeshMember::BaseCluster("ny-dc1".into())), 1);
    }

    #[tokio::test]
    async fn a_tampered_bridge_declaration_is_rejected_over_the_wire() {
        let (addr_a, state_a) = spawn(vec![]).await;
        let identity = PeerIdentity::generate();
        let mut decl =
            crate::bridge::build_and_sign(&identity, "global", MeshMember::BaseCluster("ny-dc1".into()), now_unix())
                .unwrap();
        // Solve against the (still-untampered) declaration -- tampering happens after, matching
        // a real attacker who can't re-solve a proof bound to the content they're about to change.
        let pow = solve_bridge_pow(&state_a, &decl);
        decl.unsigned.mesh_group = "tampered".to_string();

        let http = reqwest::Client::new();
        let err = push_bridge_declaration(&http, &addr_a, &decl, pow).await.unwrap_err();
        assert!(matches!(err, PushError::Rejected(_, status) if status == StatusCode::BAD_REQUEST));
        assert_eq!(state_a.tree.read().unwrap().corroboration_for("tampered", &MeshMember::BaseCluster("ny-dc1".into())), 0);
    }

    #[tokio::test]
    async fn broadcast_reaches_every_configured_peer() {
        let (addr_a, state_a) = spawn(vec![]).await;
        let (addr_b, state_b) = spawn(vec![]).await;
        let (_addr_sender, sender_state) = spawn(vec![addr_a.clone(), addr_b.clone()]).await;

        let identity = PeerIdentity::generate();
        let decl = crate::bridge::build_and_sign(
            &identity,
            "global",
            MeshMember::BaseCluster("broadcast-test".into()),
            now_unix(),
        )
        .unwrap();

        broadcast_bridge_declaration(&sender_state, &decl).await;

        let member = MeshMember::BaseCluster("broadcast-test".into());
        assert_eq!(state_a.tree.read().unwrap().corroboration_for("global", &member), 1);
        assert_eq!(state_b.tree.read().unwrap().corroboration_for("global", &member), 1);
    }

    /// Solves whatever proof-of-work `state`'s own `tree` currently requires for `decl`'s
    /// `(mesh_group, member, peer_id)` -- the test-side equivalent of a real client asking the
    /// node it's about to push to what it needs, before spending the work.
    fn solve_bridge_pow(state: &MeshState, decl: &BridgeDeclaration) -> BridgeProofOfWork {
        let peer_id: PeerId = decl.unsigned.peer_id.parse().unwrap();
        let required = state
            .tree
            .read()
            .unwrap()
            .required_difficulty_bits(&decl.unsigned.mesh_group, &decl.unsigned.member, &peer_id);
        BridgeProofOfWork::solve(&decl.unsigned, required)
    }

    /// Solves whatever proof-of-work `state`'s own `claim_corroboration` currently requires for
    /// `report`'s `(claim_id, reporter_cluster)` -- the test-side equivalent of a real client
    /// asking the node it's about to push to what it needs, before spending the work.
    fn solve_claim_pow(state: &MeshState, report: &ClaimReport) -> ClaimReportProofOfWork {
        let required = state
            .claim_corroboration
            .read()
            .unwrap()
            .required_difficulty_bits(&report.unsigned.claim_id, &report.unsigned.reporter_cluster);
        ClaimReportProofOfWork::solve(&report.unsigned, required)
    }

    /// Solves whatever proof-of-work `state`'s own `membership_registry` currently requires for
    /// `attestation`'s `(cluster, subject_peer_id, attester_peer_id)` -- the test-side equivalent
    /// of a real client asking the node it's about to push to what it needs, before spending the
    /// work.
    fn solve_membership_pow(state: &MeshState, attestation: &MembershipAttestation) -> MembershipProofOfWork {
        let attester_peer_id: PeerId = attestation.unsigned.attester_peer_id.parse().unwrap();
        let subject_peer_id: PeerId = attestation.unsigned.subject_peer_id.parse().unwrap();
        let required = state.membership_registry.read().unwrap().required_difficulty_bits(
            &attestation.unsigned.cluster,
            &subject_peer_id,
            &attester_peer_id,
        );
        MembershipProofOfWork::solve(&attestation.unsigned, required)
    }

    fn valid_event(nonce: &str) -> AnonymousEvent {
        AnonymousEvent {
            event_id: "evt-1".to_string(),
            kind: EventKind::HazardObserved,
            severity: Severity::High,
            observed_at: (now_unix() / 300) * 300,
            location: CoarseLocation("9q8yy".to_string()),
            corroboration_nonce: nonce.to_string(),
        }
    }

    #[tokio::test]
    async fn a_pushed_anonymous_event_is_recorded() {
        let (addr_a, state_a) = spawn(vec![]).await;
        let http = reqwest::Client::new();
        let event = valid_event("transport-test-nonce");
        let pow = ProofOfWork::solve(&event, crate::anonymous_event::BASE_DIFFICULTY_BITS);
        push_anonymous_event(&http, &addr_a, &event, pow).await.unwrap();
        assert_eq!(state_a.event_log.read().unwrap().corroboration_for("transport-test-nonce"), 1);
    }

    #[tokio::test]
    async fn search_anonymous_events_filters_by_kind_and_min_severity_over_the_wire() {
        let (addr_a, _state_a) = spawn(vec![]).await;
        let http = reqwest::Client::new();

        let mut medical_critical = valid_event("search-wire-medical");
        medical_critical.kind = crate::anonymous_event::EventKind::MedicalEmergency(
            crate::anonymous_event::MedicalEmergencyKind::HeartIssue,
        );
        medical_critical.severity = crate::anonymous_event::Severity::Critical;
        let pow1 = ProofOfWork::solve(&medical_critical, crate::anonymous_event::BASE_DIFFICULTY_BITS);
        push_anonymous_event(&http, &addr_a, &medical_critical, pow1).await.unwrap();

        let mut hazard_low = valid_event("search-wire-hazard");
        hazard_low.severity = crate::anonymous_event::Severity::Low;
        let pow2 = ProofOfWork::solve(&hazard_low, crate::anonymous_event::BASE_DIFFICULTY_BITS);
        push_anonymous_event(&http, &addr_a, &hazard_low, pow2).await.unwrap();

        let response =
            reqwest::get(format!("{addr_a}/oag-mesh/v1/anonymous-event/search?kind=MedicalEmergency")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["events"].as_array().unwrap().len(), 1);
        assert_eq!(body["events"][0]["corroboration_nonce"], "search-wire-medical");

        let response = reqwest::get(format!("{addr_a}/oag-mesh/v1/anonymous-event/search?min_severity=High"))
            .await
            .unwrap();
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["events"].as_array().unwrap().len(), 1);
        assert_eq!(body["events"][0]["corroboration_nonce"], "search-wire-medical");

        // No filter at all returns both.
        let response = reqwest::get(format!("{addr_a}/oag-mesh/v1/anonymous-event/search")).await.unwrap();
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["events"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn an_invalid_anonymous_event_is_rejected_over_the_wire() {
        let (addr_a, state_a) = spawn(vec![]).await;
        let mut event = valid_event("transport-test-nonce-2");
        event.observed_at += 1; // not rounded -- invalid
        let pow = ProofOfWork::solve(&event, crate::anonymous_event::BASE_DIFFICULTY_BITS);
        let http = reqwest::Client::new();
        let err = push_anonymous_event(&http, &addr_a, &event, pow).await.unwrap_err();
        assert!(matches!(err, PushError::Rejected(_, status) if status == StatusCode::BAD_REQUEST));
        assert_eq!(state_a.event_log.read().unwrap().corroboration_for("transport-test-nonce-2"), 0);
    }

    #[tokio::test]
    async fn an_anonymous_event_with_insufficient_proof_of_work_is_rejected_over_the_wire() {
        let (addr_a, state_a) = spawn(vec![]).await;
        let event = valid_event("transport-test-nonce-pow");
        let http = reqwest::Client::new();
        let err = push_anonymous_event(&http, &addr_a, &event, ProofOfWork { nonce: 0 }).await.unwrap_err();
        assert!(matches!(err, PushError::Rejected(_, status) if status == StatusCode::BAD_REQUEST));
        assert_eq!(state_a.event_log.read().unwrap().corroboration_for("transport-test-nonce-pow"), 0);
    }

    #[tokio::test]
    async fn a_pushed_claim_report_is_recorded_and_queryable_over_the_wire() {
        let (addr_a, state_a) = spawn(vec![]).await;
        let identity = PeerIdentity::generate();
        let report =
            crate::corroboration::build_and_sign(&identity, "claim-transport-test", "cluster-a", "blake3:abc", now_unix())
                .unwrap();

        let pow = solve_claim_pow(&state_a, &report);
        push_claim_report(&reqwest::Client::new(), &addr_a, &report, pow).await.unwrap();

        let response = reqwest::get(format!("{addr_a}/oag-mesh/v1/claim-report/claim-transport-test/best"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["best"]["observed_value_hash"], "blake3:abc");
        assert_eq!(body["best"]["distinct_clusters"], 1);
    }

    #[tokio::test]
    async fn a_tampered_claim_report_is_rejected_over_the_wire() {
        let (addr_a, state_a) = spawn(vec![]).await;
        let identity = PeerIdentity::generate();
        let mut report =
            crate::corroboration::build_and_sign(&identity, "claim-tamper-test", "cluster-a", "blake3:abc", now_unix())
                .unwrap();
        // Solve against the (still-untampered) report -- tampering happens after, matching a
        // real attacker who can't re-solve a proof bound to the content they're about to change.
        let pow = solve_claim_pow(&state_a, &report);
        report.unsigned.observed_value_hash = "blake3:tampered".to_string();

        let err = push_claim_report(&reqwest::Client::new(), &addr_a, &report, pow).await.unwrap_err();
        assert!(matches!(err, PushError::Rejected(_, status) if status == StatusCode::BAD_REQUEST));
    }

    #[tokio::test]
    async fn broadcast_claim_report_reaches_every_configured_peer_and_corroborates() {
        let (addr_a, state_a) = spawn(vec![]).await;
        let (addr_b, state_b) = spawn(vec![]).await;
        let (_addr_sender, sender_state) = spawn(vec![addr_a.clone(), addr_b.clone()]).await;

        let identity = PeerIdentity::generate();
        let report = crate::corroboration::build_and_sign(
            &identity,
            "claim-broadcast-test",
            "cluster-sender",
            "blake3:abc",
            now_unix(),
        )
        .unwrap();

        broadcast_claim_report(&sender_state, &report).await;

        assert_eq!(
            state_a.claim_corroboration.read().unwrap().cluster_corroboration_for("claim-broadcast-test", "blake3:abc"),
            1
        );
        assert_eq!(
            state_b.claim_corroboration.read().unwrap().cluster_corroboration_for("claim-broadcast-test", "blake3:abc"),
            1
        );
    }

    #[tokio::test]
    async fn best_cross_checked_drops_a_report_claiming_an_unattested_cluster() {
        let (addr_a, state_a) = spawn(vec![]).await;

        // Attest "cluster-real" via a real BridgeDeclaration first.
        let bridge_signer = PeerIdentity::generate();
        let decl = crate::bridge::build_and_sign(
            &bridge_signer,
            "global",
            MeshMember::BaseCluster("cluster-real".into()),
            now_unix(),
        )
        .unwrap();
        let bridge_pow = solve_bridge_pow(&state_a, &decl);
        push_bridge_declaration(&reqwest::Client::new(), &addr_a, &decl, bridge_pow).await.unwrap();

        // One report from the attested cluster, one from a fabricated cluster name.
        let real_reporter = PeerIdentity::generate();
        let fake_reporter = PeerIdentity::generate();
        let real_report = crate::corroboration::build_and_sign(
            &real_reporter,
            "claim-cross-check-test",
            "cluster-real",
            "blake3:abc",
            now_unix(),
        )
        .unwrap();
        let fake_report = crate::corroboration::build_and_sign(
            &fake_reporter,
            "claim-cross-check-test",
            "cluster-fabricated",
            "blake3:abc",
            now_unix(),
        )
        .unwrap();
        let real_pow = solve_claim_pow(&state_a, &real_report);
        push_claim_report(&reqwest::Client::new(), &addr_a, &real_report, real_pow).await.unwrap();
        let fake_pow = solve_claim_pow(&state_a, &fake_report);
        push_claim_report(&reqwest::Client::new(), &addr_a, &fake_report, fake_pow).await.unwrap();

        // The uncross-checked view still sees both clusters.
        assert_eq!(
            state_a.claim_corroboration.read().unwrap().best_corroborated_value("claim-cross-check-test").unwrap().distinct_clusters,
            2
        );

        let response = reqwest::get(format!(
            "{addr_a}/oag-mesh/v1/claim-report/claim-cross-check-test/best-cross-checked"
        ))
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["result"]["best"]["distinct_clusters"], 1);
        assert_eq!(body["result"]["reports_dropped_unattested_cluster"], 1);
    }

    #[tokio::test]
    async fn best_cross_checked_against_an_unknown_claim_returns_null_result() {
        let (addr_a, _state_a) = spawn(vec![]).await;
        let response = reqwest::get(format!(
            "{addr_a}/oag-mesh/v1/claim-report/never-reported/best-cross-checked"
        ))
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = response.json().await.unwrap();
        assert!(body["result"].is_null());
    }

    #[tokio::test]
    async fn querying_an_unknown_claim_returns_null() {
        let (addr_a, _state_a) = spawn(vec![]).await;
        let response = reqwest::get(format!("{addr_a}/oag-mesh/v1/claim-report/never-reported/best")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = response.json().await.unwrap();
        assert!(body["best"].is_null());
    }

    #[tokio::test]
    async fn save_to_dir_then_load_from_dir_round_trips_all_five_stores() {
        let (_addr_a, state_a) = spawn(vec![]).await;

        // Populate all five stores with one real entry each.
        let bridge_signer = PeerIdentity::generate();
        let decl =
            crate::bridge::build_and_sign(&bridge_signer, "global", MeshMember::BaseCluster("persist-test".into()), now_unix())
                .unwrap();
        let bridge_pow = solve_bridge_pow(&state_a, &decl);
        state_a.tree.write().unwrap().add(&decl, bridge_pow, now_unix()).unwrap();

        let reporter = PeerIdentity::generate();
        let report =
            crate::corroboration::build_and_sign(&reporter, "claim-persist-test", "cluster-a", "blake3:abc", now_unix())
                .unwrap();
        let claim_pow = solve_claim_pow(&state_a, &report);
        state_a.claim_corroboration.write().unwrap().add(&report, claim_pow, now_unix()).unwrap();

        let event = valid_event("persist-test-nonce");
        let event_pow = ProofOfWork::solve(&event, crate::anonymous_event::BASE_DIFFICULTY_BITS);
        state_a.event_log.write().unwrap().record(event, event_pow).unwrap();

        let attester = PeerIdentity::generate();
        let subject = PeerIdentity::generate();
        let attestation =
            crate::membership::build_and_sign(&attester, subject.peer_id(), "cluster-a", now_unix()).unwrap();
        let membership_pow = solve_membership_pow(&state_a, &attestation);
        state_a.membership_registry.write().unwrap().add(&attestation, membership_pow, now_unix()).unwrap();

        let responder = PeerIdentity::generate();
        let ack = crate::responder::build_and_sign(&responder, "ack-persist-test", true, now_unix()).unwrap();
        state_a.responder_acknowledgments.write().unwrap().add(&ack, now_unix()).unwrap();

        let dir = std::env::temp_dir().join(format!("oag-mesh-transport-persist-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        state_a.save_to_dir(&dir).unwrap();

        let loaded = MeshState::load_from_dir(PeerIdentity::generate(), vec![], &dir).unwrap();
        assert_eq!(
            loaded.tree.read().unwrap().corroboration_for("global", &MeshMember::BaseCluster("persist-test".into())),
            1
        );
        assert_eq!(loaded.claim_corroboration.read().unwrap().cluster_corroboration_for("claim-persist-test", "blake3:abc"), 1);
        assert_eq!(loaded.event_log.read().unwrap().corroboration_for("persist-test-nonce"), 1);
        assert!(loaded.membership_registry.read().unwrap().is_attested_member("cluster-a", &subject.peer_id(), 1));
        assert_eq!(
            loaded.responder_acknowledgments.read().unwrap().active_responders_for("ack-persist-test"),
            vec![responder.peer_id()]
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn load_from_dir_against_a_nonexistent_directory_starts_empty() {
        let dir = std::env::temp_dir().join(format!("oag-mesh-transport-persist-missing-{}", std::process::id()));
        let loaded = MeshState::load_from_dir(PeerIdentity::generate(), vec![], &dir).unwrap();
        assert!(loaded.tree.read().unwrap().members_of("global", 1).is_empty());
        assert_eq!(loaded.event_log.read().unwrap().corroboration_for("anything"), 0);
        assert!(!loaded.membership_registry.read().unwrap().is_attested_member("anything", &PeerIdentity::generate().peer_id(), 1));
        assert!(loaded.responder_acknowledgments.read().unwrap().active_responders_for("anything").is_empty());
    }

    #[tokio::test]
    async fn a_pushed_membership_attestation_is_recorded_and_corroborated() {
        let (addr_a, state_a) = spawn(vec![]).await;

        let attester = PeerIdentity::generate();
        let subject = PeerIdentity::generate();
        let attestation =
            crate::membership::build_and_sign(&attester, subject.peer_id(), "cluster-transport-test", now_unix())
                .unwrap();

        let pow = solve_membership_pow(&state_a, &attestation);
        push_membership_attestation(&reqwest::Client::new(), &addr_a, &attestation, pow).await.unwrap();

        assert!(state_a
            .membership_registry
            .read()
            .unwrap()
            .is_attested_member("cluster-transport-test", &subject.peer_id(), 1));
    }

    #[tokio::test]
    async fn a_tampered_membership_attestation_is_rejected_over_the_wire() {
        let (addr_a, state_a) = spawn(vec![]).await;
        let attester = PeerIdentity::generate();
        let subject = PeerIdentity::generate();
        let mut attestation =
            crate::membership::build_and_sign(&attester, subject.peer_id(), "cluster-tamper-test", now_unix())
                .unwrap();
        let pow = solve_membership_pow(&state_a, &attestation);
        attestation.unsigned.cluster = "tampered".to_string();

        let err = push_membership_attestation(&reqwest::Client::new(), &addr_a, &attestation, pow).await.unwrap_err();
        assert!(matches!(err, PushError::Rejected(_, status) if status == StatusCode::BAD_REQUEST));
        assert!(!state_a.membership_registry.read().unwrap().is_attested_member("tampered", &subject.peer_id(), 1));
    }

    #[tokio::test]
    async fn broadcast_membership_attestation_reaches_every_configured_peer() {
        let (addr_a, state_a) = spawn(vec![]).await;
        let (addr_b, state_b) = spawn(vec![]).await;
        let (_addr_sender, sender_state) = spawn(vec![addr_a.clone(), addr_b.clone()]).await;

        let attester = PeerIdentity::generate();
        let subject = PeerIdentity::generate();
        let attestation =
            crate::membership::build_and_sign(&attester, subject.peer_id(), "cluster-broadcast-test", now_unix())
                .unwrap();

        broadcast_membership_attestation(&sender_state, &attestation).await;

        assert!(state_a.membership_registry.read().unwrap().is_attested_member("cluster-broadcast-test", &subject.peer_id(), 1));
        assert!(state_b.membership_registry.read().unwrap().is_attested_member("cluster-broadcast-test", &subject.peer_id(), 1));
    }

    #[tokio::test]
    async fn a_pushed_responder_acknowledgment_is_recorded_and_readable_over_the_wire() {
        let (addr_a, state_a) = spawn(vec![]).await;
        let responder = PeerIdentity::generate();
        let ack = crate::responder::build_and_sign(&responder, "ack-wire-test", true, now_unix()).unwrap();

        push_responder_acknowledgment(&reqwest::Client::new(), &addr_a, &ack).await.unwrap();

        assert_eq!(
            state_a.responder_acknowledgments.read().unwrap().active_responders_for("ack-wire-test"),
            vec![responder.peer_id()]
        );

        let response =
            reqwest::get(format!("{addr_a}/oag-mesh/v1/responder-acknowledgment/ack-wire-test")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["active_responders"].as_array().unwrap().len(), 1);
        assert_eq!(body["active_responders"][0], responder.peer_id().to_string());
    }

    #[tokio::test]
    async fn a_tampered_responder_acknowledgment_is_rejected_over_the_wire() {
        let (addr_a, state_a) = spawn(vec![]).await;
        let responder = PeerIdentity::generate();
        let mut ack = crate::responder::build_and_sign(&responder, "ack-tamper-test", true, now_unix()).unwrap();
        ack.unsigned.corroboration_nonce = "tampered".to_string();

        let err = push_responder_acknowledgment(&reqwest::Client::new(), &addr_a, &ack).await.unwrap_err();
        assert!(matches!(err, PushError::Rejected(_, status) if status == StatusCode::BAD_REQUEST));
        assert!(state_a.responder_acknowledgments.read().unwrap().active_responders_for("tampered").is_empty());
    }

    #[tokio::test]
    async fn broadcast_responder_acknowledgment_reaches_every_configured_peer() {
        let (addr_a, state_a) = spawn(vec![]).await;
        let (addr_b, state_b) = spawn(vec![]).await;
        let (_addr_sender, sender_state) = spawn(vec![addr_a.clone(), addr_b.clone()]).await;

        let responder = PeerIdentity::generate();
        let ack = crate::responder::build_and_sign(&responder, "ack-broadcast-test", true, now_unix()).unwrap();

        broadcast_responder_acknowledgment(&sender_state, &ack).await;

        assert_eq!(
            state_a.responder_acknowledgments.read().unwrap().active_responders_for("ack-broadcast-test"),
            vec![responder.peer_id()]
        );
        assert_eq!(
            state_b.responder_acknowledgments.read().unwrap().active_responders_for("ack-broadcast-test"),
            vec![responder.peer_id()]
        );
    }

    #[tokio::test]
    async fn querying_active_responders_for_an_unknown_nonce_returns_an_empty_list() {
        let (addr_a, _state_a) = spawn(vec![]).await;
        let response =
            reqwest::get(format!("{addr_a}/oag-mesh/v1/responder-acknowledgment/never-acknowledged")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = response.json().await.unwrap();
        assert!(body["active_responders"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn best_fully_cross_checked_drops_a_report_from_a_peer_with_no_membership_attestation() {
        let (addr_a, state_a) = spawn(vec![]).await;

        // Attest "cluster-real" via a real BridgeDeclaration.
        let bridge_signer = PeerIdentity::generate();
        let decl = crate::bridge::build_and_sign(
            &bridge_signer,
            "global",
            MeshMember::BaseCluster("cluster-real".into()),
            now_unix(),
        )
        .unwrap();
        let bridge_pow = solve_bridge_pow(&state_a, &decl);
        push_bridge_declaration(&reqwest::Client::new(), &addr_a, &decl, bridge_pow).await.unwrap();

        // Attest that real_reporter is a genuine member of cluster-real.
        let attester = PeerIdentity::generate();
        let real_reporter = PeerIdentity::generate();
        let unattested_reporter = PeerIdentity::generate();
        let attestation =
            crate::membership::build_and_sign(&attester, real_reporter.peer_id(), "cluster-real", now_unix()).unwrap();
        let membership_pow = solve_membership_pow(&state_a, &attestation);
        push_membership_attestation(&reqwest::Client::new(), &addr_a, &attestation, membership_pow).await.unwrap();

        // Both reporters claim the same real cluster name; only one has a membership attestation.
        let real_report = crate::corroboration::build_and_sign(
            &real_reporter,
            "claim-fully-cross-check-test",
            "cluster-real",
            "blake3:abc",
            now_unix(),
        )
        .unwrap();
        let unattested_report = crate::corroboration::build_and_sign(
            &unattested_reporter,
            "claim-fully-cross-check-test",
            "cluster-real",
            "blake3:abc",
            now_unix(),
        )
        .unwrap();
        let real_pow = solve_claim_pow(&state_a, &real_report);
        push_claim_report(&reqwest::Client::new(), &addr_a, &real_report, real_pow).await.unwrap();
        let unattested_pow = solve_claim_pow(&state_a, &unattested_report);
        push_claim_report(&reqwest::Client::new(), &addr_a, &unattested_report, unattested_pow).await.unwrap();

        let response = reqwest::get(format!(
            "{addr_a}/oag-mesh/v1/claim-report/claim-fully-cross-check-test/best-fully-cross-checked"
        ))
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["result"]["best"]["distinct_peers"], 1);
        assert_eq!(body["result"]["reports_dropped_unattested_cluster"], 0);
        assert_eq!(body["result"]["reports_dropped_unattested_membership"], 1);
    }

    #[tokio::test]
    async fn best_fully_cross_checked_against_an_unknown_claim_returns_null_result() {
        let (addr_a, _state_a) = spawn(vec![]).await;
        let response = reqwest::get(format!(
            "{addr_a}/oag-mesh/v1/claim-report/never-reported/best-fully-cross-checked"
        ))
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = response.json().await.unwrap();
        assert!(body["result"].is_null());
    }

    #[tokio::test]
    async fn pull_and_merge_catches_up_a_node_that_missed_every_broadcast() {
        let (addr_source, state_source) = spawn(vec![]).await;
        let (_addr_catcher, state_catcher) = spawn(vec![]).await;

        // Populate the source node's five stores directly, as if it had received all this from
        // broadcasts the catcher node was offline for.
        let bridge_signer = PeerIdentity::generate();
        let decl = crate::bridge::build_and_sign(
            &bridge_signer,
            "global",
            MeshMember::BaseCluster("sync-test".into()),
            now_unix(),
        )
        .unwrap();
        let bridge_pow = solve_bridge_pow(&state_source, &decl);
        state_source.tree.write().unwrap().add(&decl, bridge_pow, now_unix()).unwrap();

        let reporter = PeerIdentity::generate();
        let report = crate::corroboration::build_and_sign(
            &reporter,
            "claim-sync-test",
            "cluster-a",
            "blake3:abc",
            now_unix(),
        )
        .unwrap();
        let claim_pow = solve_claim_pow(&state_source, &report);
        state_source.claim_corroboration.write().unwrap().add(&report, claim_pow, now_unix()).unwrap();

        let attester = PeerIdentity::generate();
        let subject = PeerIdentity::generate();
        let attestation =
            crate::membership::build_and_sign(&attester, subject.peer_id(), "cluster-a", now_unix()).unwrap();
        let membership_pow = solve_membership_pow(&state_source, &attestation);
        state_source.membership_registry.write().unwrap().add(&attestation, membership_pow, now_unix()).unwrap();

        let event = valid_event("sync-test-nonce");
        let event_pow = ProofOfWork::solve(&event, crate::anonymous_event::BASE_DIFFICULTY_BITS);
        state_source.event_log.write().unwrap().record(event, event_pow).unwrap();

        let responder = PeerIdentity::generate();
        let ack = crate::responder::build_and_sign(&responder, "sync-test-nonce", true, now_unix()).unwrap();
        state_source.responder_acknowledgments.write().unwrap().add(&ack, now_unix()).unwrap();

        // The catcher starts empty; one pull_and_merge call should bring it fully up to date.
        pull_and_merge(&state_catcher, &addr_source).await;

        assert_eq!(
            state_catcher.tree.read().unwrap().corroboration_for("global", &MeshMember::BaseCluster("sync-test".into())),
            1
        );
        assert_eq!(
            state_catcher.claim_corroboration.read().unwrap().cluster_corroboration_for("claim-sync-test", "blake3:abc"),
            1
        );
        assert!(state_catcher.membership_registry.read().unwrap().is_attested_member("cluster-a", &subject.peer_id(), 1));
        assert_eq!(state_catcher.event_log.read().unwrap().corroboration_for("sync-test-nonce"), 1);
        assert_eq!(
            state_catcher.responder_acknowledgments.read().unwrap().active_responders_for("sync-test-nonce"),
            vec![responder.peer_id()]
        );

        // Pulling again (e.g. a periodic re-sync) must not inflate anything -- idempotent merge.
        pull_and_merge(&state_catcher, &addr_source).await;
        assert_eq!(
            state_catcher.tree.read().unwrap().corroboration_for("global", &MeshMember::BaseCluster("sync-test".into())),
            1
        );
        assert_eq!(state_catcher.event_log.read().unwrap().corroboration_for("sync-test-nonce"), 1);
    }

    #[tokio::test]
    async fn sync_with_all_peers_pulls_from_every_configured_peer() {
        let (addr_a, state_a) = spawn(vec![]).await;
        let (addr_b, state_b) = spawn(vec![]).await;
        let (_addr_catcher, state_catcher) = spawn(vec![addr_a.clone(), addr_b.clone()]).await;

        let decl_a = crate::bridge::build_and_sign(
            &PeerIdentity::generate(),
            "global",
            MeshMember::BaseCluster("from-a".into()),
            now_unix(),
        )
        .unwrap();
        let pow_a = solve_bridge_pow(&state_a, &decl_a);
        state_a.tree.write().unwrap().add(&decl_a, pow_a, now_unix()).unwrap();

        let decl_b = crate::bridge::build_and_sign(
            &PeerIdentity::generate(),
            "global",
            MeshMember::BaseCluster("from-b".into()),
            now_unix(),
        )
        .unwrap();
        let pow_b = solve_bridge_pow(&state_b, &decl_b);
        state_b.tree.write().unwrap().add(&decl_b, pow_b, now_unix()).unwrap();

        sync_with_all_peers(&state_catcher).await;

        assert_eq!(
            state_catcher.tree.read().unwrap().corroboration_for("global", &MeshMember::BaseCluster("from-a".into())),
            1
        );
        assert_eq!(
            state_catcher.tree.read().unwrap().corroboration_for("global", &MeshMember::BaseCluster("from-b".into())),
            1
        );
    }

    #[tokio::test]
    async fn pulling_from_an_unreachable_peer_does_not_panic_or_stop_other_stores() {
        let (_addr_catcher, state_catcher) = spawn(vec![]).await;
        // Port 0 on loopback is never a live listener -- a real connection failure.
        pull_and_merge(&state_catcher, "http://127.0.0.1:0").await;
        assert!(state_catcher.tree.read().unwrap().members_of("global", 1).is_empty());
    }
}
