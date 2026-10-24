//! A real peer-to-peer transport for both of this crate's message types -- its own HTTP wire
//! protocol, on its own listen address/port, separate from the base project's
//! `/oag/sync/v1/*` or `/oag/gateway/v1/query` entirely. Same "separate concern, separate
//! endpoint" posture the base repo's `spec/32-verified-internet-gateway.md` used for its own
//! query protocol, one layer up: this is `oag-mesh`'s own Layer-3-equivalent, structurally
//! parallel to the base project's `oag-sync`, not a part of it.
//!
//! The three message types get genuinely different transport treatment, because they have
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
//!   cluster, which only means anything if the reporter is identified at all.

use std::sync::{Arc, RwLock};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};

use serde::{Deserialize, Serialize};

use crate::anonymous_event::{AnonymousEvent, AnonymousEventLog, ProofOfWork};
use crate::bridge::{BridgeDeclaration, BridgeError, MeshTree};
use crate::corroboration::{ClaimCorroboration, ClaimReport, ClaimReportError};

/// The wire shape for `POST /oag-mesh/v1/anonymous-event` -- the event plus the proof-of-work
/// that must satisfy `AnonymousEventLog::required_difficulty_bits` for this event's nonce
/// (`anonymous_event.rs`'s own anti-spam/anti-replay mechanism) before it's recorded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymousEventSubmission {
    pub event: AnonymousEvent,
    pub pow: ProofOfWork,
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
            peers: Arc::new(peers),
            http: Arc::new(reqwest::Client::new()),
        }
    }
}

pub fn router(state: MeshState) -> Router {
    Router::new()
        .route("/oag-mesh/v1/bridge-declaration", post(receive_bridge_declaration))
        .route("/oag-mesh/v1/anonymous-event", post(receive_anonymous_event))
        .route("/oag-mesh/v1/claim-report", post(receive_claim_report))
        .route("/oag-mesh/v1/claim-report/{claim_id}/best", get(get_best_corroborated_value))
        .route(
            "/oag-mesh/v1/claim-report/{claim_id}/best-cross-checked",
            get(get_best_corroborated_value_cross_checked),
        )
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

async fn receive_bridge_declaration(State(state): State<MeshState>, Json(decl): Json<BridgeDeclaration>) -> Response {
    let now = now_unix();
    let result = {
        let mut tree = state.tree.write().unwrap();
        tree.add(&decl, now)
    };
    match result {
        Ok(peer_id) => {
            tracing::info!(%peer_id, mesh_group = %decl.unsigned.mesh_group, "bridge declaration recorded");
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
        | BridgeError::SelfReference => StatusCode::BAD_REQUEST,
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

/// Receives a `ClaimReport`, verifies it, and records it into `state.claim_corroboration` --
/// same signature/pairing/clock-skew checks as a `BridgeDeclaration`, nothing about
/// `reporter_cluster` is checked here (see `corroboration.rs`'s own doc comment on why that's a
/// bare self-assertion, by design).
async fn receive_claim_report(State(state): State<MeshState>, Json(report): Json<ClaimReport>) -> Response {
    let now = now_unix();
    let result = {
        let mut corroboration = state.claim_corroboration.write().unwrap();
        corroboration.add(&report, now)
    };
    match result {
        Ok(peer_id) => {
            tracing::info!(%peer_id, claim_id = %report.unsigned.claim_id, "claim report recorded");
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
        | ClaimReportError::ClockSkew => StatusCode::BAD_REQUEST,
        ClaimReportError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
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

#[derive(Debug, thiserror::Error)]
pub enum PushError {
    #[error("request to {0} failed: {1}")]
    Request(String, reqwest::Error),
    #[error("{0} rejected the submission with status {1}")]
    Rejected(String, StatusCode),
}

pub async fn push_bridge_declaration(http: &reqwest::Client, address: &str, decl: &BridgeDeclaration) -> Result<(), PushError> {
    let url = format!("{}/oag-mesh/v1/bridge-declaration", address.trim_end_matches('/'));
    let response =
        http.post(&url).json(decl).send().await.map_err(|e| PushError::Request(address.to_string(), e))?;
    if !response.status().is_success() {
        return Err(PushError::Rejected(address.to_string(), response.status()));
    }
    Ok(())
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
pub async fn broadcast_bridge_declaration(state: &MeshState, decl: &BridgeDeclaration) {
    for peer in state.peers.iter() {
        if let Err(e) = push_bridge_declaration(&state.http, peer, decl).await {
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

pub async fn push_claim_report(http: &reqwest::Client, address: &str, report: &ClaimReport) -> Result<(), PushError> {
    let url = format!("{}/oag-mesh/v1/claim-report", address.trim_end_matches('/'));
    let response =
        http.post(&url).json(report).send().await.map_err(|e| PushError::Request(address.to_string(), e))?;
    if !response.status().is_success() {
        return Err(PushError::Rejected(address.to_string(), response.status()));
    }
    Ok(())
}

/// Same best-effort push, for a claim report -- a cluster's own corroboration signal only
/// strengthens across the mesh once its reports actually reach nodes in *other* clusters, which
/// is exactly what broadcasting to every configured peer does (and, same as the other two
/// broadcast functions, all it does -- no pull-based anti-entropy here either).
pub async fn broadcast_claim_report(state: &MeshState, report: &ClaimReport) {
    for peer in state.peers.iter() {
        if let Err(e) = push_claim_report(&state.http, peer, report).await {
            tracing::warn!(peer, error = %e, "failed to push claim report to peer");
        }
    }
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

        push_bridge_declaration(&state_b.http, &addr_a, &decl).await.unwrap();

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
        decl.unsigned.mesh_group = "tampered".to_string();

        let http = reqwest::Client::new();
        let err = push_bridge_declaration(&http, &addr_a, &decl).await.unwrap_err();
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
        let (addr_a, _state_a) = spawn(vec![]).await;
        let identity = PeerIdentity::generate();
        let report =
            crate::corroboration::build_and_sign(&identity, "claim-transport-test", "cluster-a", "blake3:abc", now_unix())
                .unwrap();

        push_claim_report(&reqwest::Client::new(), &addr_a, &report).await.unwrap();

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
        let (addr_a, _state_a) = spawn(vec![]).await;
        let identity = PeerIdentity::generate();
        let mut report =
            crate::corroboration::build_and_sign(&identity, "claim-tamper-test", "cluster-a", "blake3:abc", now_unix())
                .unwrap();
        report.unsigned.observed_value_hash = "blake3:tampered".to_string();

        let err = push_claim_report(&reqwest::Client::new(), &addr_a, &report).await.unwrap_err();
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
        push_bridge_declaration(&reqwest::Client::new(), &addr_a, &decl).await.unwrap();

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
        push_claim_report(&reqwest::Client::new(), &addr_a, &real_report).await.unwrap();
        push_claim_report(&reqwest::Client::new(), &addr_a, &fake_report).await.unwrap();

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
}
