//! A real peer-to-peer transport for both of this crate's message types -- its own HTTP wire
//! protocol, on its own listen address/port, separate from the base project's
//! `/oag/sync/v1/*` or `/oag/gateway/v1/query` entirely. Same "separate concern, separate
//! endpoint" posture the base repo's `spec/32-verified-internet-gateway.md` used for its own
//! query protocol, one layer up: this is `oag-mesh`'s own Layer-3-equivalent, structurally
//! parallel to the base project's `oag-sync`, not a part of it.
//!
//! The two message types get genuinely different transport treatment, because they have
//! genuinely different requirements:
//!
//! - `BridgeDeclaration` is signed by a real identity and loses nothing by ordinary propagation
//!   -- push it to known mesh peers, store what verifies, nothing about this needs hiding.
//! - `AnonymousEvent` carries no identity in its *payload*, but a plain HTTP POST still reveals
//!   the submitting connection's source IP to whoever receives it. **This transport does not
//!   hide that.** See `receive_anonymous_event`'s doc comment and `spec/04-transport.md` for
//!   exactly what is, and is not, achieved here -- this is a real, open gap, not an oversight.

use std::sync::{Arc, RwLock};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};

use crate::anonymous_event::{AnonymousEvent, AnonymousEventLog};
use crate::bridge::{BridgeDeclaration, BridgeError, MeshTree};

fn now_unix() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as i64
}

#[derive(Clone)]
pub struct MeshState {
    pub identity: Arc<oag_crypto::PeerIdentity>,
    pub tree: Arc<RwLock<MeshTree>>,
    pub event_log: Arc<RwLock<AnonymousEventLog>>,
    /// Other mesh nodes this one pushes its own declarations/events to -- static,
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
            peers: Arc::new(peers),
            http: Arc::new(reqwest::Client::new()),
        }
    }
}

pub fn router(state: MeshState) -> Router {
    Router::new()
        .route("/oag-mesh/v1/bridge-declaration", post(receive_bridge_declaration))
        .route("/oag-mesh/v1/anonymous-event", post(receive_anonymous_event))
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

/// Receives an `AnonymousEvent` and records it into `state.event_log`.
///
/// **Does not, and cannot, hide the submitting connection's source IP from this peer** -- that's
/// an inherent property of a plain HTTP POST, not a choice this handler makes. The payload
/// itself carries no identity by `anonymous_event.rs`'s own design; the *transport* carrying it
/// here is not anonymous at the network level. A real anonymizing submission path (routing
/// through an intermediary that doesn't log source-to-content correlation, onion-style layered
/// relaying, or similar) is explicitly not built -- see `spec/04-transport.md`'s open questions.
/// Treat this endpoint as "gets the (already-anonymous) payload from A to B," not as "hides who
/// submitted it."
async fn receive_anonymous_event(State(state): State<MeshState>, Json(event): Json<AnonymousEvent>) -> Response {
    let result = {
        let mut log = state.event_log.write().unwrap();
        log.record(event)
    };
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e.to_string() }))).into_response(),
    }
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

pub async fn push_anonymous_event(http: &reqwest::Client, address: &str, event: &AnonymousEvent) -> Result<(), PushError> {
    let url = format!("{}/oag-mesh/v1/anonymous-event", address.trim_end_matches('/'));
    let response =
        http.post(&url).json(event).send().await.map_err(|e| PushError::Request(address.to_string(), e))?;
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
pub async fn broadcast_anonymous_event(state: &MeshState, event: &AnonymousEvent) {
    for peer in state.peers.iter() {
        if let Err(e) = push_anonymous_event(&state.http, peer, event).await {
            tracing::warn!(peer, error = %e, "failed to push anonymous event to peer");
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
        push_anonymous_event(&http, &addr_a, &valid_event("transport-test-nonce")).await.unwrap();
        assert_eq!(state_a.event_log.read().unwrap().corroboration_for("transport-test-nonce"), 1);
    }

    #[tokio::test]
    async fn an_invalid_anonymous_event_is_rejected_over_the_wire() {
        let (addr_a, state_a) = spawn(vec![]).await;
        let mut event = valid_event("transport-test-nonce-2");
        event.observed_at += 1; // not rounded -- invalid
        let http = reqwest::Client::new();
        let err = push_anonymous_event(&http, &addr_a, &event).await.unwrap_err();
        assert!(matches!(err, PushError::Rejected(_, status) if status == StatusCode::BAD_REQUEST));
        assert_eq!(state_a.event_log.read().unwrap().corroboration_for("transport-test-nonce-2"), 0);
    }
}
