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

use std::collections::HashMap;
use std::hash::{BuildHasher, Hasher};
use std::sync::{Arc, RwLock};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};

use oag_crypto::PeerId;
use serde::{Deserialize, Serialize};

use crate::anonymous_event::{AnonymousEvent, AnonymousEventLog, EventFilter, ProofOfWork};
use crate::bridge::{BridgeDeclaration, BridgeError, BridgeProofOfWork, MeshMember, MeshTree};
use crate::corroboration::{ClaimCorroboration, ClaimReport, ClaimReportError, ClaimReportProofOfWork};
use crate::dispatch::{ResponderInbox, ResponderSubscriptionRegistry};
use crate::onion::{OnionLayer, OnionPayload};
use crate::membership::{MembershipAttestation, MembershipError, MembershipProofOfWork, MembershipRegistry};
use crate::rate_limit::{RateLimiter, TokenBucket};
use crate::responder::{ResponderAcknowledgment, ResponderAcknowledgmentError, ResponderAcknowledgmentLog};

/// Default cap on how many outbound `route-search` requests one distributed search may trigger
/// across its whole fan-out tree -- see `spec/13-distributed-route-search.md`'s
/// "Anti-amplification" section.
/// How long a TCP connection to a peer may take to establish before the attempt is abandoned.
///
/// This is the timeout that matters most in practice: a peer that is unreachable *and* silently
/// dropping packets (rather than refusing the connection) would otherwise hold the request open
/// until the operating system gives up, which can be minutes.
pub const HTTP_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Total time budget for one HTTP request to a peer, connect included.
///
/// `reqwest::Client::new()` sets no timeout at all, so without this a single non-responding peer
/// can stall a `sync_with_all_peers` tick or a route search indefinitely -- and both of those are
/// on the path of an *inbound* request, so one broken peer can hang a request from a third party
/// rather than only this node's own background work.
pub const HTTP_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Builds this crate's HTTP client with bounded connect and total-request timeouts.
///
/// Separate from `MeshState::new` so a test can build a client with short timeouts and prove the
/// bound actually holds without waiting the production value out.
pub fn build_http_client(
    connect_timeout: std::time::Duration,
    request_timeout: std::time::Duration,
) -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(connect_timeout)
        .timeout(request_timeout)
        .build()
        .expect("building a reqwest client with static timeout configuration cannot fail")
}

pub const DEFAULT_ROUTE_SEARCH_FANOUT_BUDGET: u32 = 256;
/// Default token-bucket capacity for inbound `route-search` requests on one node.
pub const ROUTE_SEARCH_RATE_LIMIT_CAPACITY: u32 = 8;
/// Default token-bucket refill rate, in tokens per second, for inbound `route-search` requests.
pub const ROUTE_SEARCH_RATE_LIMIT_PER_SEC: f64 = 2.0;
/// Default window for the per-identity responder-acknowledgment rate limit -- see
/// `spec/12-responder-acknowledgment.md`'s "rate limiting by identity" section.
pub const RESPONDER_ACK_RATE_LIMIT_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
/// Default cap on responder acknowledgments per identity per window. A starting point, not a
/// derived value -- a real deployment should tune it to its own responder traffic.
pub const RESPONDER_ACK_RATE_LIMIT_MAX: u32 = 60;
/// Default window for the per-attester membership-attestation rate limit.
pub const MEMBERSHIP_ATTESTATION_RATE_LIMIT_WINDOW: std::time::Duration =
    std::time::Duration::from_secs(60);
/// Default cap on membership attestations per attester per window -- a starting point, not a
/// derived value.
pub const MEMBERSHIP_ATTESTATION_RATE_LIMIT_MAX: u32 = 30;
/// Default maximum number of events `GET /oag-mesh/v1/anonymous-event/search` returns in one
/// response -- see `spec/11-responder-search.md`'s own pagination section.
pub const DEFAULT_EVENT_SEARCH_LIMIT: usize = 100;
/// Hard ceiling on a single search response, even when a caller asks for more.
pub const MAX_EVENT_SEARCH_LIMIT: usize = 1000;
/// A starting point for `spec/03`'s retention/expiry open question -- 30 days. Not a derived
/// value; a deployment should choose its own retention and call the prune endpoint.
pub const DEFAULT_EVENT_RETENTION_SECONDS: i64 = 30 * 24 * 60 * 60;

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

/// The wire shape for `POST /oag-mesh/v1/route-search` -- see `find_route_across_mesh`'s own doc
/// comment for the distributed search this drives. `already_asked` carries forward every peer
/// address already contacted *in this search*, so the same peer isn't asked twice as the query
/// fans out across hops -- a best-effort redundancy reducer, not what actually bounds the
/// search; `remaining_hops` reaching `0` is what guarantees this always terminates, covered in
/// `spec/13-distributed-route-search.md`. `fanout_budget` is the total number of outbound
/// `route-search` requests this search may still trigger across its whole fan-out tree,
/// divided among a node's peers as it propagates -- the anti-amplification bound covered in
/// that same file's "Anti-amplification" section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteSearchRequest {
    pub from: MeshMember,
    pub target: MeshMember,
    pub min_corroboration: usize,
    pub remaining_hops: u32,
    pub already_asked: Vec<String>,
    pub fanout_budget: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteSearchResponse {
    pub path: Option<Vec<MeshMember>>,
}

/// The wire shape for `GET /oag-mesh/v1/sync/heads` -- a cheap per-store version stamp so a
/// puller can skip stores that haven't changed since its last pull, instead of fetching all
/// five whole snapshots every time. See `spec/10-anti-entropy.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreHeads {
    /// Identifies this process's lifetime. A restart gets a new instance id even if the
    /// per-store sequences happen to line up, so a puller never mistakes a restarted peer's
    /// state for unchanged.
    pub instance_id: u64,
    pub bridge_tree: u64,
    pub claim_corroboration: u64,
    pub membership_registry: u64,
    pub anonymous_events: u64,
    pub responder_acknowledgments: u64,
}

/// A per-process random id for `StoreHeads::instance_id`, from the same per-process random
/// seed the jitter helper uses -- it only has to be unique per process lifetime, not
/// cryptographic.
fn random_instance_id() -> u64 {
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0),
    );
    hasher.finish()
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
    /// Node-wide token bucket for inbound `POST /oag-mesh/v1/route-search` requests -- the one
    /// endpoint that can turn a single request into real outbound fan-out traffic. In-memory
    /// only, so a restart resets it; see `spec/13`'s "Anti-amplification" section.
    pub route_search_limiter: Arc<RwLock<TokenBucket>>,
    /// Per-identity fixed-window limiter for `POST /oag-mesh/v1/responder-acknowledgment` --
    /// the griefing mitigation `spec/12-responder-acknowledgment.md` names as "rate limiting by
    /// identity". In-memory only, so a restart resets it.
    pub responder_ack_limiter: Arc<RateLimiter>,
    /// Identifies this process's lifetime for the heads check -- see `StoreHeads` and
    /// `spec/10-anti-entropy.md`.
    pub instance_id: u64,
    /// The last heads this node pulled from each peer, so unchanged stores can be skipped on
    /// the next pull. Keyed by peer address. In-memory only, so a restart re-pulls once.
    pub sync_heads: Arc<RwLock<HashMap<String, StoreHeads>>>,
    /// If set, this node acts as a one-hop anonymous relay: every verified anonymous event it
    /// receives is also forwarded to this address, which sees the relay's address rather than
    /// the original submitter's. See `spec/04-transport.md`'s anonymity section.
    pub anonymous_event_relay_target: Option<String>,
    /// Per-attester fixed-window limiter for `POST /oag-mesh/v1/membership-attestation` --
    /// bounds how fast one identity can vouch for many subjects, the gap `spec/09` names as
    /// "no weighting by how many subjects an attester vouches for, or how often". In-memory
    /// only, so a restart resets it.
    pub membership_attestation_limiter: Arc<RateLimiter>,
    /// Blinded responder subscriptions: a responder-chosen random id -> filter. The node never
    /// learns who the responder is, only that a subscription exists. In-memory only -- a
    /// restart loses it, and the responder re-registers. See `spec/14`.
    pub responder_subscriptions: Arc<RwLock<ResponderSubscriptionRegistry>>,
    /// Per-subscription inboxes, filled when an event matching a subscription arrives. The
    /// responder drains it by polling. In-memory only -- a restart clears it, and the responder
    /// can re-search the log. See `spec/14`.
    pub responder_inbox: Arc<RwLock<ResponderInbox>>,
    /// What this node has observed about each peer's deliverability, used to order route-search
    /// fan-out so the fan-out budget is spent on peers that have been answering. In-memory only,
    /// so a restart re-learns it; it orders and never excludes. See `spec/13` and
    /// `link_quality`'s own module docs.
    pub link_quality: Arc<crate::link_quality::LinkQualityLedger>,
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
            http: Arc::new(build_http_client(HTTP_CONNECT_TIMEOUT, HTTP_REQUEST_TIMEOUT)),
            route_search_limiter: Arc::new(RwLock::new(TokenBucket::new(
                ROUTE_SEARCH_RATE_LIMIT_CAPACITY,
                ROUTE_SEARCH_RATE_LIMIT_PER_SEC,
            ))),
            responder_ack_limiter: Arc::new(RateLimiter::new(
                RESPONDER_ACK_RATE_LIMIT_WINDOW,
                RESPONDER_ACK_RATE_LIMIT_MAX,
            )),
            instance_id: random_instance_id(),
            sync_heads: Arc::new(RwLock::new(HashMap::new())),
            anonymous_event_relay_target: None,
            membership_attestation_limiter: Arc::new(RateLimiter::new(
                MEMBERSHIP_ATTESTATION_RATE_LIMIT_WINDOW,
                MEMBERSHIP_ATTESTATION_RATE_LIMIT_MAX,
            )),
            responder_subscriptions: Arc::new(RwLock::new(ResponderSubscriptionRegistry::new())),
            responder_inbox: Arc::new(RwLock::new(ResponderInbox::new())),
            link_quality: Arc::new(crate::link_quality::LinkQualityLedger::default()),
        }
    }

    /// Snapshots all seven in-memory stores to `bridge_tree.json`,
    /// `claim_corroboration.json`, `anonymous_events.json`, `membership_registry.json`,
    /// `responder_acknowledgments.json`, `responder_subscriptions.json`, and
    /// `responder_inbox.json` under `dir`, overwriting whatever was there -- see `persistence`'s
    /// own module doc comment for what this does and does not guarantee (atomic on Unix via
    /// temp-file-plus-rename, rewrites the whole file every call). This crate doesn't call this
    /// automatically on any write; a caller decides when to save (periodically, on a clean
    /// shutdown, after every N writes -- whatever fits its own deployment).
    pub fn save_to_dir(&self, dir: &std::path::Path) -> Result<(), crate::persistence::PersistenceError> {
        // Write all seven stores, recording each one's name, then write a commit marker
        // describing the set. Each file is individually atomic (temp + rename), so a crash
        // mid-save leaves the previous file intact and an orphaned temp -- but it can leave the
        // *set* torn, with some stores from the new snapshot and some from the old. The marker
        // closes that window: it is written last, and a reader trusts the set only when every
        // file matches what the marker recorded. See `persistence`'s own doc comment.
        let mut entries = Vec::with_capacity(crate::persistence::STORE_FILES.len());
        // One save plus its recorded hash, so the marker describes the bytes actually on disk.
        macro_rules! save_store {
            ($name:expr, $value:expr) => {{
                crate::persistence::save_json(&dir.join($name), &$value)?;
                entries.push(crate::persistence::CommitEntry {
                    file: $name.to_string(),
                    blake3: crate::persistence::hash_file(&dir.join($name))?,
                });
            }};
        }
        save_store!(
            crate::persistence::STORE_FILES[0],
            self.tree.read().unwrap().snapshot()
        );
        save_store!(
            crate::persistence::STORE_FILES[1],
            self.claim_corroboration.read().unwrap().snapshot()
        );
        save_store!(
            crate::persistence::STORE_FILES[2],
            &*self.event_log.read().unwrap()
        );
        save_store!(
            crate::persistence::STORE_FILES[3],
            self.membership_registry.read().unwrap().snapshot()
        );
        save_store!(
            crate::persistence::STORE_FILES[4],
            self.responder_acknowledgments.read().unwrap().snapshot()
        );
        save_store!(
            crate::persistence::STORE_FILES[5],
            self.responder_subscriptions.read().unwrap().subscriptions()
        );
        save_store!(
            crate::persistence::STORE_FILES[6],
            self.responder_inbox.read().unwrap().inbox()
        );
        crate::persistence::write_commit_marker(dir, entries)?;
        Ok(())
    }

    /// Builds a fresh `MeshState` for `identity`/`peers`, loading each of the seven stores from
    /// whatever `save_to_dir` previously wrote to `dir` -- or starting empty for any file that
    /// doesn't exist yet (a brand-new node's first run).
    pub fn load_from_dir(
        identity: oag_crypto::PeerIdentity,
        peers: Vec<String>,
        dir: &std::path::Path,
    ) -> Result<Self, crate::persistence::PersistenceError> {
        // Refuse a torn set rather than loading it. If there is no marker this is either a first
        // run or a directory written before markers existed, and the old behaviour (load whatever
        // is there) is deliberately preserved -- refusing here would break every existing
        // deployment on upgrade. If a marker *is* present and the files do not match it, the save
        // was interrupted and some stores are from a different snapshot; acting on that would be
        // worse than starting empty, because nothing would reveal the disagreement.
        crate::persistence::verify_commit_marker(dir)?;
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
        let subscriptions = crate::persistence::load_json::<HashMap<String, EventFilter>>(
            &dir.join("responder_subscriptions.json"),
        )?
        .unwrap_or_default();
        let inbox = crate::persistence::load_json::<HashMap<String, Vec<AnonymousEvent>>>(
            &dir.join("responder_inbox.json"),
        )?
        .unwrap_or_default();
        Ok(Self {
            identity: Arc::new(identity),
            tree: Arc::new(RwLock::new(tree)),
            event_log: Arc::new(RwLock::new(event_log)),
            claim_corroboration: Arc::new(RwLock::new(claim_corroboration)),
            membership_registry: Arc::new(RwLock::new(membership_registry)),
            responder_acknowledgments: Arc::new(RwLock::new(responder_acknowledgments)),
            peers: Arc::new(peers),
            http: Arc::new(build_http_client(HTTP_CONNECT_TIMEOUT, HTTP_REQUEST_TIMEOUT)),
            route_search_limiter: Arc::new(RwLock::new(TokenBucket::new(
                ROUTE_SEARCH_RATE_LIMIT_CAPACITY,
                ROUTE_SEARCH_RATE_LIMIT_PER_SEC,
            ))),
            responder_ack_limiter: Arc::new(RateLimiter::new(
                RESPONDER_ACK_RATE_LIMIT_WINDOW,
                RESPONDER_ACK_RATE_LIMIT_MAX,
            )),
            instance_id: random_instance_id(),
            sync_heads: Arc::new(RwLock::new(HashMap::new())),
            anonymous_event_relay_target: None,
            membership_attestation_limiter: Arc::new(RateLimiter::new(
                MEMBERSHIP_ATTESTATION_RATE_LIMIT_WINDOW,
                MEMBERSHIP_ATTESTATION_RATE_LIMIT_MAX,
            )),
            responder_subscriptions: Arc::new(RwLock::new(ResponderSubscriptionRegistry::from_subscriptions(
                subscriptions,
            ))),
            responder_inbox: Arc::new(RwLock::new(ResponderInbox::from_inbox(inbox))),
            link_quality: Arc::new(crate::link_quality::LinkQualityLedger::default()),
        })
    }
}

pub fn router(state: MeshState) -> Router {
    Router::new()
        .route("/oag-mesh/v1/bridge-declaration", post(receive_bridge_declaration))
        .route("/oag-mesh/v1/anonymous-event", post(receive_anonymous_event))
        .route("/oag-mesh/v1/anonymous-event/search", get(search_anonymous_events))
        .route("/oag-mesh/v1/anonymous-event/prune", post(prune_anonymous_events))
        .route(
            "/oag-mesh/v1/responder-subscriptions",
            post(register_responder_subscription),
        )
        .route(
            "/oag-mesh/v1/responder-subscriptions/{subscription_id}",
            delete(unregister_responder_subscription),
        )
        .route(
            "/oag-mesh/v1/responder-inbox/{subscription_id}",
            get(get_responder_inbox),
        )
        .route("/oag-mesh/v1/onion-key", get(get_onion_key))
        .route("/oag-mesh/v1/onion", post(receive_onion_layer))
        .route("/oag-mesh/v1/claim-report", post(receive_claim_report))
        .route("/oag-mesh/v1/membership-attestation", post(receive_membership_attestation))
        .route("/oag-mesh/v1/responder-acknowledgment", post(receive_responder_acknowledgment))
        .route(
            "/oag-mesh/v1/responder-acknowledgment/{corroboration_nonce}",
            get(get_active_responders),
        )
        .route("/oag-mesh/v1/route-search", post(receive_route_search))
        .route("/oag-mesh/v1/claim-report/{claim_id}/best", get(get_best_corroborated_value))
        .route(
            "/oag-mesh/v1/claim-report/{claim_id}/best-cross-checked",
            get(get_best_corroborated_value_cross_checked),
        )
        .route(
            "/oag-mesh/v1/claim-report/{claim_id}/best-fully-cross-checked",
            get(get_best_corroborated_value_fully_cross_checked),
        )
        .route("/oag-mesh/v1/sync/heads", get(get_sync_heads))
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
    record_anonymous_event(&state, submission).await
}

/// Records a verified anonymous event, dispatches it to matching blinded responder inboxes, and
/// forwards it to this node's one-hop anonymity relay if one is configured. Shared by the direct
/// endpoint and the onion layer's final hop.
async fn record_anonymous_event(state: &MeshState, submission: AnonymousEventSubmission) -> Response {
    // Clone before `record` moves them, so a relay can forward the identical verified event.
    let relay_event = submission.event.clone();
    let relay_pow = submission.pow;
    let result = {
        let mut log = state.event_log.write().unwrap();
        log.record(submission.event, submission.pow)
    };
    match result {
        Ok(()) => {
            // Dispatch: append the event to every matching blinded responder inbox. Best-effort
            // and synchronous with the submission -- a responder polling its inbox sees the
            // event after the 204. See `spec/14`.
            {
                let subscriptions = state.responder_subscriptions.read().unwrap();
                let mut inbox = state.responder_inbox.write().unwrap();
                inbox.push_matching(&relay_event, subscriptions.subscriptions());
            }
            // One-hop anonymity relay: the target sees this node's address, not the original
            // submitter's. Best-effort -- a relay failure never rejects the submission, which
            // the relay already recorded. See `spec/04-transport.md`.
            if let Some(target) = state.anonymous_event_relay_target.clone() {
                if let Err(e) = push_anonymous_event(&state.http, &target, &relay_event, relay_pow).await {
                    tracing::warn!(target, error = %e, "failed to relay anonymous event");
                }
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e.to_string() }))).into_response(),
    }
}

/// Read-only: this node's X25519 public key for onion routing, derived from its Ed25519
/// identity. A reporter computes the same key from the relay's Ed25519 public key. See
/// `spec/15-onion-routing.md`.
async fn get_onion_key(State(state): State<MeshState>) -> Response {
    let key = crate::onion::x25519_public_key(&state.identity);
    Json(serde_json::json!({
        "peer_id": state.identity.peer_id().to_string(),
        "x25519_public_key": hex::encode(key.to_bytes()),
    }))
    .into_response()
}

/// Peels one onion layer. A relay forwards the inner layer to the next hop; the exit relay
/// forwards the recovered submission to the target's direct endpoint. See `spec/15`.
async fn receive_onion_layer(State(state): State<MeshState>, Json(layer): Json<OnionLayer>) -> Response {
    let inner = match crate::onion::peel_layer(&layer, &state.identity) {
        Ok(inner) => inner,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    };
    match inner.payload {
        OnionPayload::Layer(next_layer) => match push_onion_layer(&state.http, &inner.next_hop, &next_layer).await {
            Ok(()) => StatusCode::NO_CONTENT.into_response(),
            Err(e) => (StatusCode::BAD_GATEWAY, Json(serde_json::json!({ "error": e.to_string() }))).into_response(),
        },
        OnionPayload::Submission { event, pow } => match push_anonymous_event(&state.http, &inner.next_hop, &event, pow).await
        {
            Ok(()) => StatusCode::NO_CONTENT.into_response(),
            Err(e) => (StatusCode::BAD_GATEWAY, Json(serde_json::json!({ "error": e.to_string() }))).into_response(),
        },
    }
}

/// The query-string shape for `GET /oag-mesh/v1/anonymous-event/search`: the filter fields plus
/// pagination. `limit` defaults to `DEFAULT_EVENT_SEARCH_LIMIT` and is clamped to
/// `MAX_EVENT_SEARCH_LIMIT`; `offset` defaults to `0`.
#[derive(Debug, Deserialize)]
struct EventSearchQuery {
    #[serde(flatten)]
    filter: EventFilter,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
}

/// Read-only: every event in this node's own `AnonymousEventLog` matching the query-string filter
/// (`kind`, `min_severity`, `location_prefix`, `since` -- see `anonymous_event::EventFilter`),
/// paginated by `limit`/`offset`. This is the one piece of
/// `spec/03-anonymous-event-rfc.md`'s "Reaching a responder" open question this crate actually
/// answers, and it is a narrow one -- see `spec/11-responder-search.md` for exactly what it is
/// and is not. Same node-local-only, no-auth scope as every other `GET` endpoint in this file:
/// it searches this node's own log, not the wider mesh, and anyone who can reach the listen
/// address can run any search. The response includes `total` (all matches, before pagination)
/// so a caller can page through a large result set.
async fn search_anonymous_events(State(state): State<MeshState>, Query(query): Query<EventSearchQuery>) -> Response {
    let log = state.event_log.read().unwrap();
    let matches = log.search(&query.filter);
    let total = matches.len();
    let offset = query.offset.unwrap_or(0).min(total);
    let limit = query.limit.unwrap_or(DEFAULT_EVENT_SEARCH_LIMIT).min(MAX_EVENT_SEARCH_LIMIT);
    let events: Vec<&AnonymousEvent> = matches.into_iter().skip(offset).take(limit).collect();
    Json(serde_json::json!({
        "events": events,
        "total": total,
        "limit": limit,
        "offset": offset,
    }))
    .into_response()
}

/// The body for `POST /oag-mesh/v1/anonymous-event/prune` -- an explicit operator action to
/// prune events older than `before` (unix seconds). See `spec/03`'s "Retention/expiry".
#[derive(Debug, Deserialize)]
struct PruneRequest {
    before: i64,
}

/// Prunes this node's own `AnonymousEventLog` before `before` (unix seconds), returning the
/// number of events removed. Explicit, not automatic -- same node-local, no-auth scope as every
/// other endpoint here. See `spec/03-anonymous-event-rfc.md`'s "Retention/expiry" open question.
async fn prune_anonymous_events(State(state): State<MeshState>, Json(request): Json<PruneRequest>) -> Response {
    let removed = state.event_log.write().unwrap().prune_before(request.before);
    Json(serde_json::json!({ "removed": removed })).into_response()
}

/// The body for `POST /oag-mesh/v1/responder-subscriptions` -- a responder-chosen random id and
/// a filter. The node never learns which `PeerIdentity` stands behind the id; see `spec/14`.
#[derive(Debug, Deserialize)]
struct SubscriptionRegistration {
    subscription_id: String,
    #[serde(flatten)]
    filter: EventFilter,
}

/// Registers or replaces a blinded responder subscription. Nothing about the responder's
/// identity is recorded -- only the id they chose and the filter they want. See `spec/14`.
async fn register_responder_subscription(
    State(state): State<MeshState>,
    Json(registration): Json<SubscriptionRegistration>,
) -> Response {
    state
        .responder_subscriptions
        .write()
        .unwrap()
        .upsert(registration.subscription_id, registration.filter);
    StatusCode::NO_CONTENT.into_response()
}

/// Removes a blinded responder subscription. `404` if the id was not registered.
async fn unregister_responder_subscription(
    State(state): State<MeshState>,
    Path(subscription_id): Path<String>,
) -> Response {
    if state.responder_subscriptions.write().unwrap().remove(&subscription_id) {
        StatusCode::NO_CONTENT.into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

/// Drains a blinded responder's inbox -- the events that matched its subscription since the
/// last poll. Nothing is pushed; the responder has to ask. See `spec/14`.
async fn get_responder_inbox(State(state): State<MeshState>, Path(subscription_id): Path<String>) -> Response {
    let events = state.responder_inbox.write().unwrap().drain(&subscription_id);
    Json(serde_json::json!({ "events": events })).into_response()
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
    let (attester_peer_id, subject_peer_id) = match crate::membership::verify(&submission.attestation, now) {
        Ok(ids) => ids,
        Err(e) => return membership_error_response(e),
    };
    // Rate limiting by attester -- the gap spec/09 names as "no weighting by how many subjects
    // an attester vouches for, or how often". Checked after verification, so an invalid
    // signature never costs a token.
    if let Err(retry_after) = state.membership_attestation_limiter.check(&attester_peer_id.to_string()) {
        let retry_after_seconds = retry_after.as_secs().max(1);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(axum::http::header::RETRY_AFTER, retry_after_seconds.to_string())],
            Json(serde_json::json!({
                "error": "membership attestation rate limit exceeded",
                "retry_after_seconds": retry_after_seconds,
            })),
        )
            .into_response();
    }
    let result = {
        let mut registry = state.membership_registry.write().unwrap();
        registry.add_verified(&submission.attestation, submission.pow, attester_peer_id, subject_peer_id)
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
    let peer_id = match crate::responder::verify(&submission.acknowledgment, now) {
        Ok(peer_id) => peer_id,
        Err(e) => return responder_acknowledgment_error_response(e),
    };
    // Rate limiting by identity -- the griefing mitigation spec/12 names. Checked after
    // verification, so an invalid signature never costs a token; see that file's own section.
    if let Err(retry_after) = state.responder_ack_limiter.check(&peer_id.to_string()) {
        let retry_after_seconds = retry_after.as_secs().max(1);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(axum::http::header::RETRY_AFTER, retry_after_seconds.to_string())],
            Json(serde_json::json!({
                "error": "responder acknowledgment rate limit exceeded",
                "retry_after_seconds": retry_after_seconds,
            })),
        )
            .into_response();
    }
    {
        let mut log = state.responder_acknowledgments.write().unwrap();
        log.add_verified(&submission.acknowledgment, peer_id);
    }
    tracing::info!(%peer_id, corroboration_nonce = %submission.acknowledgment.unsigned.corroboration_nonce, "responder acknowledgment recorded");
    StatusCode::NO_CONTENT.into_response()
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

/// The recursive core of distributed route search (`spec/13-distributed-route-search.md`),
/// shared by `find_route_across_mesh` (the public entry point a caller starts a search with)
/// and `receive_route_search` (what runs on *each* node the search reaches, including the one
/// that started it) -- the same function either way, which is what makes the search distributed
/// at all: every hop re-runs this exact logic against its own node's own local
/// `bridge::MeshTree`, not a single node doing all the work.
///
/// Checks this node's own local `MeshTree::shortest_path` first -- free, no network -- and
/// returns immediately if it already has enough edges to answer. Otherwise, if `remaining_hops`
/// is still above `0`, fans out the identical query (with `remaining_hops - 1`) to every
/// configured peer not already in `already_asked`, in parallel, and returns the shortest path
/// any of them found (if several did). `remaining_hops` reaching `0` is the **only** thing that
/// guarantees this terminates -- `already_asked` reduces redundant re-asking of a peer already
/// contacted earlier in this specific search, it does not guarantee each node in the mesh is
/// visited at most once overall (two different branches of the fan-out can independently reach
/// the same peer with different `already_asked` histories and ask it again). See `spec/13`'s own
/// "what this explicitly is not" for this stated in full, including the amplification cost this
/// trades for a chance at finding a path no single node knows end-to-end.
async fn search_for_route(
    state: &MeshState,
    from: &MeshMember,
    target: &MeshMember,
    min_corroboration: usize,
    remaining_hops: u32,
    already_asked: &[String],
    fanout_budget: u32,
) -> Option<Vec<MeshMember>> {
    if let Some(path) = state.tree.read().unwrap().shortest_path(from, target, min_corroboration) {
        return Some(path);
    }
    if remaining_hops == 0 || fanout_budget == 0 {
        return None;
    }

    // Order by observed deliverability before taking the first `ask_count`: the fan-out budget
    // is the scarce resource here, and spending it on a peer that has been failing for hours is
    // the one waste this search can avoid. Ordering only -- every peer stays in the list, so a
    // healthy-looking peer that is actually down is still tried when the budget allows.
    let peers_to_ask: Vec<String> = state
        .link_quality
        .ordered(&state.peers.iter().filter(|peer| !already_asked.contains(peer)).cloned().collect::<Vec<_>>());
    if peers_to_ask.is_empty() {
        return None;
    }

    // Spend one unit of the search's fan-out budget per outbound request, and divide what is
    // left among the peers this node asks -- so the sum of all outbound requests a single
    // search can cause is bounded by the budget it started with, no matter how the fan-out
    // branches. See `spec/13`'s "Anti-amplification" section.
    let ask_count = peers_to_ask.len().min(fanout_budget as usize);
    let peers_to_ask: Vec<String> = peers_to_ask.into_iter().take(ask_count).collect();
    let remaining_for_children = fanout_budget - ask_count as u32;
    let per_child_budget = remaining_for_children / ask_count as u32;

    let mut newly_asked = already_asked.to_vec();
    newly_asked.extend(peers_to_ask.iter().cloned());

    let child_request = RouteSearchRequest {
        from: from.clone(),
        target: target.clone(),
        min_corroboration,
        remaining_hops: remaining_hops - 1,
        already_asked: newly_asked,
        fanout_budget: per_child_budget,
    };

    let mut tasks = tokio::task::JoinSet::new();
    for peer in peers_to_ask {
        let http = state.http.clone();
        let request = child_request.clone();
        let link_quality = state.link_quality.clone();
        tasks.spawn(async move {
            let result = push_route_search(&http, &peer, &request).await.ok().flatten();
            // Record the outcome either way: a peer that did not answer is exactly the
            // observation the next search needs, and it is invisible if only successes are
            // recorded.
            link_quality.record(&peer, result.is_some(), crate::link_quality::now_unix());
            result
        });
    }

    let mut best: Option<Vec<MeshMember>> = None;
    while let Some(result) = tasks.join_next().await {
        if let Ok(Some(path)) = result {
            if best.as_ref().is_none_or(|current_best| path.len() < current_best.len()) {
                // A path of two members is a direct edge -- the shortest possible
                // path for distinct `from`/`target`, so no other branch can beat
                // it. Stop the fan-out early rather than waiting for every peer
                // to answer; the "shortest among those found" guarantee is
                // preserved because a direct edge is the global minimum. See
                // `spec/13`'s "deduplication" note.
                let is_direct = path.len() <= 2;
                best = Some(path);
                if is_direct {
                    tasks.abort_all();
                    break;
                }
            }
        }
    }
    best
}

/// Receives a `RouteSearchRequest` and answers it by running `search_for_route` against this
/// node's own state -- see that function's doc comment for exactly what happens here, including
/// the fan-out to this node's own peers if its own local `MeshTree` doesn't already have an
/// answer.
async fn receive_route_search(State(state): State<MeshState>, Json(request): Json<RouteSearchRequest>) -> Response {
    // Node-wide token bucket: this transport has no requester identity, so it cannot tell one
    // caller from another. See `spec/13`'s "Anti-amplification" section for exactly what this
    // does and does not bound.
    let retry_after = {
        let mut limiter = state.route_search_limiter.write().unwrap();
        if limiter.try_take() {
            None
        } else {
            Some(limiter.retry_after())
        }
    };
    if let Some(retry_after) = retry_after {
        let retry_after_seconds = retry_after.as_secs().max(1);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(axum::http::header::RETRY_AFTER, retry_after_seconds.to_string())],
            Json(serde_json::json!({
                "error": "route search rate limit exceeded",
                "retry_after_seconds": retry_after_seconds,
            })),
        )
            .into_response();
    }

    let path = search_for_route(
        &state,
        &request.from,
        &request.target,
        request.min_corroboration,
        request.remaining_hops,
        &request.already_asked,
        request.fanout_budget,
    )
    .await;
    Json(RouteSearchResponse { path }).into_response()
}

/// Searches the mesh for a path from `from` to `target`, starting with this node's own local
/// `bridge::MeshTree::shortest_path` and, if that alone isn't enough, fanning the same query out
/// across up to `max_hops` of peer-to-peer hops -- "moving forward through random clusters of
/// nodes" (the mesh's own founding principle, `README.md`'s "Founding principle: bounded-hop
/// reachability") when a single node's own knowledge of the mesh isn't enough on its own.
///
/// **Not the same guarantee as `MeshTree::shortest_path` run against a single node's complete
/// data.** A path found this way is real (every edge along it came from an actually-verified
/// `BridgeDeclaration` somewhere in the mesh, same as any local result), but it is not guaranteed
/// to be the *global* shortest path -- only the shortest one found among whatever this search
/// actually reached within `max_hops`, which depends on which peers happened to answer and in
/// what order. `None` means no path was found within the hop budget, not that no path exists
/// anywhere in the mesh. See `spec/13-distributed-route-search.md` for this stated in full,
/// including the fan-out/amplification cost of running this at all.
pub async fn find_route_across_mesh(
    state: &MeshState,
    from: &MeshMember,
    target: &MeshMember,
    min_corroboration: usize,
    max_hops: u32,
) -> Option<Vec<MeshMember>> {
    find_route_across_mesh_with_budget(
        state,
        from,
        target,
        min_corroboration,
        max_hops,
        DEFAULT_ROUTE_SEARCH_FANOUT_BUDGET,
    )
    .await
}

/// Same as `find_route_across_mesh`, with an explicit cap on how many outbound `route-search`
/// requests this search may trigger across its whole fan-out tree -- divided among a node's
/// peers as the search propagates, so the total is bounded by `fanout_budget` no matter how the
/// branches split. `DEFAULT_ROUTE_SEARCH_FANOUT_BUDGET` is what `find_route_across_mesh` uses;
/// `0` disables all forwarding (local knowledge only). See `spec/13`'s "Anti-amplification"
/// section.
pub async fn find_route_across_mesh_with_budget(
    state: &MeshState,
    from: &MeshMember,
    target: &MeshMember,
    min_corroboration: usize,
    max_hops: u32,
    fanout_budget: u32,
) -> Option<Vec<MeshMember>> {
    search_for_route(state, from, target, min_corroboration, max_hops, &[], fanout_budget).await
}

pub async fn push_route_search(
    http: &reqwest::Client,
    address: &str,
    request: &RouteSearchRequest,
) -> Result<Option<Vec<MeshMember>>, PullError> {
    let url = format!("{}/oag-mesh/v1/route-search", address.trim_end_matches('/'));
    let response =
        http.post(&url).json(request).send().await.map_err(|e| PullError::Request(address.to_string(), e))?;
    if !response.status().is_success() {
        return Err(PullError::Rejected(address.to_string(), response.status()));
    }
    let parsed: RouteSearchResponse =
        response.json().await.map_err(|e| PullError::Request(address.to_string(), e))?;
    Ok(parsed.path)
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

/// Read-only: this node's per-store version stamps, for `pull_and_merge`'s heads check -- the
/// cheap first step of a pull, so unchanged stores can be skipped. See
/// `spec/10-anti-entropy.md`.
async fn get_sync_heads(State(state): State<MeshState>) -> Response {
    Json(StoreHeads {
        instance_id: state.instance_id,
        bridge_tree: state.tree.read().unwrap().sequence(),
        claim_corroboration: state.claim_corroboration.read().unwrap().sequence(),
        membership_registry: state.membership_registry.read().unwrap().sequence(),
        anonymous_events: state.event_log.read().unwrap().sequence(),
        responder_acknowledgments: state.responder_acknowledgments.read().unwrap().sequence(),
    })
    .into_response()
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
    #[error("onion error: {0}")]
    Onion(String),
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

#[derive(Debug, Deserialize)]
struct OnionKeyResponse {
    #[allow(dead_code)]
    peer_id: String,
    x25519_public_key: String,
}

/// Fetches a relay's X25519 public key for onion routing -- derived from the relay's Ed25519
/// identity, so the reporter can compute it from a key it already knows. See `spec/15`.
pub async fn fetch_onion_key(http: &reqwest::Client, address: &str) -> Result<x25519_dalek::PublicKey, PushError> {
    let url = format!("{}/oag-mesh/v1/onion-key", address.trim_end_matches('/'));
    let response = http.get(&url).send().await.map_err(|e| PushError::Request(address.to_string(), e))?;
    if !response.status().is_success() {
        return Err(PushError::Rejected(address.to_string(), response.status()));
    }
    let key: OnionKeyResponse = response.json().await.map_err(|e| PushError::Request(address.to_string(), e))?;
    let bytes = hex::decode(&key.x25519_public_key).map_err(|e| PushError::Onion(e.to_string()))?;
    let array: [u8; 32] = bytes.try_into().map_err(|_| PushError::Onion("bad key length".to_string()))?;
    Ok(x25519_dalek::PublicKey::from(array))
}

/// Sends one onion layer to a relay. See `spec/15`.
pub async fn push_onion_layer(
    http: &reqwest::Client,
    address: &str,
    layer: &OnionLayer,
) -> Result<(), PushError> {
    let url = format!("{}/oag-mesh/v1/onion", address.trim_end_matches('/'));
    let response = http.post(&url).json(layer).send().await.map_err(|e| PushError::Request(address.to_string(), e))?;
    if !response.status().is_success() {
        return Err(PushError::Rejected(address.to_string(), response.status()));
    }
    Ok(())
}

/// Submits an anonymous event through an onion path: fetches each relay's X25519 key, builds
/// the layered onion, and sends the outermost layer to the guard. No single relay learns both
/// the reporter and the target. See `spec/15`.
pub async fn push_anonymous_event_onion(
    http: &reqwest::Client,
    path: &[String],
    target: &str,
    event: &AnonymousEvent,
    pow: ProofOfWork,
) -> Result<(), PushError> {
    if path.is_empty() {
        return Err(PushError::Onion("empty relay path".to_string()));
    }
    let mut relay_keys = Vec::with_capacity(path.len());
    for address in path {
        relay_keys.push(fetch_onion_key(http, address).await?);
    }
    let guard_layer =
        crate::onion::build_onion(path, target, event, pow, &relay_keys).map_err(|e| PushError::Onion(e.to_string()))?;
    push_onion_layer(http, &path[0], &guard_layer).await
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
/// Pulls and merges one peer, returning whether the interaction *delivered* something usable --
/// which is what `link_quality` records. The boolean is not a new requirement on callers: it is
/// the difference between "answered" and "failed", and until now that distinction was dropped on
/// the floor even though the fan-out budget is spent on exactly it.
pub async fn pull_and_merge(state: &MeshState, address: &str) -> bool {
    let remote_heads = match pull_heads(&state.http, address).await {
        Ok(heads) => heads,
        Err(e) => {
            tracing::warn!(address, error = %e, "failed to pull sync heads from peer; falling back to a full pull");
            let delivered = pull_changed_stores(state, address, [true; 5]).await;
            state.link_quality.record(address, delivered, crate::link_quality::now_unix());
            return delivered;
        }
    };

    let last_heads = state.sync_heads.read().unwrap().get(address).copied();
    let changed = heads_changed(last_heads, remote_heads);
    let all_ok = pull_changed_stores(state, address, changed).await;
    state.link_quality.record(address, all_ok, crate::link_quality::now_unix());
    if all_ok {
        state.sync_heads.write().unwrap().insert(address.to_string(), remote_heads);
    }
    all_ok
}

/// Which of the five stores differ between the last heads this node pulled from a peer and
/// the peer's current heads. A peer never seen before (or a restarted one, identified by a new
/// `instance_id`) is fully pulled.
fn heads_changed(last: Option<StoreHeads>, remote: StoreHeads) -> [bool; 5] {
    match last {
        None => [true; 5],
        Some(last) => {
            let instance_changed = last.instance_id != remote.instance_id;
            [
                instance_changed || last.bridge_tree != remote.bridge_tree,
                instance_changed || last.claim_corroboration != remote.claim_corroboration,
                instance_changed || last.membership_registry != remote.membership_registry,
                instance_changed || last.anonymous_events != remote.anonymous_events,
                instance_changed || last.responder_acknowledgments != remote.responder_acknowledgments,
            ]
        }
    }
}

/// Pulls and merges only the stores marked `true` in `changed`, returning whether every pull
/// that was attempted succeeded. A failed store is left at its old state and, because the
/// caller only records the remote heads when this returns `true`, retried on the next pull.
async fn pull_changed_stores(state: &MeshState, address: &str, changed: [bool; 5]) -> bool {
    let [bridge, claims, membership, events, acks] = changed;
    let mut all_ok = true;

    if bridge {
        match pull_bridge_tree(&state.http, address).await {
            Ok(snapshot) => {
                state.tree.write().unwrap().merge_snapshot(snapshot);
            }
            Err(e) => {
                tracing::warn!(address, error = %e, "failed to pull bridge tree from peer");
                all_ok = false;
            }
        }
    }
    if claims {
        match pull_claim_corroboration(&state.http, address).await {
            Ok(snapshot) => {
                state.claim_corroboration.write().unwrap().merge_snapshot(snapshot);
            }
            Err(e) => {
                tracing::warn!(address, error = %e, "failed to pull claim corroboration from peer");
                all_ok = false;
            }
        }
    }
    if membership {
        match pull_membership_registry(&state.http, address).await {
            Ok(snapshot) => {
                state.membership_registry.write().unwrap().merge_snapshot(snapshot);
            }
            Err(e) => {
                tracing::warn!(address, error = %e, "failed to pull membership registry from peer");
                all_ok = false;
            }
        }
    }
    if events {
        match pull_anonymous_events(&state.http, address).await {
            Ok(log) => {
                state.event_log.write().unwrap().merge(log);
            }
            Err(e) => {
                tracing::warn!(address, error = %e, "failed to pull anonymous events from peer");
                all_ok = false;
            }
        }
    }
    if acks {
        match pull_responder_acknowledgments(&state.http, address).await {
            Ok(snapshot) => {
                state.responder_acknowledgments.write().unwrap().merge_snapshot(snapshot);
            }
            Err(e) => {
                tracing::warn!(address, error = %e, "failed to pull responder acknowledgments from peer");
                all_ok = false;
            }
        }
    }

    all_ok
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

/// Opts into a schedule for `sync_with_all_peers`: spawns a background task that calls it once
/// immediately, then again every `interval`, forever, until the returned `JoinHandle` is aborted
/// or dropped-and-the-runtime-shuts-down. This is the specific thing `spec/10-anti-entropy.md`'s
/// own "not scheduled" gap named -- `sync_with_all_peers` existing wasn't enough on its own,
/// since nothing in this crate called it on any cadence. Calling this function is still an
/// explicit opt-in a caller makes (and picks its own `interval` for); nothing here runs by
/// default just from constructing a `MeshState`.
///
/// Best-effort in the same sense every other function in this file is: a single peer being
/// unreachable on one tick is logged and retried on the next tick, never fatal to the loop. Drop
/// or `.abort()` the returned handle to stop -- there is no graceful mid-tick cancellation beyond
/// what `tokio::task::JoinHandle::abort`'s usual "cancel at the next `.await` point" already
/// gives.
pub fn spawn_periodic_sync(state: MeshState, interval: std::time::Duration) -> tokio::task::JoinHandle<()> {
    spawn_periodic_sync_with_jitter(state, interval, std::time::Duration::ZERO)
}

/// Same as `spawn_periodic_sync`, with an added random jitter of up to `max_jitter` on each
/// tick -- the specific thing `spec/10-anti-entropy.md`'s "no jitter/coordination" gap named.
/// Without jitter, every node that starts a periodic sync at the same wall-clock moment pulls
/// from every other peer at the same moment, forever; a per-node random phase breaks that
/// synchronization. `spawn_periodic_sync` keeps the old fixed-interval behavior; this variant
/// lets a caller pick its own jitter range, and `max_jitter = 0` is exactly the old behavior.
///
/// The jitter is drawn from `std::collections::hash_map::RandomState`'s per-process random seed,
/// not a cryptographic RNG -- it only has to desynchronize independent nodes, not resist an
/// adversary. It is not persisted, so a restart re-randomizes the phase.
pub fn spawn_periodic_sync_with_jitter(
    state: MeshState,
    interval: std::time::Duration,
    max_jitter: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            sync_with_all_peers(&state).await;
            let jitter = random_jitter(max_jitter);
            tokio::time::sleep(interval + jitter).await;
        }
    })
}

/// A random duration in `[0, max)`, or `Duration::ZERO` when `max` is zero.
fn random_jitter(max: std::time::Duration) -> std::time::Duration {
    if max.is_zero() {
        return std::time::Duration::ZERO;
    }
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0),
    );
    let nanos = max.as_nanos().max(1) as u64;
    std::time::Duration::from_nanos(hasher.finish() % nanos)
}

#[derive(Debug, thiserror::Error)]
pub enum PullError {
    #[error("request to {0} failed: {1}")]
    Request(String, reqwest::Error),
    #[error("{0} rejected the request with status {1}")]
    Rejected(String, StatusCode),
}

pub async fn pull_heads(http: &reqwest::Client, address: &str) -> Result<StoreHeads, PullError> {
    let url = format!("{}/oag-mesh/v1/sync/heads", address.trim_end_matches('/'));
    let response = http.get(&url).send().await.map_err(|e| PullError::Request(address.to_string(), e))?;
    if !response.status().is_success() {
        return Err(PullError::Rejected(address.to_string(), response.status()));
    }
    response.json().await.map_err(|e| PullError::Request(address.to_string(), e))
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
        spawn_with_state(MeshState::new(PeerIdentity::generate(), peers)).await
    }

    async fn spawn_with_state(state: MeshState) -> (String, MeshState) {
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
    async fn search_anonymous_events_paginates_and_reports_total() {
        let (addr_a, _state_a) = spawn(vec![]).await;
        let http = reqwest::Client::new();

        for i in 0..5 {
            let event = valid_event(&format!("search-page-{i}"));
            let pow = ProofOfWork::solve(&event, crate::anonymous_event::BASE_DIFFICULTY_BITS);
            push_anonymous_event(&http, &addr_a, &event, pow).await.unwrap();
        }

        let response = reqwest::get(format!("{addr_a}/oag-mesh/v1/anonymous-event/search?limit=2&offset=0"))
            .await
            .unwrap();
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["events"].as_array().unwrap().len(), 2);
        assert_eq!(body["total"], 5);
        assert_eq!(body["limit"], 2);
        assert_eq!(body["offset"], 0);

        let response = reqwest::get(format!("{addr_a}/oag-mesh/v1/anonymous-event/search?limit=2&offset=2"))
            .await
            .unwrap();
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["events"].as_array().unwrap().len(), 2);
        assert_eq!(body["total"], 5);
        assert_eq!(body["offset"], 2);

        // The last page is short.
        let response = reqwest::get(format!("{addr_a}/oag-mesh/v1/anonymous-event/search?limit=2&offset=4"))
            .await
            .unwrap();
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["events"].as_array().unwrap().len(), 1);
        assert_eq!(body["total"], 5);
    }

    #[tokio::test]
    async fn search_anonymous_events_default_limit_bounds_the_response() {
        let (addr_a, _state_a) = spawn(vec![]).await;
        let http = reqwest::Client::new();

        for i in 0..DEFAULT_EVENT_SEARCH_LIMIT + 10 {
            let event = valid_event(&format!("search-default-{i}"));
            let pow = ProofOfWork::solve(&event, crate::anonymous_event::BASE_DIFFICULTY_BITS);
            push_anonymous_event(&http, &addr_a, &event, pow).await.unwrap();
        }

        let response = reqwest::get(format!("{addr_a}/oag-mesh/v1/anonymous-event/search")).await.unwrap();
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["events"].as_array().unwrap().len(), DEFAULT_EVENT_SEARCH_LIMIT);
        assert_eq!(body["total"], DEFAULT_EVENT_SEARCH_LIMIT + 10);
        assert_eq!(body["limit"], DEFAULT_EVENT_SEARCH_LIMIT);

        // A caller asking for more than the hard ceiling is clamped to it.
        let response = reqwest::get(format!("{addr_a}/oag-mesh/v1/anonymous-event/search?limit=99999"))
            .await
            .unwrap();
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["limit"], MAX_EVENT_SEARCH_LIMIT);
    }

    #[tokio::test]
    async fn prune_endpoint_removes_old_events() {
        let (addr_a, state_a) = spawn(vec![]).await;
        let http = reqwest::Client::new();

        let mut old = valid_event("prune-wire-old");
        old.observed_at = 999_900; // divisible by 300, before the cutoff
        let pow_old = ProofOfWork::solve(&old, crate::anonymous_event::BASE_DIFFICULTY_BITS);
        push_anonymous_event(&http, &addr_a, &old, pow_old).await.unwrap();

        let mut recent = valid_event("prune-wire-recent");
        recent.observed_at = 2_000_100; // divisible by 300, after the cutoff
        let pow_recent = ProofOfWork::solve(&recent, crate::anonymous_event::BASE_DIFFICULTY_BITS);
        push_anonymous_event(&http, &addr_a, &recent, pow_recent).await.unwrap();

        let response = http
            .post(format!("{addr_a}/oag-mesh/v1/anonymous-event/prune"))
            .json(&serde_json::json!({ "before": 1_500_000 }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["removed"], 1);

        assert_eq!(state_a.event_log.read().unwrap().corroboration_for("prune-wire-old"), 0);
        assert_eq!(state_a.event_log.read().unwrap().corroboration_for("prune-wire-recent"), 1);
    }

    #[tokio::test]
    async fn a_configured_relay_forwards_anonymous_events_to_its_target() {
        let (addr_target, state_target) = spawn(vec![]).await;

        let mut relay_state = MeshState::new(PeerIdentity::generate(), vec![]);
        relay_state.anonymous_event_relay_target = Some(addr_target.clone());
        let (addr_relay, state_relay) = spawn_with_state(relay_state).await;

        let event = valid_event("relay-test");
        let pow = ProofOfWork::solve(&event, crate::anonymous_event::BASE_DIFFICULTY_BITS);
        push_anonymous_event(&reqwest::Client::new(), &addr_relay, &event, pow).await.unwrap();

        // The relay recorded it locally, and the target received it via the relay.
        assert_eq!(state_relay.event_log.read().unwrap().corroboration_for("relay-test"), 1);
        assert_eq!(state_target.event_log.read().unwrap().corroboration_for("relay-test"), 1);
    }

    #[tokio::test]
    async fn a_relay_failure_does_not_reject_the_submission() {
        let (_addr_target, _state_target) = spawn(vec![]).await;

        // The relay is configured with an address that is not listening (port 0).
        let mut relay_state = MeshState::new(PeerIdentity::generate(), vec![]);
        relay_state.anonymous_event_relay_target = Some("http://127.0.0.1:0".to_string());
        let (addr_relay, state_relay) = spawn_with_state(relay_state).await;

        let event = valid_event("relay-failure-test");
        let pow = ProofOfWork::solve(&event, crate::anonymous_event::BASE_DIFFICULTY_BITS);
        // The submission still succeeds: the relay recorded it, and the failed forward is
        // best-effort.
        push_anonymous_event(&reqwest::Client::new(), &addr_relay, &event, pow).await.unwrap();
        assert_eq!(state_relay.event_log.read().unwrap().corroboration_for("relay-failure-test"), 1);
    }

    #[tokio::test]
    async fn all_clear_hides_a_nonce_from_search_over_the_wire() {
        let (addr_a, _state_a) = spawn(vec![]).await;
        let http = reqwest::Client::new();

        let event = valid_event("all-clear-wire");
        let pow = ProofOfWork::solve(&event, crate::anonymous_event::BASE_DIFFICULTY_BITS);
        push_anonymous_event(&http, &addr_a, &event, pow).await.unwrap();

        let mut all_clear = valid_event("all-clear-wire");
        all_clear.kind = crate::anonymous_event::EventKind::AllClear;
        all_clear.event_id = "evt-all-clear".to_string();
        // The second report under the same nonce pays the escalated difficulty.
        let required = _state_a.event_log.read().unwrap().required_difficulty_bits("all-clear-wire");
        let pow = ProofOfWork::solve(&all_clear, required);
        push_anonymous_event(&http, &addr_a, &all_clear, pow).await.unwrap();

        // The default search hides the resolved nonce.
        let response = reqwest::get(format!("{addr_a}/oag-mesh/v1/anonymous-event/search")).await.unwrap();
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["events"].as_array().unwrap().len(), 0);

        // `include_resolved=true` shows both events.
        let response = reqwest::get(format!("{addr_a}/oag-mesh/v1/anonymous-event/search?include_resolved=true"))
            .await
            .unwrap();
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["events"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn a_subscription_receives_matching_events_in_its_inbox() {
        let (addr_a, _state_a) = spawn(vec![]).await;
        let http = reqwest::Client::new();

        // Register a blinded subscription for medical emergencies.
        let register = serde_json::json!({ "subscription_id": "sub-1", "kind": "MedicalEmergency" });
        let response = http
            .post(format!("{addr_a}/oag-mesh/v1/responder-subscriptions"))
            .json(&register)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // A matching event is queued.
        let mut medical = valid_event("dispatch-medical");
        medical.kind = crate::anonymous_event::EventKind::MedicalEmergency(
            crate::anonymous_event::MedicalEmergencyKind::HeartIssue,
        );
        let pow = ProofOfWork::solve(&medical, crate::anonymous_event::BASE_DIFFICULTY_BITS);
        push_anonymous_event(&http, &addr_a, &medical, pow).await.unwrap();

        // A non-matching event is not.
        let hazard = valid_event("dispatch-hazard");
        let pow = ProofOfWork::solve(&hazard, crate::anonymous_event::BASE_DIFFICULTY_BITS);
        push_anonymous_event(&http, &addr_a, &hazard, pow).await.unwrap();

        let response = reqwest::get(format!("{addr_a}/oag-mesh/v1/responder-inbox/sub-1")).await.unwrap();
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["events"].as_array().unwrap().len(), 1);
        assert_eq!(body["events"][0]["corroboration_nonce"], "dispatch-medical");

        // Draining empties the inbox.
        let response = reqwest::get(format!("{addr_a}/oag-mesh/v1/responder-inbox/sub-1")).await.unwrap();
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["events"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn unregister_stops_delivery() {
        let (addr_a, _state_a) = spawn(vec![]).await;
        let http = reqwest::Client::new();

        let register = serde_json::json!({ "subscription_id": "sub-1", "kind": "MedicalEmergency" });
        http.post(format!("{addr_a}/oag-mesh/v1/responder-subscriptions"))
            .json(&register)
            .send()
            .await
            .unwrap();

        let response = http
            .delete(format!("{addr_a}/oag-mesh/v1/responder-subscriptions/sub-1"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let mut medical = valid_event("dispatch-unregister");
        medical.kind = crate::anonymous_event::EventKind::MedicalEmergency(
            crate::anonymous_event::MedicalEmergencyKind::HeartIssue,
        );
        let pow = ProofOfWork::solve(&medical, crate::anonymous_event::BASE_DIFFICULTY_BITS);
        push_anonymous_event(&http, &addr_a, &medical, pow).await.unwrap();

        let response = reqwest::get(format!("{addr_a}/oag-mesh/v1/responder-inbox/sub-1")).await.unwrap();
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["events"].as_array().unwrap().len(), 0);

        // Unregistering again is 404.
        let response = http
            .delete(format!("{addr_a}/oag-mesh/v1/responder-subscriptions/sub-1"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn an_onion_path_delivers_an_event_to_the_target_only() {
        let (addr_target, state_target) = spawn(vec![]).await;
        let (addr_r1, state_r1) = spawn(vec![]).await;
        let (addr_r2, state_r2) = spawn(vec![]).await;

        let event = valid_event("onion-wire");
        let pow = ProofOfWork::solve(&event, crate::anonymous_event::BASE_DIFFICULTY_BITS);
        let path = vec![addr_r1.clone(), addr_r2.clone()];
        push_anonymous_event_onion(&reqwest::Client::new(), &path, &addr_target, &event, pow)
            .await
            .unwrap();

        // The target records it.
        assert_eq!(state_target.event_log.read().unwrap().corroboration_for("onion-wire"), 1);
        // The relays only forwarded encrypted layers; they never see the event.
        assert_eq!(state_r1.event_log.read().unwrap().corroboration_for("onion-wire"), 0);
        assert_eq!(state_r2.event_log.read().unwrap().corroboration_for("onion-wire"), 0);
    }

    #[tokio::test]
    async fn a_relay_rejects_a_layer_it_cannot_peel() {
        let (addr_r1, _state_r1) = spawn(vec![]).await;
        let (addr_r2, state_r2) = spawn(vec![]).await;

        // Build a layer for r1's key, but send it to r2.
        let event = valid_event("onion-wrong-relay");
        let pow = ProofOfWork::solve(&event, crate::anonymous_event::BASE_DIFFICULTY_BITS);
        let r1_key = fetch_onion_key(&reqwest::Client::new(), &addr_r1).await.unwrap();
        let layer = crate::onion::build_onion(
            std::slice::from_ref(&addr_r1),
            "http://target",
            &event,
            pow,
            &[r1_key],
        )
        .unwrap();

        let err = push_onion_layer(&reqwest::Client::new(), &addr_r2, &layer).await.unwrap_err();
        assert!(matches!(err, PushError::Rejected(_, status) if status == StatusCode::BAD_REQUEST));
        assert_eq!(state_r2.event_log.read().unwrap().corroboration_for("onion-wrong-relay"), 0);
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
    async fn save_to_dir_then_load_from_dir_round_trips_responder_dispatch() {
        let dir = std::env::temp_dir().join(format!("oag-mesh-dispatch-persist-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let state = MeshState::new(PeerIdentity::generate(), vec![]);
        let filter = EventFilter {
            kind: Some(crate::anonymous_event::EventKindCategory::MedicalEmergency),
            ..Default::default()
        };
        state.responder_subscriptions.write().unwrap().upsert("sub-1".to_string(), filter.clone());

        let mut event = valid_event("dispatch-persist");
        event.kind = crate::anonymous_event::EventKind::MedicalEmergency(
            crate::anonymous_event::MedicalEmergencyKind::HeartIssue,
        );
        let subscriptions = state.responder_subscriptions.read().unwrap().subscriptions().clone();
        state.responder_inbox.write().unwrap().push_matching(&event, &subscriptions);

        state.save_to_dir(&dir).unwrap();

        let loaded = MeshState::load_from_dir(PeerIdentity::generate(), vec![], &dir).unwrap();
        assert!(loaded.responder_subscriptions.read().unwrap().subscriptions().contains_key("sub-1"));
        assert_eq!(loaded.responder_inbox.write().unwrap().drain("sub-1").len(), 1);

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
    async fn save_to_dir_writes_a_commit_marker_that_still_verifies() {
        let (_addr_a, state_a) = spawn(vec![]).await;
        let dir = std::env::temp_dir().join(format!("oag-mesh-transport-commit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        state_a.save_to_dir(&dir).unwrap();
        assert_eq!(
            crate::persistence::verify_commit_marker(&dir).unwrap(),
            crate::persistence::CommitState::Consistent,
            "a fresh save must describe a consistent set"
        );
        // Every recorded file is really on disk.
        for name in crate::persistence::STORE_FILES {
            assert!(dir.join(name).exists(), "{name} should have been written");
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn load_from_dir_refuses_a_torn_set_instead_of_acting_on_it() {
        // The crash window the marker closes: some stores from one snapshot, some from another.
        // Loading that would silently accept stores that disagree with each other, and nothing
        // downstream could tell.
        let (_addr_a, state_a) = spawn(vec![]).await;
        let dir = std::env::temp_dir().join(format!("oag-mesh-transport-torn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        state_a.save_to_dir(&dir).unwrap();
        std::fs::remove_file(dir.join(crate::persistence::STORE_FILES[2])).unwrap();

        let err = match MeshState::load_from_dir(PeerIdentity::generate(), vec![], &dir) {
            Ok(_) => panic!("a torn set must be refused, not loaded"),
            Err(err) => err,
        };
        assert!(
            matches!(err, crate::persistence::PersistenceError::TornSet { .. }),
            "expected TornSet, got {err}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn load_from_dir_still_accepts_a_directory_written_before_markers() {
        // Backward compatibility: an existing deployment upgrades, and its directory has seven
        // store files but no marker. That must load exactly as it did before -- refusing would
        // strand every existing node's state on upgrade.
        let (_addr_a, state_a) = spawn(vec![]).await;
        let dir = std::env::temp_dir().join(format!("oag-mesh-transport-legacy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        state_a.save_to_dir(&dir).unwrap();
        std::fs::remove_file(dir.join(crate::persistence::COMMIT_MARKER_FILE)).unwrap();

        let loaded = MeshState::load_from_dir(PeerIdentity::generate(), vec![], &dir)
            .expect("a pre-marker directory must still load");
        assert!(loaded.tree.read().unwrap().members_of("global", 1).is_empty());

        std::fs::remove_dir_all(&dir).ok();
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
    async fn membership_attestation_rate_limiter_rejects_a_burst_per_attester() {
        let (addr_a, state_a) = spawn(vec![]).await;
        let attester = PeerIdentity::generate();
        let http = reqwest::Client::new();

        for i in 0..MEMBERSHIP_ATTESTATION_RATE_LIMIT_MAX {
            let subject = PeerIdentity::generate();
            let attestation = crate::membership::build_and_sign(
                &attester,
                subject.peer_id(),
                &format!("cluster-{i}"),
                now_unix(),
            )
            .unwrap();
            let pow = solve_membership_pow(&state_a, &attestation);
            push_membership_attestation(&http, &addr_a, &attestation, pow).await.unwrap();
        }

        // The attester's window is full: the next attestation is rejected with 429.
        let subject = PeerIdentity::generate();
        let attestation =
            crate::membership::build_and_sign(&attester, subject.peer_id(), "cluster-over", now_unix()).unwrap();
        let pow = solve_membership_pow(&state_a, &attestation);
        let err = push_membership_attestation(&http, &addr_a, &attestation, pow).await.unwrap_err();
        assert!(matches!(err, PushError::Rejected(_, status) if status == StatusCode::TOO_MANY_REQUESTS));
        assert!(!state_a.membership_registry.read().unwrap().is_attested_member("cluster-over", &subject.peer_id(), 1));

        // A different attester has its own window.
        let other = PeerIdentity::generate();
        let other_subject = PeerIdentity::generate();
        let attestation =
            crate::membership::build_and_sign(&other, other_subject.peer_id(), "cluster-other", now_unix())
                .unwrap();
        let pow = solve_membership_pow(&state_a, &attestation);
        push_membership_attestation(&http, &addr_a, &attestation, pow).await.unwrap();
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
    async fn responder_acknowledgment_rate_limiter_rejects_a_burst_per_identity() {
        let (addr_a, state_a) = spawn(vec![]).await;
        let responder = PeerIdentity::generate();
        let http = reqwest::Client::new();

        for i in 0..RESPONDER_ACK_RATE_LIMIT_MAX {
            let ack = crate::responder::build_and_sign(&responder, &format!("ack-rate-{i}"), true, now_unix())
                .unwrap();
            push_responder_acknowledgment(&http, &addr_a, &ack).await.unwrap();
        }

        // The identity's window is now full: the next acknowledgment is rejected with 429.
        let ack = crate::responder::build_and_sign(&responder, "ack-rate-over", true, now_unix()).unwrap();
        let err = push_responder_acknowledgment(&http, &addr_a, &ack).await.unwrap_err();
        assert!(matches!(err, PushError::Rejected(_, status) if status == StatusCode::TOO_MANY_REQUESTS));
        assert!(
            state_a
                .responder_acknowledgments
                .read()
                .unwrap()
                .active_responders_for("ack-rate-over")
                .is_empty()
        );

        // A different identity has its own window and is not blocked by the first one's burst.
        let other = PeerIdentity::generate();
        let ack = crate::responder::build_and_sign(&other, "ack-rate-other", true, now_unix()).unwrap();
        push_responder_acknowledgment(&http, &addr_a, &ack).await.unwrap();
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

    #[tokio::test]
    async fn spawn_periodic_sync_picks_up_data_that_arrives_after_the_first_tick() {
        let (addr_source, state_source) = spawn(vec![]).await;
        let (_addr_catcher, state_catcher) = spawn(vec![addr_source.clone()]).await;

        let handle = spawn_periodic_sync(state_catcher.clone(), std::time::Duration::from_millis(20));

        // Populate the source only *after* starting the schedule -- the periodic nature, not
        // just a one-shot pull, is what this test is actually checking.
        let decl = crate::bridge::build_and_sign(
            &PeerIdentity::generate(),
            "global",
            MeshMember::BaseCluster("periodic-sync-test".into()),
            now_unix(),
        )
        .unwrap();
        let pow = solve_bridge_pow(&state_source, &decl);
        state_source.tree.write().unwrap().add(&decl, pow, now_unix()).unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert_eq!(
            state_catcher.tree.read().unwrap().corroboration_for("global", &MeshMember::BaseCluster("periodic-sync-test".into())),
            1
        );

        handle.abort();
    }

    #[tokio::test]
    async fn aborting_the_returned_handle_stops_further_syncing() {
        let (addr_source, state_source) = spawn(vec![]).await;
        let (_addr_catcher, state_catcher) = spawn(vec![addr_source.clone()]).await;

        let handle = spawn_periodic_sync(state_catcher.clone(), std::time::Duration::from_millis(20));
        // Let at least one tick run, then stop the schedule entirely.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        handle.abort();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await; // let the abort actually land

        // Data added to the source *after* the abort must never reach the catcher.
        let decl = crate::bridge::build_and_sign(
            &PeerIdentity::generate(),
            "global",
            MeshMember::BaseCluster("post-abort-test".into()),
            now_unix(),
        )
        .unwrap();
        let pow = solve_bridge_pow(&state_source, &decl);
        state_source.tree.write().unwrap().add(&decl, pow, now_unix()).unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(state_catcher.tree.read().unwrap().members_of("global", 1).is_empty());
    }

    #[tokio::test]
    async fn sync_heads_reports_per_store_sequences() {
        let (addr_a, state_a) = spawn(vec![]).await;
        let decl = crate::bridge::build_and_sign(
            &PeerIdentity::generate(),
            "global",
            MeshMember::BaseCluster("heads-test".into()),
            now_unix(),
        )
        .unwrap();
        let pow = solve_bridge_pow(&state_a, &decl);
        state_a.tree.write().unwrap().add(&decl, pow, now_unix()).unwrap();

        let response = reqwest::get(format!("{addr_a}/oag-mesh/v1/sync/heads")).await.unwrap();
        let heads: StoreHeads = response.json().await.unwrap();
        assert!(heads.bridge_tree > 0);
        assert_eq!(heads.claim_corroboration, 0);
        assert_eq!(heads.membership_registry, 0);
        assert_eq!(heads.anonymous_events, 0);
        assert_eq!(heads.responder_acknowledgments, 0);
        assert_ne!(heads.instance_id, 0);
    }

    #[tokio::test]
    async fn a_second_pull_after_no_changes_is_a_no_op() {
        let (addr_source, state_source) = spawn(vec![]).await;
        let (_addr_catcher, state_catcher) = spawn(vec![addr_source.clone()]).await;

        let decl = crate::bridge::build_and_sign(
            &PeerIdentity::generate(),
            "global",
            MeshMember::BaseCluster("heads-noop".into()),
            now_unix(),
        )
        .unwrap();
        let pow = solve_bridge_pow(&state_source, &decl);
        state_source.tree.write().unwrap().add(&decl, pow, now_unix()).unwrap();

        pull_and_merge(&state_catcher, &addr_source).await;
        let first = state_catcher
            .tree
            .read()
            .unwrap()
            .corroboration_for("global", &MeshMember::BaseCluster("heads-noop".into()));

        // Nothing changed on the source: the second pull must not regress anything.
        pull_and_merge(&state_catcher, &addr_source).await;
        let second = state_catcher
            .tree
            .read()
            .unwrap()
            .corroboration_for("global", &MeshMember::BaseCluster("heads-noop".into()));
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn a_change_to_one_store_is_picked_up_on_the_next_pull() {
        let (addr_source, state_source) = spawn(vec![]).await;
        let (_addr_catcher, state_catcher) = spawn(vec![addr_source.clone()]).await;

        // First pull: nothing to catch up on.
        pull_and_merge(&state_catcher, &addr_source).await;

        // Add a claim report to the source only.
        let identity = PeerIdentity::generate();
        let report =
            crate::corroboration::build_and_sign(&identity, "heads-claim", "cluster-a", "blake3:abc", now_unix())
                .unwrap();
        let pow = solve_claim_pow(&state_source, &report);
        state_source.claim_corroboration.write().unwrap().add(&report, pow, now_unix()).unwrap();

        pull_and_merge(&state_catcher, &addr_source).await;
        assert_eq!(
            state_catcher
                .claim_corroboration
                .read()
                .unwrap()
                .cluster_corroboration_for("heads-claim", "blake3:abc"),
            1
        );
    }

    #[test]
    fn heads_changed_treats_a_new_peer_as_fully_changed() {
        let remote = StoreHeads {
            instance_id: 1,
            bridge_tree: 5,
            claim_corroboration: 0,
            membership_registry: 0,
            anonymous_events: 0,
            responder_acknowledgments: 0,
        };
        assert_eq!(heads_changed(None, remote), [true; 5]);
    }

    #[test]
    fn heads_changed_detects_a_changed_store_and_a_restart() {
        let last = StoreHeads {
            instance_id: 1,
            bridge_tree: 5,
            claim_corroboration: 3,
            membership_registry: 0,
            anonymous_events: 0,
            responder_acknowledgments: 0,
        };
        let remote = StoreHeads {
            instance_id: 1,
            bridge_tree: 6,
            claim_corroboration: 3,
            membership_registry: 0,
            anonymous_events: 0,
            responder_acknowledgments: 0,
        };
        assert_eq!(heads_changed(Some(last), remote), [true, false, false, false, false]);

        let restarted = StoreHeads { instance_id: 2, ..remote };
        assert_eq!(heads_changed(Some(last), restarted), [true, true, true, true, true]);
    }

    #[tokio::test]
    async fn spawn_periodic_sync_with_jitter_still_syncs() {
        let (addr_source, state_source) = spawn(vec![]).await;
        let (_addr_catcher, state_catcher) = spawn(vec![addr_source.clone()]).await;

        let handle = spawn_periodic_sync_with_jitter(
            state_catcher.clone(),
            std::time::Duration::from_millis(20),
            std::time::Duration::from_millis(50),
        );

        let decl = crate::bridge::build_and_sign(
            &PeerIdentity::generate(),
            "global",
            MeshMember::BaseCluster("jitter-sync-test".into()),
            now_unix(),
        )
        .unwrap();
        let pow = solve_bridge_pow(&state_source, &decl);
        state_source.tree.write().unwrap().add(&decl, pow, now_unix()).unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        assert_eq!(
            state_catcher
                .tree
                .read()
                .unwrap()
                .corroboration_for("global", &MeshMember::BaseCluster("jitter-sync-test".into())),
            1
        );

        handle.abort();
    }

    #[test]
    fn random_jitter_is_bounded_by_the_maximum() {
        let max = std::time::Duration::from_millis(500);
        for _ in 0..100 {
            assert!(random_jitter(max) < max);
        }
    }

    #[test]
    fn zero_maximum_jitter_is_zero() {
        assert_eq!(random_jitter(std::time::Duration::ZERO), std::time::Duration::ZERO);
    }

    #[tokio::test]
    async fn find_route_across_mesh_answers_from_local_knowledge_with_no_network_call() {
        // peers: vec![] -- if this succeeds at all, it proves the local-first check is really
        // checked before any fan-out is attempted, not just faster in practice.
        let (_addr_a, state_a) = spawn(vec![]).await;
        let decl = crate::bridge::build_and_sign(
            &PeerIdentity::generate(),
            "global",
            MeshMember::BaseCluster("local-only".into()),
            now_unix(),
        )
        .unwrap();
        let pow = solve_bridge_pow(&state_a, &decl);
        state_a.tree.write().unwrap().add(&decl, pow, now_unix()).unwrap();

        let from = MeshMember::MeshGroup("global".into());
        let to = MeshMember::BaseCluster("local-only".into());
        let path = find_route_across_mesh(&state_a, &from, &to, 1, 0).await;
        assert_eq!(path, Some(vec![from, to]));
    }

    #[tokio::test]
    async fn find_route_across_mesh_finds_a_path_known_only_by_a_direct_peer() {
        let (addr_b, state_b) = spawn(vec![]).await;
        let (_addr_a, state_a) = spawn(vec![addr_b.clone()]).await;

        let decl = crate::bridge::build_and_sign(
            &PeerIdentity::generate(),
            "global",
            MeshMember::BaseCluster("known-by-b".into()),
            now_unix(),
        )
        .unwrap();
        let pow = solve_bridge_pow(&state_b, &decl);
        state_b.tree.write().unwrap().add(&decl, pow, now_unix()).unwrap();

        let from = MeshMember::MeshGroup("global".into());
        let to = MeshMember::BaseCluster("known-by-b".into());

        // A's own tree knows nothing -- this can only succeed by asking peer B.
        assert!(state_a.tree.read().unwrap().shortest_path(&from, &to, 1).is_none());
        let path = find_route_across_mesh(&state_a, &from, &to, 1, 1).await;
        assert_eq!(path, Some(vec![from, to]));
    }

    #[tokio::test]
    async fn find_route_across_mesh_moves_through_a_chain_of_peers_bounded_by_max_hops() {
        let (addr_c, state_c) = spawn(vec![]).await;
        let (addr_b, _state_b) = spawn(vec![addr_c.clone()]).await;
        let (_addr_a, state_a) = spawn(vec![addr_b.clone()]).await;

        // Only C -- two hops away from A, through B -- has the data.
        let decl = crate::bridge::build_and_sign(
            &PeerIdentity::generate(),
            "global",
            MeshMember::BaseCluster("known-by-c".into()),
            now_unix(),
        )
        .unwrap();
        let pow = solve_bridge_pow(&state_c, &decl);
        state_c.tree.write().unwrap().add(&decl, pow, now_unix()).unwrap();

        let from = MeshMember::MeshGroup("global".into());
        let to = MeshMember::BaseCluster("known-by-c".into());

        // Only one degree of separation's worth of hops to spend: A can reach B, but B has no
        // budget left to forward on to C -- "only so many degrees of separation" cuts the
        // search off before it reaches the answer.
        assert_eq!(find_route_across_mesh(&state_a, &from, &to, 1, 1).await, None);

        // Two hops is enough to go A -> B -> C and back with an answer.
        let path = find_route_across_mesh(&state_a, &from, &to, 1, 2).await;
        assert_eq!(path, Some(vec![from, to]));
    }

    /// A real measurement of the link-quality feedback path: with a fan-out budget of one, the
    /// first search spends its only slot on the configured-first peer -- which is dead -- and
    /// fails. That failure is recorded. The *next* search, with the same budget, puts the proven
    /// peer first and succeeds. The adaptation is observable, not just present in the code.
    #[tokio::test]
    async fn a_failed_fan_out_is_recorded_and_the_next_search_spends_its_budget_better() {
        // A closed port: the connection is refused immediately, so the failure is fast.
        let dead_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = format!("http://{}", dead_listener.local_addr().unwrap());
        drop(dead_listener);

        let live_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live_addr = format!("http://{}", live_listener.local_addr().unwrap());

        // Configuration order deliberately puts the dead peer first, so the *initial* ordering
        // has no reason to prefer the live one.
        let state_a = MeshState::new(PeerIdentity::generate(), vec![dead_addr.clone(), live_addr.clone()]);
        let state_b = MeshState::new(PeerIdentity::generate(), vec![]);

        // Only B knows about the target, and B is one hop away with a fan-out budget of zero for
        // its own children -- so it can answer from local knowledge alone.
        let decl = crate::bridge::build_and_sign(
            &PeerIdentity::generate(),
            "global",
            MeshMember::BaseCluster("quality-target".into()),
            now_unix(),
        )
        .unwrap();
        let pow = solve_bridge_pow(&state_b, &decl);
        state_b.tree.write().unwrap().add(&decl, pow, now_unix()).unwrap();
        tokio::spawn(async move { axum::serve(live_listener, router(state_b)).await.unwrap() });

        let from = MeshMember::MeshGroup("global".into());
        let to = MeshMember::BaseCluster("quality-target".into());

        // First search: budget 1, configuration order, so the dead peer is asked and fails.
        let first = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            find_route_across_mesh_with_budget(&state_a, &from, &to, 1, 2, 1),
        )
        .await
        .expect("search must not hang");
        assert!(first.is_none(), "the first search should fail: its one slot went to the dead peer");

        let dead_quality = state_a.link_quality.quality(&dead_addr).expect("the failure must be recorded");
        assert_eq!(dead_quality.attempts, 1);
        assert_eq!(dead_quality.successes, 0);

        // Second search: same budget, but the live peer now outranks the proven-dead one.
        let second = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            find_route_across_mesh_with_budget(&state_a, &from, &to, 1, 2, 1),
        )
        .await
        .expect("search must not hang");
        assert!(second.is_some(), "the second search should succeed now that the live peer is asked first");
    }

    /// The black-hole case: the peer accepts the TCP connection and then never sends a byte. A
    /// connect timeout alone cannot catch this -- the connection *succeeded* -- so it is the total
    /// request timeout that bounds the wait. Without it, `sync_with_all_peers` (sequential) would
    /// stall on this one peer for as long as the OS cares to wait.
    #[tokio::test]
    async fn a_peer_that_accepts_but_never_responds_is_abandoned_at_the_timeout() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { break };
                // Hold the connection open deliberately, responding with nothing.
                std::mem::forget(stream);
            }
        });

        let client = build_http_client(
            std::time::Duration::from_millis(50),
            std::time::Duration::from_millis(200),
        );
        let started = std::time::Instant::now();
        let result = client.get(format!("http://{addr}/")).send().await;
        let elapsed = started.elapsed();

        assert!(result.is_err(), "a non-responding peer must produce an error, not hang");
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "the request timeout should fire well before this, took {elapsed:?}"
        );
    }

    /// End to end through the mesh's own pull path: a black-holed peer costs one timeout and the
    /// pull reports a failed delivery, which is exactly what `link_quality` records. Before the
    /// client had a timeout this call had no bound at all.
    #[tokio::test]
    async fn pull_and_merge_against_a_black_holed_peer_is_bounded_and_recorded() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { break };
                std::mem::forget(stream);
            }
        });

        let mut state = MeshState::new(PeerIdentity::generate(), vec![addr.clone()]);
        state.http = Arc::new(build_http_client(
            std::time::Duration::from_millis(50),
            std::time::Duration::from_millis(200),
        ));

        let started = std::time::Instant::now();
        let delivered = pull_and_merge(&state, &addr).await;
        let elapsed = started.elapsed();

        assert!(!delivered, "a black-holed peer must report a failed delivery");
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "the pull must be bounded by the client timeout, took {elapsed:?}"
        );
        let q = state.link_quality.quality(&addr).expect("the failure must be recorded");
        assert_eq!(q.attempts, 1);
        assert_eq!(q.successes, 0);
    }

    #[tokio::test]
    async fn pull_and_merge_records_a_failure_against_an_unreachable_peer() {
        let dead_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = format!("http://{}", dead_listener.local_addr().unwrap());
        drop(dead_listener);

        let state = MeshState::new(PeerIdentity::generate(), vec![dead_addr.clone()]);
        let delivered = pull_and_merge(&state, &dead_addr).await;
        assert!(!delivered, "an unreachable peer must report a failed delivery");

        let q = state.link_quality.quality(&dead_addr).expect("the failure must be recorded");
        assert_eq!(q.attempts, 1);
        assert_eq!(q.successes, 0);
        assert!(q.score < crate::link_quality::UNKNOWN_PEER_SCORE);
    }

    #[tokio::test]
    async fn pull_and_merge_records_a_success_against_a_live_peer() {
        let live_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live_addr = format!("http://{}", live_listener.local_addr().unwrap());
        let state = MeshState::new(PeerIdentity::generate(), vec![live_addr.clone()]);
        let peer_state = MeshState::new(PeerIdentity::generate(), vec![]);
        tokio::spawn(async move { axum::serve(live_listener, router(peer_state)).await.unwrap() });

        let delivered = pull_and_merge(&state, &live_addr).await;
        assert!(delivered, "a live peer must report a successful delivery");

        let q = state.link_quality.quality(&live_addr).expect("the success must be recorded");
        assert_eq!(q.attempts, 1);
        assert_eq!(q.successes, 1);
        assert!(q.score > crate::link_quality::UNKNOWN_PEER_SCORE);
    }

    #[tokio::test]
    async fn find_route_across_mesh_terminates_on_a_cyclic_peer_graph() {
        // A <-> B, B -> C, C -> B: the peer graph has a cycle, so a naive fan-out could
        // ping-pong between A and B forever. `already_asked` plus `remaining_hops` must still
        // bound it -- this is the termination guarantee spec/13 names.
        let listener_a = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_b = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_c = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_a = format!("http://{}", listener_a.local_addr().unwrap());
        let addr_b = format!("http://{}", listener_b.local_addr().unwrap());
        let addr_c = format!("http://{}", listener_c.local_addr().unwrap());

        let state_a = MeshState::new(PeerIdentity::generate(), vec![addr_b.clone()]);
        let state_b = MeshState::new(PeerIdentity::generate(), vec![addr_a.clone(), addr_c.clone()]);
        let state_c = MeshState::new(PeerIdentity::generate(), vec![addr_b.clone()]);

        for (state, listener) in [
            (state_a.clone(), listener_a),
            (state_b.clone(), listener_b),
            (state_c.clone(), listener_c),
        ] {
            tokio::spawn(async move { axum::serve(listener, router(state)).await.unwrap(); });
        }

        // Only C -- reachable from A only by going A -> B -> C -- has the data.
        let decl = crate::bridge::build_and_sign(
            &PeerIdentity::generate(),
            "global",
            MeshMember::BaseCluster("known-by-c".into()),
            now_unix(),
        )
        .unwrap();
        let pow = solve_bridge_pow(&state_c, &decl);
        state_c.tree.write().unwrap().add(&decl, pow, now_unix()).unwrap();

        let from = MeshMember::MeshGroup("global".into());
        let to = MeshMember::BaseCluster("known-by-c".into());

        // The cycle must not hang the search, and the path must still come back.
        let path = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            find_route_across_mesh(&state_a, &from, &to, 1, 3),
        )
        .await
        .expect("the search must terminate on a cyclic peer graph");
        assert_eq!(path, Some(vec![from, to]));
    }

    #[tokio::test]
    async fn find_route_across_mesh_cannot_assemble_a_path_split_across_two_peers_with_no_shared_knowledge() {
        // A real, honest limitation: each hop's answer comes from ONE node's own complete local
        // shortest_path, never several different peers' partial knowledge stitched together.
        let (addr_b, state_b) = spawn(vec![]).await;
        let (addr_c, state_c) = spawn(vec![]).await;
        let (_addr_a, state_a) = spawn(vec![addr_b.clone(), addr_c.clone()]).await;

        // B knows "global contains north-america"; C knows "north-america contains ny-dc1" --
        // together they describe a real two-hop path, but neither peer alone can compute it,
        // and A asks each independently rather than combining their answers.
        let decl_b = crate::bridge::build_and_sign(
            &PeerIdentity::generate(),
            "global",
            MeshMember::MeshGroup("north-america".into()),
            now_unix(),
        )
        .unwrap();
        let pow_b = solve_bridge_pow(&state_b, &decl_b);
        state_b.tree.write().unwrap().add(&decl_b, pow_b, now_unix()).unwrap();

        let decl_c = crate::bridge::build_and_sign(
            &PeerIdentity::generate(),
            "north-america",
            MeshMember::BaseCluster("ny-dc1".into()),
            now_unix(),
        )
        .unwrap();
        let pow_c = solve_bridge_pow(&state_c, &decl_c);
        state_c.tree.write().unwrap().add(&decl_c, pow_c, now_unix()).unwrap();

        let from = MeshMember::MeshGroup("global".into());
        let to = MeshMember::BaseCluster("ny-dc1".into());

        // A real path exists in the union of what B and C each know -- but this search can't
        // see it, exactly the gap spec/13's own "what this explicitly is not" names.
        assert_eq!(find_route_across_mesh(&state_a, &from, &to, 1, 3).await, None);

        // Running spec/10's own pull-based anti-entropy first consolidates both halves onto one
        // node, which is then enough for a plain local shortest_path to answer directly.
        pull_and_merge(&state_a, &addr_b).await;
        pull_and_merge(&state_a, &addr_c).await;
        assert_eq!(
            state_a.tree.read().unwrap().shortest_path(&from, &to, 1),
            Some(vec![from, MeshMember::MeshGroup("north-america".into()), to])
        );
    }

    #[tokio::test]
    async fn find_route_across_mesh_with_zero_fanout_budget_makes_no_network_call() {
        let (addr_b, state_b) = spawn(vec![]).await;
        let (_addr_a, state_a) = spawn(vec![addr_b.clone()]).await;

        let decl = crate::bridge::build_and_sign(
            &PeerIdentity::generate(),
            "global",
            MeshMember::BaseCluster("budget-zero".into()),
            now_unix(),
        )
        .unwrap();
        let pow = solve_bridge_pow(&state_b, &decl);
        state_b.tree.write().unwrap().add(&decl, pow, now_unix()).unwrap();

        let from = MeshMember::MeshGroup("global".into());
        let to = MeshMember::BaseCluster("budget-zero".into());

        // B knows the path; A has a peer but a fan-out budget of 0, so it must not ask anyone.
        assert!(state_a.tree.read().unwrap().shortest_path(&from, &to, 1).is_none());
        assert_eq!(
            find_route_across_mesh_with_budget(&state_a, &from, &to, 1, 8, 0).await,
            None
        );
    }

    #[tokio::test]
    async fn fanout_budget_is_divided_across_hops() {
        let (addr_c, state_c) = spawn(vec![]).await;
        let (addr_b, _state_b) = spawn(vec![addr_c.clone()]).await;
        let (_addr_a, state_a) = spawn(vec![addr_b.clone()]).await;

        // Only C -- two hops away from A, through B -- has the data.
        let decl = crate::bridge::build_and_sign(
            &PeerIdentity::generate(),
            "global",
            MeshMember::BaseCluster("budget-chain".into()),
            now_unix(),
        )
        .unwrap();
        let pow = solve_bridge_pow(&state_c, &decl);
        state_c.tree.write().unwrap().add(&decl, pow, now_unix()).unwrap();

        let from = MeshMember::MeshGroup("global".into());
        let to = MeshMember::BaseCluster("budget-chain".into());

        // Budget 1: A asks B (spends its only unit), B gets 0 and cannot forward to C.
        assert_eq!(
            find_route_across_mesh_with_budget(&state_a, &from, &to, 1, 8, 1).await,
            None
        );

        // Budget 2: A asks B (spends 1), B gets 1 and forwards to C (spends 1).
        assert_eq!(
            find_route_across_mesh_with_budget(&state_a, &from, &to, 1, 8, 2).await,
            Some(vec![from, to])
        );
    }

    #[tokio::test]
    async fn route_search_rate_limiter_rejects_a_burst_and_recovers() {
        let (addr_a, _state_a) = spawn(vec![]).await;
        let http = reqwest::Client::new();
        let request = RouteSearchRequest {
            from: MeshMember::MeshGroup("global".into()),
            target: MeshMember::BaseCluster("rate-limit".into()),
            min_corroboration: 1,
            remaining_hops: 0,
            already_asked: vec![],
            fanout_budget: 1,
        };

        // Capacity is 8: the first 8 succeed, the 9th is rejected with 429 + Retry-After.
        for _ in 0..ROUTE_SEARCH_RATE_LIMIT_CAPACITY {
            let response = http
                .post(format!("{addr_a}/oag-mesh/v1/route-search"))
                .json(&request)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        let response = http
            .post(format!("{addr_a}/oag-mesh/v1/route-search"))
            .json(&request)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(response.headers().contains_key(axum::http::header::RETRY_AFTER));

        // After the bucket refills, requests succeed again.
        tokio::time::sleep(std::time::Duration::from_millis(700)).await;
        let response = http
            .post(format!("{addr_a}/oag-mesh/v1/route-search"))
            .json(&request)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
