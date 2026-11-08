//! `oag-mesh`: the cluster-bridging / federated-trust layer that sits one level above a single
//! Open Agent Graph peer or peer cluster (see `github.com/webdawg/open-agent-graph`,
//! `spec/26-peer-clustering.md` there for what a single cluster already is).
//!
//! Deliberately a separate repository, separate spec numbering, separate crate -- see this
//! repo's `README.md` for why. Reuses `oag-core`/`oag-crypto` from the base project (via git
//! dependency) for identifiers and signing conventions, so a signature produced here verifies
//! the same way a base-project peer's does, but implements its own protocol rather than
//! modifying the base project's `oag-sync` in place.
//!
//! See `spec/01-overview.md` (base repo link above), `spec/02-cluster-nesting.md`,
//! `spec/03-anonymous-event-rfc.md`, `spec/04-transport.md`, and
//! `spec/05-federated-corroboration.md` (this repo) for the design this crate implements.

pub mod anonymous_event;
pub mod bridge;
pub mod corroboration;
pub mod membership;
pub mod persistence;
pub mod rate_limit;
pub mod responder;
pub mod transport;

pub use anonymous_event::{
    AnonymousEvent, AnonymousEventError, AnonymousEventLog, CoarseLocation, EventFilter, EventKind,
    EventKindCategory, MedicalEmergencyKind, ProofOfWork, Severity, BASE_DIFFICULTY_BITS, DIFFICULTY_STEP_BITS,
};
pub use bridge::{
    BridgeDeclaration, BridgeEdgeSnapshot, BridgeError, BridgeProofOfWork, MeshMember, MeshTree,
    UnsignedBridgeDeclaration, BASE_BRIDGE_DIFFICULTY_BITS, BRIDGE_DIFFICULTY_STEP_BITS,
};
pub use corroboration::{
    ClaimAgreement, ClaimCorroboration, ClaimReport, ClaimReportError, ClaimReportProofOfWork, ClaimSnapshot,
    CrossCheckedAgreement, FullyCrossCheckedAgreement, RecordedReportSnapshot, UnsignedClaimReport,
    BASE_CLAIM_REPORT_DIFFICULTY_BITS, CLAIM_REPORT_DIFFICULTY_STEP_BITS,
};
pub use membership::{
    MembershipAttestation, MembershipError, MembershipProofOfWork, MembershipRegistry, MembershipSnapshot,
    UnsignedMembershipAttestation, BASE_MEMBERSHIP_DIFFICULTY_BITS, MEMBERSHIP_DIFFICULTY_STEP_BITS,
};
pub use persistence::PersistenceError;
pub use rate_limit::{RateLimiter, TokenBucket};
pub use responder::{
    RecordedAcknowledgmentSnapshot, ResponderAcknowledgment, ResponderAcknowledgmentError,
    ResponderAcknowledgmentLog, ResponderAcknowledgmentSnapshot, UnsignedResponderAcknowledgment,
};
pub use transport::{
    find_route_across_mesh, find_route_across_mesh_with_budget, spawn_periodic_sync,
    spawn_periodic_sync_with_jitter, pull_heads, BridgeDeclarationSubmission, ClaimReportSubmission,
    MembershipAttestationSubmission, MeshState, PullError, PushError, ResponderAcknowledgmentSubmission,
    RouteSearchRequest, RouteSearchResponse, StoreHeads, DEFAULT_EVENT_RETENTION_SECONDS,
    DEFAULT_EVENT_SEARCH_LIMIT, DEFAULT_ROUTE_SEARCH_FANOUT_BUDGET, MAX_EVENT_SEARCH_LIMIT,
    RESPONDER_ACK_RATE_LIMIT_MAX, RESPONDER_ACK_RATE_LIMIT_WINDOW, ROUTE_SEARCH_RATE_LIMIT_CAPACITY,
    ROUTE_SEARCH_RATE_LIMIT_PER_SEC,
};
