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
pub mod transport;

pub use anonymous_event::{
    AnonymousEvent, AnonymousEventError, AnonymousEventLog, CoarseLocation, EventKind, MedicalEmergencyKind,
    ProofOfWork, Severity, BASE_DIFFICULTY_BITS, DIFFICULTY_STEP_BITS,
};
pub use bridge::{BridgeDeclaration, BridgeError, MeshMember, MeshTree, UnsignedBridgeDeclaration};
pub use corroboration::{
    ClaimAgreement, ClaimCorroboration, ClaimReport, ClaimReportError, ClaimReportProofOfWork, CrossCheckedAgreement,
    UnsignedClaimReport, BASE_CLAIM_REPORT_DIFFICULTY_BITS, CLAIM_REPORT_DIFFICULTY_STEP_BITS,
};
pub use transport::{ClaimReportSubmission, MeshState, PushError};
