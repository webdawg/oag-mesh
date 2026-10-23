//! Cluster-of-clusters nesting ("these are clusters within clusters"), entirely new to this
//! repository -- zero changes to the base project's `oag-sync` clustering (`spec/26-peer-
//! clustering.md` there stays exactly as it is, one `[cluster].name` per peer, untouched).
//!
//! A base-layer cluster name, or another mesh-group, becomes a member of a *mesh-group* purely
//! by a peer that already belongs to it signing a `BridgeDeclaration` saying so -- the same
//! self-declared, signed-but-uncorroborated-by-default shape `spec/26-peer-clustering.md`
//! itself already uses for plain cluster membership (deliberate consistency, not an oversight:
//! the base project's own security note for that shape — "a name is a shared, unauthenticated
//! label until corroborated" — applies here identically). `oag_crypto::PeerIdentity` (the same
//! identity a peer already uses for everything else) signs these; the domain string and message
//! shape are entirely this crate's own, so nothing here is parsed by, or needs to be understood
//! by, the base project's own `oag-sync` wire protocol.
//!
//! Corroboration (multiple *independent* peers declaring the same membership fact) is a
//! strictly separate, later step from parsing one signed declaration -- see
//! `MeshTree::corroboration_for`.

use std::collections::{HashMap, HashSet};

use oag_crypto::{sign_with_domain, verify_with_domain, PeerId, PeerIdentity, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const BRIDGE_DOMAIN: &str = "OAG-MESH:BRIDGE_DECLARATION:v1:";

/// Same tolerance the base project's own signed declarations use (presence heartbeats, cluster
/// declarations, transfer/gateway requests) -- generous on purpose, a declaration shouldn't be
/// rejected just for taking an unusually long time in flight.
pub const MAX_CLOCK_SKEW_SECONDS: i64 = 300;

/// What's being placed into a mesh-group: either a base-layer `spec/26` cluster, referenced by
/// its plain `[cluster].name` string (a leaf), or another mesh-group, referenced by name
/// (an interior node) -- this recursion is what "clusters within clusters" means concretely.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum MeshMember {
    BaseCluster(String),
    MeshGroup(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedBridgeDeclaration {
    pub peer_id: String,
    /// Hex-encoded Ed25519 public key -- same convention the base project's own signed
    /// declarations use (`HelloResponse`, `ClusterDeclaration`, presence heartbeats, ...).
    pub public_key: String,
    /// The mesh-group `member` is being placed into.
    pub mesh_group: String,
    pub member: MeshMember,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeDeclaration {
    #[serde(flatten)]
    pub unsigned: UnsignedBridgeDeclaration,
    pub signature: String,
}

#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
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
    #[error("a mesh-group cannot declare itself as its own member (direct self-reference)")]
    SelfReference,
    #[error("internal error: {0}")]
    Internal(String),
}

fn decode_32(s: &str) -> Option<[u8; 32]> {
    hex::decode(s).ok().and_then(|v| v.try_into().ok())
}

fn decode_64(s: &str) -> Option<[u8; 64]> {
    hex::decode(s).ok().and_then(|v| v.try_into().ok())
}

/// Sign a declaration that `member` belongs to `mesh_group`. Takes `timestamp` explicitly
/// (rather than reading the clock itself) so tests can exercise `verify`'s clock-skew check
/// deterministically -- same reasoning as every signed-message constructor in the base project.
pub fn build_and_sign(
    identity: &PeerIdentity,
    mesh_group: &str,
    member: MeshMember,
    timestamp: i64,
) -> Result<BridgeDeclaration, BridgeError> {
    if let MeshMember::MeshGroup(name) = &member {
        if name == mesh_group {
            return Err(BridgeError::SelfReference);
        }
    }
    let unsigned = UnsignedBridgeDeclaration {
        peer_id: identity.peer_id().to_string(),
        public_key: hex::encode(identity.verifying_key().to_bytes()),
        mesh_group: mesh_group.to_string(),
        member,
        timestamp,
    };
    let canonical =
        oag_core::canonical_json_bytes(&unsigned).map_err(|e| BridgeError::Internal(e.to_string()))?;
    let signature = sign_with_domain(identity.signing_key(), BRIDGE_DOMAIN, &canonical);
    Ok(BridgeDeclaration { unsigned, signature: hex::encode(signature.to_bytes()) })
}

/// Verify a declaration's `(peer_id, public_key)` pairing, its Ed25519 signature, and timestamp
/// freshness. Returns the verified declaring peer's `PeerId`. Does **not** check corroboration,
/// authorization, or whether `peer_id` has any real standing in `mesh_group`/`member` -- same
/// bare-self-assertion shape the base project's own `spec/26-peer-clustering.md` documents and
/// accepts for plain cluster declarations; see `MeshTree::corroboration_for` for the separate
/// step that actually weighs multiple declarations against each other.
pub fn verify(declaration: &BridgeDeclaration, now: i64) -> Result<PeerId, BridgeError> {
    let peer_id: PeerId = declaration.unsigned.peer_id.parse()?;
    let pk_bytes = decode_32(&declaration.unsigned.public_key).ok_or(BridgeError::InvalidPublicKey)?;
    let verifying_key = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| BridgeError::InvalidPublicKey)?;
    if peer_id != PeerId::from_public_key(&verifying_key) {
        return Err(BridgeError::PeerIdKeyMismatch);
    }

    let canonical = oag_core::canonical_json_bytes(&declaration.unsigned)
        .map_err(|e| BridgeError::Internal(e.to_string()))?;
    let sig_bytes = decode_64(&declaration.signature).ok_or(BridgeError::BadSignatureEncoding)?;
    let signature = Signature::from_bytes(&sig_bytes);
    verify_with_domain(&verifying_key, BRIDGE_DOMAIN, &canonical, &signature)
        .map_err(|_| BridgeError::BadSignature)?;

    if (declaration.unsigned.timestamp - now).abs() > MAX_CLOCK_SKEW_SECONDS {
        return Err(BridgeError::ClockSkew);
    }

    Ok(peer_id)
}

/// A collected set of verified declarations, resolved into queryable membership facts. Built
/// purely in memory from whatever declarations the caller has gathered (from any transport --
/// this crate doesn't yet define one, see `spec/01-overview.md`'s open questions); nothing here
/// talks to the network or to the base project's own storage.
#[derive(Debug, Default)]
pub struct MeshTree {
    /// (mesh_group, member) -> set of declaring peer ids. A `HashSet` per edge, not a count --
    /// the same declaring peer re-asserting the same fact must not inflate corroboration (that
    /// would make corroboration free to fake by simply repeating yourself), only genuinely
    /// distinct peers asserting it independently do.
    edges: HashMap<(String, MeshMember), HashSet<PeerId>>,
}

impl MeshTree {
    pub fn new() -> Self {
        Self::default()
    }

    /// Verifies `declaration` and, if valid, records it. Returns the declaring peer's `PeerId`
    /// on success. A declaration that fails verification is never recorded -- same "verify
    /// before you trust it at all" posture as everything else in this family of protocols.
    pub fn add(&mut self, declaration: &BridgeDeclaration, now: i64) -> Result<PeerId, BridgeError> {
        let peer_id = verify(declaration, now)?;
        self.edges
            .entry((declaration.unsigned.mesh_group.clone(), declaration.unsigned.member.clone()))
            .or_default()
            .insert(peer_id);
        Ok(peer_id)
    }

    /// How many *distinct* peers have declared that `member` belongs to `mesh_group`. `0` if
    /// nothing has ever asserted this edge. This is the corroboration signal -- a single
    /// self-declaration (corroboration 1) is exactly as unauthenticated-as-a-label as the base
    /// project's own plain cluster names are; a caller deciding how much to trust an edge should
    /// weigh this number, not just whether the edge exists at all.
    pub fn corroboration_for(&self, mesh_group: &str, member: &MeshMember) -> usize {
        self.edges.get(&(mesh_group.to_string(), member.clone())).map(HashSet::len).unwrap_or(0)
    }

    /// Every direct member of `mesh_group` (one level, not recursive) with at least
    /// `min_corroboration` distinct declaring peers.
    pub fn members_of(&self, mesh_group: &str, min_corroboration: usize) -> Vec<MeshMember> {
        self.edges
            .iter()
            .filter(|((group, _), peers)| group == mesh_group && peers.len() >= min_corroboration)
            .map(|((_, member), _)| member.clone())
            .collect()
    }

    /// Every base-layer cluster name reachable from `mesh_group` by following `MeshGroup`
    /// members recursively -- "clusters within clusters," flattened. A cycle (group A contains
    /// group B which contains group A) terminates instead of looping forever; a cyclical mesh
    /// topology is a caller/operator error, not something this function tries to interpret as
    /// meaningful.
    pub fn base_clusters_under(&self, mesh_group: &str, min_corroboration: usize) -> HashSet<String> {
        let mut visited_groups = HashSet::new();
        let mut result = HashSet::new();
        self.collect_base_clusters(mesh_group, min_corroboration, &mut visited_groups, &mut result);
        result
    }

    fn collect_base_clusters(
        &self,
        mesh_group: &str,
        min_corroboration: usize,
        visited_groups: &mut HashSet<String>,
        result: &mut HashSet<String>,
    ) {
        if !visited_groups.insert(mesh_group.to_string()) {
            return; // already visited -- cycle, stop here
        }
        for member in self.members_of(mesh_group, min_corroboration) {
            match member {
                MeshMember::BaseCluster(name) => {
                    result.insert(name);
                }
                MeshMember::MeshGroup(name) => {
                    self.collect_base_clusters(&name, min_corroboration, visited_groups, result);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declaration_sign_and_verify_round_trip() {
        let identity = PeerIdentity::generate();
        let decl =
            build_and_sign(&identity, "north-america", MeshMember::BaseCluster("ny-dc1".into()), 1_000).unwrap();
        let peer_id = verify(&decl, 1_010).unwrap();
        assert_eq!(peer_id, identity.peer_id());
    }

    #[test]
    fn declaring_a_mesh_group_as_its_own_member_is_rejected() {
        let identity = PeerIdentity::generate();
        let err =
            build_and_sign(&identity, "north-america", MeshMember::MeshGroup("north-america".into()), 1_000)
                .unwrap_err();
        assert!(matches!(err, BridgeError::SelfReference));
    }

    #[test]
    fn tampered_mesh_group_fails_verification() {
        let identity = PeerIdentity::generate();
        let mut decl =
            build_and_sign(&identity, "north-america", MeshMember::BaseCluster("ny-dc1".into()), 1_000).unwrap();
        decl.unsigned.mesh_group = "europe".to_string();
        assert!(matches!(verify(&decl, 1_010), Err(BridgeError::BadSignature)));
    }

    #[test]
    fn mismatched_peer_id_and_public_key_is_rejected() {
        let victim = PeerIdentity::generate();
        let attacker = PeerIdentity::generate();
        let mut decl =
            build_and_sign(&victim, "north-america", MeshMember::BaseCluster("ny-dc1".into()), 1_000).unwrap();
        decl.unsigned.public_key = hex::encode(attacker.verifying_key().to_bytes());
        let canonical = oag_core::canonical_json_bytes(&decl.unsigned).unwrap();
        let sig = sign_with_domain(attacker.signing_key(), BRIDGE_DOMAIN, &canonical);
        decl.signature = hex::encode(sig.to_bytes());
        assert!(matches!(verify(&decl, 1_010), Err(BridgeError::PeerIdKeyMismatch)));
    }

    #[test]
    fn stale_timestamp_is_rejected() {
        let identity = PeerIdentity::generate();
        let decl =
            build_and_sign(&identity, "north-america", MeshMember::BaseCluster("ny-dc1".into()), 1_000).unwrap();
        let far_future = 1_000 + MAX_CLOCK_SKEW_SECONDS + 1;
        assert!(matches!(verify(&decl, far_future), Err(BridgeError::ClockSkew)));
    }

    #[test]
    fn corroboration_counts_distinct_peers_not_repeated_declarations() {
        let a = PeerIdentity::generate();
        let b = PeerIdentity::generate();
        let mut tree = MeshTree::new();

        let decl_a =
            build_and_sign(&a, "north-america", MeshMember::BaseCluster("ny-dc1".into()), 1_000).unwrap();
        tree.add(&decl_a, 1_010).unwrap();
        assert_eq!(tree.corroboration_for("north-america", &MeshMember::BaseCluster("ny-dc1".into())), 1);

        // The same peer re-declaring the identical fact must not inflate corroboration.
        let decl_a_again =
            build_and_sign(&a, "north-america", MeshMember::BaseCluster("ny-dc1".into()), 1_001).unwrap();
        tree.add(&decl_a_again, 1_011).unwrap();
        assert_eq!(tree.corroboration_for("north-america", &MeshMember::BaseCluster("ny-dc1".into())), 1);

        // A genuinely different peer declaring the same fact does.
        let decl_b =
            build_and_sign(&b, "north-america", MeshMember::BaseCluster("ny-dc1".into()), 1_000).unwrap();
        tree.add(&decl_b, 1_010).unwrap();
        assert_eq!(tree.corroboration_for("north-america", &MeshMember::BaseCluster("ny-dc1".into())), 2);
    }

    #[test]
    fn an_invalid_declaration_is_never_recorded() {
        let identity = PeerIdentity::generate();
        let mut decl =
            build_and_sign(&identity, "north-america", MeshMember::BaseCluster("ny-dc1".into()), 1_000).unwrap();
        decl.unsigned.mesh_group = "tampered".to_string();
        let mut tree = MeshTree::new();
        assert!(tree.add(&decl, 1_010).is_err());
        assert_eq!(tree.corroboration_for("tampered", &MeshMember::BaseCluster("ny-dc1".into())), 0);
    }

    #[test]
    fn base_clusters_under_recurses_through_nested_mesh_groups() {
        let a = PeerIdentity::generate();
        let mut tree = MeshTree::new();

        // "clusters within clusters": global contains north-america and europe (mesh-groups);
        // north-america contains two base clusters.
        tree.add(
            &build_and_sign(&a, "global", MeshMember::MeshGroup("north-america".into()), 1_000).unwrap(),
            1_010,
        )
        .unwrap();
        tree.add(
            &build_and_sign(&a, "global", MeshMember::MeshGroup("europe".into()), 1_000).unwrap(),
            1_010,
        )
        .unwrap();
        tree.add(
            &build_and_sign(&a, "north-america", MeshMember::BaseCluster("ny-dc1".into()), 1_000).unwrap(),
            1_010,
        )
        .unwrap();
        tree.add(
            &build_and_sign(&a, "north-america", MeshMember::BaseCluster("sf-dc1".into()), 1_000).unwrap(),
            1_010,
        )
        .unwrap();
        tree.add(
            &build_and_sign(&a, "europe", MeshMember::BaseCluster("fra-dc1".into()), 1_000).unwrap(),
            1_010,
        )
        .unwrap();

        let all = tree.base_clusters_under("global", 1);
        assert_eq!(all, HashSet::from(["ny-dc1".to_string(), "sf-dc1".to_string(), "fra-dc1".to_string()]));

        let na_only = tree.base_clusters_under("north-america", 1);
        assert_eq!(na_only, HashSet::from(["ny-dc1".to_string(), "sf-dc1".to_string()]));
    }

    #[test]
    fn base_clusters_under_terminates_on_a_cycle() {
        let a = PeerIdentity::generate();
        let mut tree = MeshTree::new();
        // group-a contains group-b, group-b contains group-a -- a cyclical topology, caller
        // error, must not infinite-loop.
        tree.add(
            &build_and_sign(&a, "group-a", MeshMember::MeshGroup("group-b".into()), 1_000).unwrap(),
            1_010,
        )
        .unwrap();
        tree.add(
            &build_and_sign(&a, "group-b", MeshMember::MeshGroup("group-a".into()), 1_000).unwrap(),
            1_010,
        )
        .unwrap();
        tree.add(
            &build_and_sign(&a, "group-b", MeshMember::BaseCluster("leaf1".into()), 1_000).unwrap(),
            1_010,
        )
        .unwrap();

        let result = tree.base_clusters_under("group-a", 1);
        assert_eq!(result, HashSet::from(["leaf1".to_string()]));
    }

    #[test]
    fn members_of_filters_by_minimum_corroboration() {
        let a = PeerIdentity::generate();
        let b = PeerIdentity::generate();
        let mut tree = MeshTree::new();

        tree.add(
            &build_and_sign(&a, "global", MeshMember::BaseCluster("weakly-claimed".into()), 1_000).unwrap(),
            1_010,
        )
        .unwrap();
        tree.add(
            &build_and_sign(&a, "global", MeshMember::BaseCluster("strongly-claimed".into()), 1_000).unwrap(),
            1_010,
        )
        .unwrap();
        tree.add(
            &build_and_sign(&b, "global", MeshMember::BaseCluster("strongly-claimed".into()), 1_000).unwrap(),
            1_010,
        )
        .unwrap();

        let strong_only = tree.members_of("global", 2);
        assert_eq!(strong_only, vec![MeshMember::BaseCluster("strongly-claimed".into())]);

        let both = tree.members_of("global", 1);
        assert_eq!(both.len(), 2);
    }
}
