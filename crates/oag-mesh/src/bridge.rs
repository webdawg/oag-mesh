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

/// The difficulty (in required leading zero bits, same `blake3` scheme as
/// `anonymous_event::ProofOfWork` and `corroboration::ClaimReportProofOfWork`) for the *first*
/// peer to declare a given `(mesh_group, member)` edge. See `MeshTree::required_difficulty_bits`
/// for why every other declaration of the same edge -- by a peer that already declared it --
/// costs nothing at all.
pub const BASE_BRIDGE_DIFFICULTY_BITS: u32 = 16;

/// How much the required difficulty grows for each additional distinct peer already declaring
/// a given edge before this one. Mirrors `corroboration::CLAIM_REPORT_DIFFICULTY_STEP_BITS`'s
/// shape exactly, substituting "distinct peer already corroborating this edge" for "distinct
/// cluster already corroborating this claim" -- here, distinct peer *is* the resource being
/// counted (`corroboration_for`), so that's what gets taxed directly.
pub const BRIDGE_DIFFICULTY_STEP_BITS: u32 = 4;

/// The difficulty required to be the `existing_corroboration`-th peer (0-indexed) to declare one
/// edge -- the first peer needs `BASE_BRIDGE_DIFFICULTY_BITS`, each one after that needs
/// `BRIDGE_DIFFICULTY_STEP_BITS` more.
pub fn difficulty_bits_for_corroboration_number(existing_corroboration: usize) -> u32 {
    BASE_BRIDGE_DIFFICULTY_BITS + (existing_corroboration as u32) * BRIDGE_DIFFICULTY_STEP_BITS
}

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
    #[error("proof of work does not meet the required {required_bits} leading zero bits for this (mesh_group, member) edge")]
    InsufficientProofOfWork { required_bits: u32 },
    #[error("internal error: {0}")]
    Internal(String),
}

/// Anti-sybil proof-of-work for a `BridgeDeclaration` -- same motivation as
/// `corroboration::ClaimReportProofOfWork`: signature verification alone doesn't bound how many
/// fresh `PeerIdentity`s one actor can mint to independently "declare" the same
/// `(mesh_group, member)` edge, inflating `MeshTree::corroboration_for`'s distinct-peer count for
/// free. This matters more than it might otherwise, because `corroboration::ClaimCorroboration::
/// best_corroborated_value_cross_checked` leans on `MeshTree::is_attested_base_cluster` to decide
/// whether a claimed cluster name is "real" -- a sybil-inflated or freely-fabricated edge here
/// would have let that cross-check be gamed just as cheaply as the thing it was built to catch.
/// Same "raises cost, doesn't eliminate" caveat as every other proof-of-work in this crate: a
/// well-resourced attacker is not stopped, only taxed.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct BridgeProofOfWork {
    pub nonce: u64,
}

/// Binds the proof to this specific `(peer_id, mesh_group, member)` combination -- a solved
/// proof for one peer's declaration of one edge cannot be replayed for a different peer, group,
/// or member.
fn bridge_pow_hash(unsigned: &UnsignedBridgeDeclaration, pow: &BridgeProofOfWork) -> Result<blake3::Hash, BridgeError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"OAG-MESH:BRIDGE_DECLARATION_POW:v1:");
    hasher.update(unsigned.peer_id.as_bytes());
    hasher.update(unsigned.mesh_group.as_bytes());
    let member_bytes =
        oag_core::canonical_json_bytes(&unsigned.member).map_err(|e| BridgeError::Internal(e.to_string()))?;
    hasher.update(&member_bytes);
    hasher.update(&pow.nonce.to_le_bytes());
    Ok(hasher.finalize())
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

impl BridgeProofOfWork {
    /// The client-side work: searches for a `nonce` whose `bridge_pow_hash` has at least
    /// `difficulty_bits` leading zero bits. A real submitting client calls
    /// `MeshTree::required_difficulty_bits` first to know what to solve for.
    pub fn solve(unsigned: &UnsignedBridgeDeclaration, difficulty_bits: u32) -> Self {
        let mut nonce = 0u64;
        loop {
            let candidate = BridgeProofOfWork { nonce };
            match bridge_pow_hash(unsigned, &candidate) {
                Ok(hash) if leading_zero_bits(&hash) >= difficulty_bits => return candidate,
                _ => nonce += 1,
            }
        }
    }

    fn satisfies(&self, unsigned: &UnsignedBridgeDeclaration, difficulty_bits: u32) -> Result<bool, BridgeError> {
        Ok(leading_zero_bits(&bridge_pow_hash(unsigned, self)?) >= difficulty_bits)
    }
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

    /// The proof-of-work difficulty a declaration of `(mesh_group, member)` by `peer_id` must
    /// currently meet, per `difficulty_bits_for_corroboration_number`. **Free (`0` bits, always
    /// satisfied) if `peer_id` has already declared this edge** -- re-declaring it doesn't
    /// increase `corroboration_for`, so there is nothing to tax. Otherwise, the cost of becoming
    /// the next *new* distinct peer corroborating this edge, scaled by how many already have. A
    /// submitting client should call this before spending work solving a `BridgeProofOfWork`.
    pub fn required_difficulty_bits(&self, mesh_group: &str, member: &MeshMember, peer_id: &PeerId) -> u32 {
        let Some(peers) = self.edges.get(&(mesh_group.to_string(), member.clone())) else {
            return BASE_BRIDGE_DIFFICULTY_BITS;
        };
        if peers.contains(peer_id) {
            return 0;
        }
        difficulty_bits_for_corroboration_number(peers.len())
    }

    /// Verifies `declaration`, checks `pow` against `required_difficulty_bits` for this
    /// declaration's `(mesh_group, member, peer_id)` *at the moment this is called* -- same
    /// reasoning as `corroboration::ClaimCorroboration::add`, only this struct knows how many
    /// distinct peers already corroborate the edge -- and if both pass, records it. Returns the
    /// declaring peer's `PeerId` on success. A declaration that fails verification, or whose
    /// proof-of-work is insufficient, is never recorded -- same "verify before you trust it at
    /// all" posture as everything else in this family of protocols.
    pub fn add(&mut self, declaration: &BridgeDeclaration, pow: BridgeProofOfWork, now: i64) -> Result<PeerId, BridgeError> {
        let peer_id = verify(declaration, now)?;
        let required_bits =
            self.required_difficulty_bits(&declaration.unsigned.mesh_group, &declaration.unsigned.member, &peer_id);
        if !pow.satisfies(&declaration.unsigned, required_bits)? {
            return Err(BridgeError::InsufficientProofOfWork { required_bits });
        }
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

    /// Whether `name` is attested anywhere in this tree as a real base-layer cluster -- i.e.
    /// some `BridgeDeclaration` placed `MeshMember::BaseCluster(name)` into *some* mesh-group,
    /// with at least `min_corroboration` distinct declaring peers. This only confirms the
    /// cluster *name* is a real, nested entity in the mesh; it says nothing about whether any
    /// particular reporting peer actually belongs to that cluster -- a `BridgeDeclaration` only
    /// ever asserts that a cluster name is nested under a mesh-group, never which peers are
    /// members of the cluster itself, so that half of "is this claim real" is a gap this method
    /// cannot close. See `corroboration.rs`'s `best_corroborated_value_cross_checked` for where
    /// this is used, and its own doc comment for that remaining gap stated plainly.
    pub fn is_attested_base_cluster(&self, name: &str, min_corroboration: usize) -> bool {
        self.edges.iter().any(|((_, member), peers)| {
            matches!(member, MeshMember::BaseCluster(n) if n == name) && peers.len() >= min_corroboration
        })
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

    /// A persistable snapshot of every edge this tree currently holds. `PeerId` has no
    /// `Serialize`/`Deserialize` of its own (it's from the base project, reused via git
    /// dependency, never modified here), so peer ids round-trip through their `Display`/
    /// `FromStr` string form -- the same convention every signed message in this crate already
    /// uses for a `peer_id` field. See `MeshTree::from_snapshot` for the inverse.
    pub fn snapshot(&self) -> Vec<BridgeEdgeSnapshot> {
        self.edges
            .iter()
            .map(|((mesh_group, member), peers)| BridgeEdgeSnapshot {
                mesh_group: mesh_group.clone(),
                member: member.clone(),
                peers: peers.iter().map(|p| p.to_string()).collect(),
            })
            .collect()
    }

    /// Rebuilds a `MeshTree` from `snapshot` (e.g. loaded from disk via `persistence::load_json`).
    /// A peer id string that fails to parse is dropped with a warning rather than failing the
    /// whole load -- corrupted or hand-edited persisted state shouldn't prevent a node from
    /// starting with whatever of it is still readable.
    pub fn from_snapshot(snapshot: Vec<BridgeEdgeSnapshot>) -> Self {
        let mut tree = Self::new();
        tree.merge_snapshot(snapshot);
        tree
    }

    /// Merges `snapshot` into this tree's existing edges -- unions each edge's declaring-peer set
    /// rather than replacing it, so merging the same snapshot repeatedly (or merging snapshots
    /// from several different peers) is idempotent and additive, never lossy. The building block
    /// for `transport::pull_and_merge`'s pull-based anti-entropy (`spec/10-anti-entropy.md`): a
    /// peer that was offline for a `broadcast_bridge_declaration` can catch up by pulling a
    /// peer's whole snapshot and merging it in, rather than waiting to be re-pushed to
    /// individually. Same peer-id-string-parse-failure handling as `from_snapshot` -- an
    /// unparsable entry is dropped with a warning, not fatal to the rest of the merge.
    ///
    /// **Trust note**: unlike `add`, this does not re-verify a signature or proof-of-work for any
    /// of it -- a snapshot has already collapsed each edge down to a bare set of peer ids, with
    /// no signed `BridgeDeclaration` left to re-check. Merging a snapshot means trusting that the
    /// peer it came from already verified what it's reporting, the same trust already extended to
    /// any peer on `MeshState.peers`'s static list, not a new or weaker boundary introduced here
    /// -- but it is a different (weaker) guarantee than `add`'s own independent verification, and
    /// callers should not confuse the two. See `spec/10-anti-entropy.md` for this stated plainly.
    pub fn merge_snapshot(&mut self, snapshot: Vec<BridgeEdgeSnapshot>) {
        for edge in snapshot {
            let mut peers = HashSet::new();
            for peer_id_str in edge.peers {
                match peer_id_str.parse::<PeerId>() {
                    Ok(peer_id) => {
                        peers.insert(peer_id);
                    }
                    Err(e) => tracing::warn!(peer_id = %peer_id_str, error = %e, "dropping unparsable peer id from persisted bridge snapshot"),
                }
            }
            self.edges.entry((edge.mesh_group, edge.member)).or_default().extend(peers);
        }
    }
}

/// See `MeshTree::snapshot`/`MeshTree::from_snapshot`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeEdgeSnapshot {
    pub mesh_group: String,
    pub member: MeshMember,
    pub peers: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Solves whatever proof-of-work `tree` currently requires for `decl`'s
    /// `(mesh_group, member, peer_id)`, then adds it -- the test-side equivalent of a real
    /// client calling `required_difficulty_bits` before submitting (mirrors
    /// `anonymous_event.rs`'s and `corroboration.rs`'s own identical test helpers).
    fn add_with_fresh_pow(tree: &mut MeshTree, decl: &BridgeDeclaration, now: i64) -> Result<PeerId, BridgeError> {
        let peer_id: PeerId = decl.unsigned.peer_id.parse().unwrap();
        let required = tree.required_difficulty_bits(&decl.unsigned.mesh_group, &decl.unsigned.member, &peer_id);
        let pow = BridgeProofOfWork::solve(&decl.unsigned, required);
        tree.add(decl, pow, now)
    }

    /// Solves for a nonce whose hash has *exactly* `exact_bits` leading zero bits, not merely
    /// at least -- unlike `BridgeProofOfWork::solve`'s `>=` search (which can occasionally
    /// overshoot a higher threshold by chance, about 1-in-16 per extra `BRIDGE_DIFFICULTY_STEP_BITS`
    /// step), this guarantees the result does NOT satisfy any higher threshold, which is what an
    /// escalation-rejection assertion actually needs to be deterministic rather than flaky.
    fn solve_bridge_pow_exact(unsigned: &UnsignedBridgeDeclaration, exact_bits: u32) -> BridgeProofOfWork {
        let mut nonce = 0u64;
        loop {
            let candidate = BridgeProofOfWork { nonce };
            if leading_zero_bits(&bridge_pow_hash(unsigned, &candidate).unwrap()) == exact_bits {
                return candidate;
            }
            nonce += 1;
        }
    }

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
        add_with_fresh_pow(&mut tree, &decl_a, 1_010).unwrap();
        assert_eq!(tree.corroboration_for("north-america", &MeshMember::BaseCluster("ny-dc1".into())), 1);

        // The same peer re-declaring the identical fact must not inflate corroboration.
        let decl_a_again =
            build_and_sign(&a, "north-america", MeshMember::BaseCluster("ny-dc1".into()), 1_001).unwrap();
        add_with_fresh_pow(&mut tree, &decl_a_again, 1_011).unwrap();
        assert_eq!(tree.corroboration_for("north-america", &MeshMember::BaseCluster("ny-dc1".into())), 1);

        // A genuinely different peer declaring the same fact does.
        let decl_b =
            build_and_sign(&b, "north-america", MeshMember::BaseCluster("ny-dc1".into()), 1_000).unwrap();
        add_with_fresh_pow(&mut tree, &decl_b, 1_010).unwrap();
        assert_eq!(tree.corroboration_for("north-america", &MeshMember::BaseCluster("ny-dc1".into())), 2);
    }

    #[test]
    fn an_invalid_declaration_is_never_recorded() {
        let identity = PeerIdentity::generate();
        let mut decl =
            build_and_sign(&identity, "north-america", MeshMember::BaseCluster("ny-dc1".into()), 1_000).unwrap();
        decl.unsigned.mesh_group = "tampered".to_string();
        let mut tree = MeshTree::new();
        // A tampered declaration fails signature verification before proof-of-work is even
        // checked, so an unsolved (zero) nonce is fine here -- it must never be reached.
        assert!(tree.add(&decl, BridgeProofOfWork { nonce: 0 }, 1_010).is_err());
        assert_eq!(tree.corroboration_for("tampered", &MeshMember::BaseCluster("ny-dc1".into())), 0);
    }

    #[test]
    fn base_clusters_under_recurses_through_nested_mesh_groups() {
        let a = PeerIdentity::generate();
        let mut tree = MeshTree::new();

        // "clusters within clusters": global contains north-america and europe (mesh-groups);
        // north-america contains two base clusters.
        add_with_fresh_pow(
            &mut tree,
            &build_and_sign(&a, "global", MeshMember::MeshGroup("north-america".into()), 1_000).unwrap(),
            1_010,
        )
        .unwrap();
        add_with_fresh_pow(
            &mut tree,
            &build_and_sign(&a, "global", MeshMember::MeshGroup("europe".into()), 1_000).unwrap(),
            1_010,
        )
        .unwrap();
        add_with_fresh_pow(
            &mut tree,
            &build_and_sign(&a, "north-america", MeshMember::BaseCluster("ny-dc1".into()), 1_000).unwrap(),
            1_010,
        )
        .unwrap();
        add_with_fresh_pow(
            &mut tree,
            &build_and_sign(&a, "north-america", MeshMember::BaseCluster("sf-dc1".into()), 1_000).unwrap(),
            1_010,
        )
        .unwrap();
        add_with_fresh_pow(
            &mut tree,
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
        add_with_fresh_pow(
            &mut tree,
            &build_and_sign(&a, "group-a", MeshMember::MeshGroup("group-b".into()), 1_000).unwrap(),
            1_010,
        )
        .unwrap();
        add_with_fresh_pow(
            &mut tree,
            &build_and_sign(&a, "group-b", MeshMember::MeshGroup("group-a".into()), 1_000).unwrap(),
            1_010,
        )
        .unwrap();
        add_with_fresh_pow(
            &mut tree,
            &build_and_sign(&a, "group-b", MeshMember::BaseCluster("leaf1".into()), 1_000).unwrap(),
            1_010,
        )
        .unwrap();

        let result = tree.base_clusters_under("group-a", 1);
        assert_eq!(result, HashSet::from(["leaf1".to_string()]));
    }

    #[test]
    fn is_attested_base_cluster_checks_existence_and_minimum_corroboration() {
        let a = PeerIdentity::generate();
        let b = PeerIdentity::generate();
        let mut tree = MeshTree::new();

        add_with_fresh_pow(
            &mut tree,
            &build_and_sign(&a, "global", MeshMember::BaseCluster("ny-dc1".into()), 1_000).unwrap(),
            1_010,
        )
        .unwrap();

        assert!(tree.is_attested_base_cluster("ny-dc1", 1));
        assert!(!tree.is_attested_base_cluster("ny-dc1", 2));
        assert!(!tree.is_attested_base_cluster("made-up-cluster", 1));

        add_with_fresh_pow(
            &mut tree,
            &build_and_sign(&b, "global", MeshMember::BaseCluster("ny-dc1".into()), 1_000).unwrap(),
            1_010,
        )
        .unwrap();
        assert!(tree.is_attested_base_cluster("ny-dc1", 2));
    }

    #[test]
    fn members_of_filters_by_minimum_corroboration() {
        let a = PeerIdentity::generate();
        let b = PeerIdentity::generate();
        let mut tree = MeshTree::new();

        add_with_fresh_pow(
            &mut tree,
            &build_and_sign(&a, "global", MeshMember::BaseCluster("weakly-claimed".into()), 1_000).unwrap(),
            1_010,
        )
        .unwrap();
        add_with_fresh_pow(
            &mut tree,
            &build_and_sign(&a, "global", MeshMember::BaseCluster("strongly-claimed".into()), 1_000).unwrap(),
            1_010,
        )
        .unwrap();
        add_with_fresh_pow(
            &mut tree,
            &build_and_sign(&b, "global", MeshMember::BaseCluster("strongly-claimed".into()), 1_000).unwrap(),
            1_010,
        )
        .unwrap();

        let strong_only = tree.members_of("global", 2);
        assert_eq!(strong_only, vec![MeshMember::BaseCluster("strongly-claimed".into())]);

        let both = tree.members_of("global", 1);
        assert_eq!(both.len(), 2);
    }

    #[test]
    fn a_declaration_with_no_proof_of_work_is_rejected() {
        let identity = PeerIdentity::generate();
        let decl = build_and_sign(&identity, "global", MeshMember::BaseCluster("pow-test".into()), 1_000).unwrap();
        let mut tree = MeshTree::new();
        // Difficulty 0 is never a real solution against BASE_BRIDGE_DIFFICULTY_BITS = 16 for a
        // brand-new edge.
        let err = tree.add(&decl, BridgeProofOfWork { nonce: 0 }, 1_010).unwrap_err();
        assert!(matches!(
            err,
            BridgeError::InsufficientProofOfWork { required_bits } if required_bits == BASE_BRIDGE_DIFFICULTY_BITS
        ));
        assert_eq!(tree.corroboration_for("global", &MeshMember::BaseCluster("pow-test".into())), 0);
    }

    #[test]
    fn a_peer_re_declaring_an_edge_it_already_declared_requires_no_proof_of_work() {
        let a = PeerIdentity::generate();
        let mut tree = MeshTree::new();

        let decl = build_and_sign(&a, "global", MeshMember::BaseCluster("re-declare-test".into()), 1_000).unwrap();
        add_with_fresh_pow(&mut tree, &decl, 1_010).unwrap();

        // The same peer declaring the same edge again (e.g. a fresh timestamp) costs nothing --
        // it can't increase corroboration_for, which is already counting this peer.
        let decl_again =
            build_and_sign(&a, "global", MeshMember::BaseCluster("re-declare-test".into()), 1_001).unwrap();
        let peer_id = a.peer_id();
        assert_eq!(
            tree.required_difficulty_bits("global", &MeshMember::BaseCluster("re-declare-test".into()), &peer_id),
            0
        );
        tree.add(&decl_again, BridgeProofOfWork { nonce: 0 }, 1_011).unwrap();
        assert_eq!(tree.corroboration_for("global", &MeshMember::BaseCluster("re-declare-test".into())), 1);
    }

    #[test]
    fn required_difficulty_escalates_with_each_additional_distinct_peer_on_one_edge() {
        let a = PeerIdentity::generate();
        let b = PeerIdentity::generate();
        let mut tree = MeshTree::new();
        let member = MeshMember::BaseCluster("escalation-test".into());

        assert_eq!(
            tree.required_difficulty_bits("global", &member, &a.peer_id()),
            BASE_BRIDGE_DIFFICULTY_BITS
        );

        add_with_fresh_pow(&mut tree, &build_and_sign(&a, "global", member.clone(), 1_000).unwrap(), 1_010).unwrap();

        // A second, genuinely new peer now costs one extra step -- one distinct peer already
        // corroborates this edge.
        assert_eq!(
            tree.required_difficulty_bits("global", &member, &b.peer_id()),
            BASE_BRIDGE_DIFFICULTY_BITS + BRIDGE_DIFFICULTY_STEP_BITS
        );

        // A stale proof solved at the base difficulty is no longer enough for peer b. Solved to
        // *exactly* the base difficulty (not merely >=) so this assertion is deterministic --
        // `solve`'s `>=` search can occasionally overshoot a higher threshold by chance.
        let decl_b = build_and_sign(&b, "global", member.clone(), 1_000).unwrap();
        let stale_pow = solve_bridge_pow_exact(&decl_b.unsigned, BASE_BRIDGE_DIFFICULTY_BITS);
        let err = tree.add(&decl_b, stale_pow, 1_010).unwrap_err();
        let expected_bits = BASE_BRIDGE_DIFFICULTY_BITS + BRIDGE_DIFFICULTY_STEP_BITS;
        assert!(matches!(err, BridgeError::InsufficientProofOfWork { required_bits } if required_bits == expected_bits));
    }

    #[test]
    fn merge_snapshot_unions_peer_sets_rather_than_replacing_them() {
        let a = PeerIdentity::generate();
        let b = PeerIdentity::generate();
        let mut tree_a = MeshTree::new();
        let mut tree_b = MeshTree::new();
        let member = MeshMember::BaseCluster("merge-test".into());

        add_with_fresh_pow(&mut tree_a, &build_and_sign(&a, "global", member.clone(), 1_000).unwrap(), 1_010).unwrap();
        add_with_fresh_pow(&mut tree_b, &build_and_sign(&b, "global", member.clone(), 1_000).unwrap(), 1_010).unwrap();

        tree_a.merge_snapshot(tree_b.snapshot());
        assert_eq!(tree_a.corroboration_for("global", &member), 2);

        // Merging the identical snapshot again must not double-count (union, not append).
        tree_a.merge_snapshot(tree_b.snapshot());
        assert_eq!(tree_a.corroboration_for("global", &member), 2);
    }

    #[test]
    fn a_bridge_proof_of_work_is_bound_to_its_own_declaration_and_cannot_be_reused() {
        let a = PeerIdentity::generate();
        let b = PeerIdentity::generate();
        let decl_a = build_and_sign(&a, "global", MeshMember::BaseCluster("binding-test-a".into()), 1_000).unwrap();
        let decl_b = build_and_sign(&b, "global", MeshMember::BaseCluster("binding-test-b".into()), 1_000).unwrap();
        let pow_for_a = BridgeProofOfWork::solve(&decl_a.unsigned, BASE_BRIDGE_DIFFICULTY_BITS);

        let mut tree = MeshTree::new();
        // Reusing decl_a's proof for decl_b's (different peer/group/member) must not satisfy it.
        let err = tree.add(&decl_b, pow_for_a, 1_010).unwrap_err();
        assert!(matches!(
            err,
            BridgeError::InsufficientProofOfWork { required_bits } if required_bits == BASE_BRIDGE_DIFFICULTY_BITS
        ));
    }
}
