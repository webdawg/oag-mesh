# Cluster Nesting (Bridge Declarations)

**Source**: `crates/oag-mesh/src/bridge.rs`.

"These are clusters within clusters" — the base project's `spec/26-peer-clustering.md` gives a
peer exactly one flat cluster name. This file adds hierarchy on top, in this repository only,
with **zero changes to `oag-sync` or any other base-project code** — the old mechanism keeps
working exactly as it already does.

## The mechanism

A peer that already belongs to a base-layer cluster (or to another mesh-group) can sign a
`BridgeDeclaration`: "I declare that `member` belongs to `mesh_group`." `member` is either
`BaseCluster(name)` — a plain `spec/26` cluster name — or `MeshGroup(name)` — another mesh-group,
which is how nesting happens: a mesh-group's members can themselves be mesh-groups, recursively.

Signed with the peer's own `oag_crypto::PeerIdentity` (the identical identity it already uses for
everything else), but under this crate's own domain string (`OAG-MESH:BRIDGE_DECLARATION:v1:`) and
message shape — nothing here is base-project `oag-sync` wire format, and nothing in the base
project needs to parse or even know about it.

Verification (`bridge::verify`) checks the same three things every signed declaration in this
whole family of protocols checks: the claimed `peer_id` really is the hash of the claimed
`public_key` (anti-spoofed-pairing), the Ed25519 signature is valid, and the timestamp is fresh
(`MAX_CLOCK_SKEW_SECONDS = 300`, same tolerance the base project uses everywhere). It does **not**
check authorization or corroboration — a lone verified declaration is exactly as
unauthenticated-as-a-label as the base project's own plain `[cluster].name` already is by design
(`spec/26-peer-clustering.md`'s own stated security posture, carried over deliberately, not
accidentally).

## Anti-sybil resistance

Verification alone doesn't bound how many fresh `PeerIdentity`s one actor can mint to
independently "declare" the same `(mesh_group, member)` edge, inflating `corroboration_for`'s
distinct-peer count for free -- the same gap `corroboration::ClaimReportProofOfWork` closes for
claim reports (`spec/05`'s "Anti-sybil resistance"), and one that matters here specifically
because `corroboration::ClaimCorroboration::best_corroborated_value_cross_checked` leans on this
file's own data to decide whether a claimed cluster name is "real" (`spec/05`'s "Cross-checking
against real cluster nesting"). A sybil-inflated or freely-fabricated edge here would have let
that cross-check be gamed as cheaply as the thing it was built to catch.

`BridgeProofOfWork` mirrors `anonymous_event::ProofOfWork` and `ClaimReportProofOfWork`'s
blake3-based, Hashcash-style leading-zero-bit search, bound to one `(peer_id, mesh_group,
member)` combination. The difficulty `MeshTree::required_difficulty_bits` requires is keyed to
distinct-peer count on the edge -- the exact resource `corroboration_for` counts:

- **Free (`0` bits) if `peer_id` has already declared this edge.** Re-declaring it (e.g. with a
  fresher timestamp) can't increase `corroboration_for`, so there's nothing to tax.
- **Otherwise, `BASE_BRIDGE_DIFFICULTY_BITS` plus `BRIDGE_DIFFICULTY_STEP_BITS` for every
  distinct peer already corroborating this edge.** The first peer to declare a brand-new edge
  pays the base cost; the fifth pays real, escalating work.

Same caveat as every other proof-of-work in this crate, stated plainly: this raises the cost of
fabricating edge corroboration from free to real, it does **not** stop a well-resourced attacker.

## Corroboration

`MeshTree` collects verified declarations in memory and answers two questions:

- `corroboration_for(mesh_group, member)` — how many **distinct** peers have declared this exact
  edge. Re-declaring your own claim never inflates this (a `HashSet<PeerId>` per edge, not a
  counter) — corroboration must come from independently convinced peers, not repetition.
- `members_of(mesh_group, min_corroboration)` / `base_clusters_under(mesh_group,
  min_corroboration)` — resolve the tree (recursively flattening nested mesh-groups down to their
  base-cluster leaves) filtered to edges with at least `min_corroboration` distinct declarers. A
  cyclical topology (group A contains group B contains group A) terminates rather than looping
  forever — a caller/operator error, not something this function tries to interpret.

## Bidirectional traversal: bounded-hop reachability

`members_of`/`base_clusters_under` only ever go one direction: from a mesh-group down to its
members. They can't answer "what mesh-groups is *this* cluster nested under," or "how do I get
from this base cluster to that one" when the two aren't in a direct parent/child relationship.
`MeshTree::shortest_path(from, to, min_corroboration)` and `degrees_of_separation(from, to,
min_corroboration)` close that: breadth-first search treating every sufficiently-corroborated
`(mesh_group, member)` edge as traversable in *either* direction -- down into a mesh-group's
members, or up out of a cluster/mesh-group to whatever contains it -- answering "how many hops,
through what chain" between any two `MeshMember`s this tree has data for.

This is this crate's concrete answer to a founding principle stated directly by this
repository's user: **"there are only so many degrees of separation, go in any direction and get
there"** (quoted in full, with this file's own interpretation of it, in the top-level
`README.md`'s "Founding principle: bounded-hop reachability" section). `degrees_of_separation`
makes that idea literal and queryable rather than just aspirational -- but it is a **design goal
for how clusters get bridged, not a guarantee this mechanism enforces**: if an operator never
bridges two clusters, or only through a long, sparse chain of mesh-groups, `degrees_of_separation`
reports that honestly (a large hop count, or `None` if genuinely unreachable from the data this
tree holds) rather than pretending the mesh is smaller than it is. `from == to` is `0` hops by
definition, with no search performed. A cyclical topology terminates the search (same guard
`base_clusters_under`'s own cycle test exercises) rather than looping forever.

`shortest_path` only ever answers from *this one node's own* local edges, though -- it has no
way to find a path that's only discoverable by combining what several different peers each
separately know. `spec/13-distributed-route-search.md`'s `find_route_across_mesh` is the second
half of the same founding principle, expanded with more of the user's own words: routing should
work by "mov[ing] forward through random clusters of nodes," asking the mesh itself when one
node's own knowledge runs out, bounded by the identical "only so many degrees of separation" --
now a literal hop budget (`max_hops`) rather than just a property of already-known data.

## What this explicitly is not (yet)

- **Transport exists now (`spec/04-transport.md`).** A declaration reaches other mesh nodes by
  being pushed to a static, operator-configured peer list (`broadcast_bridge_declaration`), or
  by a peer pulling and merging a whole `MeshTree` snapshot later (`spec/10-anti-entropy.md`) --
  the latter trusts the source peer's own prior verification rather than re-checking signatures
  itself, a real trade-off `spec/10` states plainly.
- **Persistence exists now (`spec/08-persistence.md`), but is manual and not crash-safe.**
  `MeshTree::snapshot`/`from_snapshot` let a caller save/load this tree to/from disk via
  `transport::MeshState::save_to_dir`/`load_from_dir` -- nothing calls this automatically, and a
  crash mid-write can still lose or corrupt the file. Still in-memory at runtime either way.
- **No interaction with the base project's `FederationPolicy`/trust machinery.** A base cluster
  being nested under a mesh-group does not, by itself, change how the base project's own peers
  federate with each other — see `spec/01-overview.md`'s "not a trust merger" note.
- **No enforcement of "independent enough."** Two declaring peers are counted as distinct the
  moment their `PeerId`s differ, even if they're operated by the same organization. Proof-of-work
  (above) taxes *how many* distinct peers one actor can mint for free, not *whether* they're
  actually operated by different organizations -- a well-resourced single operator can still
  solve proof-of-work for several real `PeerIdentity`s and look just as "independent" as before.
  Weighing that is a later, harder problem (see `spec/01-overview.md`'s open questions).
- **A `BridgeDeclaration` never records which peers belong to a cluster, only that a cluster
  *name* is nested somewhere.** `is_attested_base_cluster` (above) confirms the name is real; it
  says nothing about any individual peer's standing in that cluster. Closing that is
  `spec/09-cluster-membership-attestation.md`'s `MembershipAttestation` -- a new, separate
  mechanism, not an extension of this one.
- **`shortest_path`/`degrees_of_separation` are node-local and not optimized for a large mesh.**
  Both answer only from whatever edges *this* tree already holds -- a node that hasn't received
  (via push or `spec/10-anti-entropy.md`'s pull) the declarations describing a path won't find
  one even if it exists elsewhere in the wider mesh. Each call rebuilds its breadth-first search
  from `self.edges` from scratch rather than maintaining any cached adjacency structure; fine at
  this crate's current scale, a real cost on a mesh with a very large number of edges.

## Tests

`crates/oag-mesh/src/bridge.rs` (22 unit tests): sign/verify round trip, self-reference rejection
(a mesh-group cannot declare itself as its own member), tampered-field/mismatched-key/stale-
timestamp rejection (mirroring the base project's own signed-declaration test shapes), corroboration
counting distinct peers rather than repeated declarations, recursive resolution through nested
mesh-groups down to base-cluster leaves, cycle termination, minimum-corroboration filtering,
`is_attested_base_cluster`'s existence/minimum-corroboration check, a declaration with no
proof-of-work being rejected, a peer re-declaring an edge it already declared requiring no
proof-of-work, required difficulty escalating with each additional distinct peer on one edge
(and a stale proof no longer being enough), a proof-of-work being bound to its own declaration
and unable to be reused for another, and `merge_snapshot` unioning peer sets idempotently (see
`spec/10-anti-entropy.md`). Plus 6 more for bidirectional traversal: a node's degrees of
separation from itself is `0`; a direct edge is one hop in either direction (mesh-group-to-member
and member-to-mesh-group); reaching a sibling cluster through a shared parent mesh-group takes
the right number of hops and the right path, going up and back down, not just sideways through
top-down traversal alone; a genuinely unreachable node returns `None`; `min_corroboration`
excludes an edge below the threshold from the path search entirely; a cyclical topology
terminates the search rather than hanging.
