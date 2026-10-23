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

## What this explicitly is not (yet)

- **No transport.** Nothing here sends a `BridgeDeclaration` anywhere or gossips it between
  peers — this is the signed message shape and the in-memory resolution logic only. A caller
  currently has to get declarations from somewhere itself.
- **No persistence.** `MeshTree` is in-memory, rebuilt from whatever declarations are fed to it.
- **No interaction with the base project's `FederationPolicy`/trust machinery.** A base cluster
  being nested under a mesh-group does not, by itself, change how the base project's own peers
  federate with each other — see `spec/01-overview.md`'s "not a trust merger" note.
- **No enforcement of "independent enough."** Two declaring peers are counted as distinct the
  moment their `PeerId`s differ, even if they're operated by the same organization. Weighing
  *how* independent a corroborating peer really is is a later, harder problem (see
  `spec/01-overview.md`'s open questions).

## Tests

`crates/oag-mesh/src/bridge.rs` (10 unit tests): sign/verify round trip, self-reference rejection
(a mesh-group cannot declare itself as its own member), tampered-field/mismatched-key/stale-
timestamp rejection (mirroring the base project's own signed-declaration test shapes), corroboration
counting distinct peers rather than repeated declarations, recursive resolution through nested
mesh-groups down to base-cluster leaves, cycle termination, and minimum-corroboration filtering.
