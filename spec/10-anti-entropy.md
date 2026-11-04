# Pull-Based Anti-Entropy

**Source**: `crates/oag-mesh/src/transport.rs` (`pull_and_merge`, `sync_with_all_peers`,
`/oag-mesh/v1/sync/*`), plus `merge_snapshot` on `bridge::MeshTree`,
`corroboration::ClaimCorroboration`, and `membership::MembershipRegistry`, and `merge` on
`anonymous_event::AnonymousEventLog`.

Every mechanism in this crate (`spec/02`, `spec/03`, `spec/05`, `spec/09`) was, until now,
push-only: `broadcast_bridge_declaration`/`broadcast_anonymous_event`/`broadcast_claim_report`/
`broadcast_membership_attestation` reach only the peers on `MeshState.peers` that happen to be
online *at the moment of that specific broadcast*. A peer offline during a push simply never got
that fact, with nothing to catch it up later — `spec/04-transport.md`'s longest-standing open
question. This file closes that gap with a pull side: fetch a peer's entire current view of a
store and merge it in.

## The mechanism

Four new read endpoints, one per store, each returning that node's **entire** current store as a
snapshot rather than an answer to one query:

- `GET /oag-mesh/v1/sync/bridge-tree` → `Vec<bridge::BridgeEdgeSnapshot>`
- `GET /oag-mesh/v1/sync/claim-corroboration` → `Vec<corroboration::ClaimSnapshot>`
- `GET /oag-mesh/v1/sync/membership-registry` → `Vec<membership::MembershipSnapshot>`
- `GET /oag-mesh/v1/sync/anonymous-events` → `anonymous_event::AnonymousEventLog` (serialized
  directly, same as this store's disk persistence)

`pull_and_merge(state, address)` fetches all four from one peer and merges each into `state`'s
own store via a new `merge_snapshot`/`merge` method on each -- **unioning**, not replacing:
`MeshTree::merge_snapshot` unions each edge's declaring-peer set, `ClaimCorroboration::
merge_snapshot` appends any `(peer_id, reporter_cluster, observed_value_hash)` not already
present for its `claim_id`, `MembershipRegistry::merge_snapshot` unions each `(cluster,
subject_peer_id)`'s attester set, and `AnonymousEventLog::merge` appends any event not already
present (by exact equality) under its nonce. Every one of these is **idempotent** -- merging the
same snapshot twice, or merging snapshots from several different peers that overlap, never
double-counts. `sync_with_all_peers(state)` is the convenience wrapper: pull-and-merge against
every configured peer in turn, best-effort, the pull-side mirror of the `broadcast_*` functions'
push-side fan-out.

Nothing in this crate calls `sync_with_all_peers` on its own -- same "caller decides the
schedule" posture as `MeshState::save_to_dir`. A real deployment would call it on a timer, or on
startup, or both; this crate has no opinion on cadence.

## The trade-off, stated as plainly as every other partial guarantee in this crate

**Pulling is a strictly weaker trust model than pushing, and that is the central thing to
understand about this mechanism.** `receive_bridge_declaration`/`receive_claim_report`/
`receive_membership_attestation`/`receive_anonymous_event` each independently re-verify a
signature (or, for `AnonymousEvent`, structural validity) and proof-of-work on every message that
arrives via push, before recording anything. A snapshot pulled from `/oag-mesh/v1/sync/*` has
already collapsed past that -- `BridgeEdgeSnapshot`/`ClaimSnapshot`/`MembershipSnapshot` carry
bare peer-id strings and aggregated counts, not the original signed `BridgeDeclaration`/
`ClaimReport`/`MembershipAttestation` objects. There is nothing left in a snapshot to
independently re-verify.

Merging a pulled snapshot therefore means trusting that the peer it came from already did its own
verification honestly -- the same trust already placed in every peer on `MeshState.peers`'s
static, operator-configured list (the one that decides who gets pushed to), not a *new* trust
boundary introduced by this feature. But it is a *different* one than push's: a compromised or
malicious peer already on that list could not get an invalid `BridgeDeclaration` recorded by
*pushing* it to you (your own `receive_bridge_declaration` would reject it), but it *could* report
a fabricated edge, claim, membership, or event through `/oag-mesh/v1/sync/*` and have you merge it
in, with no signature left for you to check. Anti-entropy closes an availability gap at the cost
of this new integrity gap for anyone already inside the trusted peer list. Whether that trade is
acceptable depends on how much a real deployment trusts its own configured peer list to begin
with -- this crate takes no position on that, beyond stating the trade-off exists.

## What this explicitly is not (yet)

- **Not incremental.** Every pull fetches a peer's *entire* store, every time -- no "since
  sequence number N" delta sync like the base project's own `oag-sync` `hello`/`heads` protocol
  uses. Fine at this crate's current scale, a real cost once any store grows large.
- **Not scheduled.** `sync_with_all_peers` exists, nothing calls it automatically. A real
  deployment decides its own cadence.
- **Does not re-verify anything.** Stated above, the central caveat: a pull trusts the source
  peer's own verification, it does not re-derive it.
- **No conflict resolution beyond union.** There is no real "conflict" shape in this crate's data
  model (a `HashSet`/append-if-absent merge can't contradict itself), but that's a consequence of
  how simple these stores are, not evidence this would generalize to richer state.

## Tests

`crates/oag-mesh/src/bridge.rs` adds 1 test: `merge_snapshot` unions peer sets rather than
replacing them, and merging the identical snapshot twice doesn't double-count.
`crates/oag-mesh/src/corroboration.rs` adds 1: `merge_snapshot` appends new reports and skips
exact duplicates on a repeated merge. `crates/oag-mesh/src/membership.rs` adds 1: `merge_snapshot`
unions attester sets the same way. `crates/oag-mesh/src/anonymous_event.rs` adds 1: `merge` adds
genuinely new events and skips an exact duplicate, while keeping an unrelated nonce distinct.
`crates/oag-mesh/src/transport.rs` adds 3 integration tests, real axum servers, real HTTP round
trips: `pull_and_merge` brings a node that started completely empty fully up to date across all
four stores in one call, and a second, repeated call doesn't inflate anything (idempotent);
`sync_with_all_peers` pulls from every configured peer and merges both; pulling from an
unreachable address logs a warning and leaves the puller's state untouched rather than panicking
or stopping other stores from being attempted.
