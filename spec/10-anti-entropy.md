# Pull-Based Anti-Entropy

**Source**: `crates/oag-mesh/src/transport.rs` (`pull_and_merge`, `sync_with_all_peers`,
`spawn_periodic_sync`, `/oag-mesh/v1/sync/*`), plus `merge_snapshot` on `bridge::MeshTree`,
`corroboration::ClaimCorroboration`, `membership::MembershipRegistry`, and
`responder::ResponderAcknowledgmentLog`, and `merge` on `anonymous_event::AnonymousEventLog`.

Every mechanism in this crate (`spec/02`, `spec/03`, `spec/05`, `spec/09`, `spec/12`) was, until
now, push-only: `broadcast_bridge_declaration`/`broadcast_anonymous_event`/
`broadcast_claim_report`/`broadcast_membership_attestation`/`broadcast_responder_acknowledgment`
reach only the peers on `MeshState.peers` that happen to be online *at the moment of that
specific broadcast*. A peer offline during a push simply never got that fact, with nothing to
catch it up later — `spec/04-transport.md`'s longest-standing open question. This file closes
that gap with a pull side: fetch a peer's entire current view of a store and merge it in.

## The mechanism

Five read endpoints, one per store, each returning that node's **entire** current store as a
snapshot rather than an answer to one query:

- `GET /oag-mesh/v1/sync/bridge-tree` → `Vec<bridge::BridgeEdgeSnapshot>`
- `GET /oag-mesh/v1/sync/claim-corroboration` → `Vec<corroboration::ClaimSnapshot>`
- `GET /oag-mesh/v1/sync/membership-registry` → `Vec<membership::MembershipSnapshot>`
- `GET /oag-mesh/v1/sync/anonymous-events` → `anonymous_event::AnonymousEventLog` (serialized
  directly, same as this store's disk persistence)
- `GET /oag-mesh/v1/sync/responder-acknowledgments` → `Vec<responder::ResponderAcknowledgmentSnapshot>`

A sixth, cheaper endpoint, `GET /oag-mesh/v1/sync/heads`, returns a `StoreHeads` stamp: a
per-process `instance_id` plus one monotonic sequence per store, bumped whenever that store's
state actually changes. `pull_and_merge` fetches heads first and pulls only the stores whose
sequence changed since its last pull from that peer, instead of all five every time.

**Heads are recorded per store, not for the pull as a whole.** Each store's head is recorded
independently when its own pull succeeds; a failed store keeps its previous version, or
`UNKNOWN_VERSION` if there is none, so `heads_changed` always sees it as different and retries it.

The earlier behaviour recorded the peer's heads only when *every* attempted store succeeded. With
one persistently failing store -- a broken endpoint, a store the peer's version does not serve --
that condition never became true, so no heads were ever recorded and all five stores were re-pulled
in full on every tick, forever, to learn nothing new about the four healthy ones. Asserted by
`a_failing_store_is_retried_without_re_pulling_the_healthy_ones`: the failing store is fetched on
both ticks, the healthy one on the first only.

`link_quality` still records the pull as a whole -- a peer serving four of five stores is asked
later than one serving all five, which is a defensible liveness signal even though the healthy
stores are no longer re-fetched.

`pull_and_merge(state, address)` merges each store into `state`'s
own store via a new `merge_snapshot`/`merge` method on each: `MeshTree::merge_snapshot` **unions**
each edge's declaring-peer set, `ClaimCorroboration::merge_snapshot` appends any `(peer_id,
reporter_cluster, observed_value_hash)` not already present for its `claim_id`,
`MembershipRegistry::merge_snapshot` unions each `(cluster, subject_peer_id)`'s attester set,
`AnonymousEventLog::merge` appends any event not already present (by exact equality) under its
nonce, and `ResponderAcknowledgmentLog::merge_snapshot` keeps whichever of a local and incoming
entry has the more recent `acknowledged_at` per `(corroboration_nonce, responder_peer_id)` pair
(the one store here with a real freshness rule rather than a pure union -- see "What this
explicitly is not" below). Every one of these is **idempotent** -- merging the same snapshot
twice, or merging snapshots from several different peers that overlap, never double-counts or
regresses state. `sync_with_all_peers(state)` is the convenience wrapper: pull-and-merge against
every configured peer in turn, best-effort, the pull-side mirror of the `broadcast_*` functions'
push-side fan-out.

`sync_with_all_peers` pulls **best-quality first**, ordering its peers by the `link_quality`
ledger (`spec/13`) before pulling any of them. The loop is sequential, so the order decides whether
the live peers' data arrives before the dead peers' timeouts are paid: pulling in configuration
order means every dead peer is waited out before a single live one is reached. Ordering only --
every configured peer is still pulled, exactly as before.

Nothing in this crate calls `sync_with_all_peers` *by default* -- same "caller decides" posture
as `MeshState::save_to_dir`. `spawn_periodic_sync(state, interval)` is the opt-in: it spawns a
background task that calls `sync_with_all_peers` once immediately, then again every `interval`,
forever, until the returned `tokio::task::JoinHandle` is aborted or dropped (with the runtime
shutting down). A caller still has to call this function and still picks its own `interval` --
nothing here decides a cadence on anyone's behalf, it just removes the need to hand-write the
loop.

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

- **Not a delta sync, but no longer a full pull every time.** `GET /oag-mesh/v1/sync/heads`
  returns a per-store version stamp, and `pull_and_merge` pulls only the stores whose stamp
  changed since its last pull from that peer -- the cheap "who's changed" check the base
  project's `oag-sync` `hello`/`heads` protocol uses. When a store *has* changed, the pull
  still fetches that store's entire current snapshot, not a delta of what changed; a store that
  hasn't changed costs one small heads response instead of a full snapshot. A peer that restarts
  gets a new `instance_id`, so a puller never mistakes its reloaded state for unchanged.
  `spawn_periodic_sync` still re-fetches a changed store's whole contents on a short interval --
  the convenience of scheduling and the cost of whole-store pulls compound.
- **Scheduling now exists (`spawn_periodic_sync`), but it's still an explicit opt-in with no
  default cadence.** Nothing constructs a `MeshState` and starts syncing on its own; a caller
  calls `spawn_periodic_sync` and picks an `interval` appropriate to its own deployment. No
  adaptive interval, no cross-node coordination, and no backoff remain; jitter now exists as
  `spawn_periodic_sync_with_jitter`, which adds a random phase of up to a caller-chosen
  `max_jitter` per tick so nodes that start together don't pull from each other at the same
  wall-clock moment forever. `spawn_periodic_sync` keeps the old fixed-interval behavior, and
  `max_jitter = 0` is exactly that. The jitter is drawn from a per-process random seed, not a
  cryptographic RNG -- it only has to desynchronize independent nodes, not resist an adversary,
  and a restart re-randomizes the phase.

  **A tick is bounded too.** Each pull is bounded (`HTTP_CONNECT_TIMEOUT` +
  `HTTP_REQUEST_TIMEOUT`), but a tick is a loop over every peer, so three unreachable peers cost
  three times the per-peer worst case -- and a pull against a black-holed peer costs the heads
  request *plus* the five-store fallback, six timeouts in all. `link_quality` asks the live peers
  first, so their data arrives early, but the live peers' next refresh waits for the dead ones to
  be waited out. `sync_with_all_peers_bounded` (and `spawn_periodic_sync_with_budget`) caps the
  tick: the budget is checked between pulls, so the pull in flight completes and the rest are
  left for the next tick. This bounds the tick rather than dropping anyone -- the skipped peers
  are retried, so "a peer that is down is asked last, never not asked" still holds. The
  unbounded forms remain for a caller that would rather wait out every peer.
- **Does not re-verify anything.** Stated above, the central caveat: a pull trusts the source
  peer's own verification, it does not re-derive it.
- **Mostly no conflict resolution beyond union -- `ResponderAcknowledgmentLog` is the one
  exception.** Four of these five stores have no real "conflict" shape (a `HashSet`/
  append-if-absent merge can't contradict itself). `ResponderAcknowledgmentLog` does: an
  `active: true` and a later `active: false` for the same responder *are* a real conflict, and
  `merge_snapshot` resolves it by `acknowledged_at` recency, not union -- see
  `spec/12-responder-acknowledgment.md`. That this crate's stores are simple enough that union
  resolves nearly all of them is a consequence of how little state each one tracks, not evidence
  this approach would generalize to richer state.

## Tests

`crates/oag-mesh/src/bridge.rs` adds 1 test: `merge_snapshot` unions peer sets rather than
replacing them, and merging the identical snapshot twice doesn't double-count.
`crates/oag-mesh/src/corroboration.rs` adds 1: `merge_snapshot` appends new reports and skips
exact duplicates on a repeated merge. `crates/oag-mesh/src/membership.rs` adds 1: `merge_snapshot`
unions attester sets the same way. `crates/oag-mesh/src/anonymous_event.rs` adds 1: `merge` adds
genuinely new events and skips an exact duplicate, while keeping an unrelated nonce distinct.
`crates/oag-mesh/src/responder.rs` adds 1: `merge_snapshot` keeps whichever of a local and
incoming entry is more recent per responder, in both directions (see `spec/12`'s own tests for
the rest of that mechanism). `crates/oag-mesh/src/transport.rs` adds 13 tests, real axum
servers, real HTTP round trips: `pull_and_merge` brings a node that started completely empty
fully up to date across all five stores in one call, and a second, repeated call doesn't inflate
anything (idempotent); `sync_with_all_peers` pulls from every configured peer and merges both;
pulling from an unreachable address logs a warning and leaves the puller's state untouched rather
than panicking or stopping other stores from being attempted; `spawn_periodic_sync` picks up data
that's added to a peer only *after* the schedule already started, across real wall-clock ticks
(not just a single pull at spawn time); aborting the returned handle actually stops further
syncing -- data added to a peer after the abort never reaches the catcher even after waiting
long enough that further ticks would otherwise have occurred; `spawn_periodic_sync_with_jitter`
still syncs across real wall-clock ticks with a random phase; two unit tests pin the jitter
helper's bounds (always below the maximum, and zero when the maximum is zero); the heads
endpoint reports a per-store sequence and a nonzero instance id after a store changes; a
second pull with no source changes is a no-op; a change to one store is picked up on the next
pull; and two unit tests pin `heads_changed`'s logic (a new peer is fully pulled; a changed
store is pulled while unchanged stores are skipped; a restarted peer's new instance id forces
a full pull).
