# Distributed Route Search

**Source**: `crates/oag-mesh/src/transport.rs` (`find_route_across_mesh`, `search_for_route`,
`push_route_search`, `/oag-mesh/v1/route-search`), plus `bridge::MeshTree::shortest_path`
(`spec/02-cluster-nesting.md`'s "Bidirectional traversal").

This is the second concrete mechanism answering the founding principle quoted directly, and
expanded, in the top-level `README.md`'s "Founding principle: bounded-hop reachability" section.
Where `MeshTree::shortest_path` answers "how do I get from A to B" from one node's own local
knowledge, this file answers it when that single node's knowledge isn't enough on its own, by
asking the mesh: forwarding the same question outward, through peer after peer, until someone
can answer or the hop budget runs out.

## The mechanism

`find_route_across_mesh(state, from, target, min_corroboration, max_hops)`:

1. Check this node's own local `bridge::MeshTree::shortest_path(from, target,
   min_corroboration)` first -- free, no network. If it already has enough edges, return
   immediately.
2. Otherwise, if `max_hops` is still above `0`, send the identical question (`from`, `target`,
   `min_corroboration`, `max_hops - 1`) to every peer on `state.peers` not already asked earlier
   in *this* search, in parallel, over `POST /oag-mesh/v1/route-search`.
3. Each peer runs the exact same two steps against its own state -- `receive_route_search` calls
   the identical `search_for_route` function `find_route_across_mesh` itself calls, which is what
   makes this genuinely distributed rather than one node doing all the work: every hop re-checks
   local knowledge first, and only forwards further if it has to.
4. Collect whatever paths come back from peers asked in step 2, and return the shortest one, if
   any.

`RouteSearchRequest { from, target, min_corroboration, remaining_hops, already_asked }` is the
wire shape; `already_asked` carries forward every peer address already contacted *in this
specific search* as it fans out, so the same peer isn't asked twice via two different branches
of the same hop. This is a redundancy reducer, not what actually bounds the search -- see below.

## What actually guarantees this terminates

**`remaining_hops` reaching `0`, nothing else.** `already_asked` only prevents a search from
immediately re-asking a peer it already just contacted on the current path through the fan-out;
it does **not** guarantee a given node is visited at most once across the *whole* search tree --
two different branches of the fan-out, started from two different intermediate nodes, can each
independently decide to ask the same downstream peer, with two different `already_asked`
histories neither one aware of the other. That's a real, accepted redundancy cost (and, at scale,
a real amplification concern: this can issue `O(branching_factor^hops)` requests in the worst
case), traded for not needing a perfect, globally-coordinated "who's already been asked" ledger.
`max_hops` is the one hard ceiling: once `remaining_hops` hits `0` on any branch, that branch
stops, full stop, which is the literal mechanism behind "there are only so many degrees of
separation" -- the search cannot run forever no matter how the peer graph is shaped.

## Anti-amplification

Two independent bounds, both stated plainly rather than oversold:

1. **A per-search fan-out budget.** `RouteSearchRequest` carries `fanout_budget`, the total
   number of outbound `route-search` requests this search may trigger across its whole fan-out
   tree. A node spends one unit per peer it asks and divides what remains among those peers, so
   the sum of all outbound requests a single search can cause is bounded by the budget it started
   with -- no matter how the branches split. `find_route_across_mesh` uses
   `DEFAULT_ROUTE_SEARCH_FANOUT_BUDGET` (256); `find_route_across_mesh_with_budget` lets a
   caller set its own, and `0` disables forwarding entirely (local knowledge only). This is a
   real bound on the `O(branching_factor^hops)` worst case, not a probabilistic one. It is also
   a trade-off: a small budget can stop a search before it reaches an answer that a larger
   budget would have found, and that is stated here rather than hidden.
2. **A node-wide token bucket on inbound requests.** `receive_route_search` refuses requests
   with `429` and a `Retry-After` header once the bucket is empty
   (`ROUTE_SEARCH_RATE_LIMIT_CAPACITY` requests, refilling at
   `ROUTE_SEARCH_RATE_LIMIT_PER_SEC` per second). It is node-wide, not per-requester: this
   transport has no requester identity, so it cannot tell one caller from another. A single
   caller can still exhaust the bucket and starve others; a real deployment that needs
   per-requester limits would have to add requester identity first. The bucket is in-memory
   only, so a restart resets it.

Neither is a substitute for not exposing the endpoint to untrusted callers. Both only raise the
cost of triggering fan-out; they do not authenticate anyone.

## Ordering the fan-out by observed deliverability

The fan-out budget is the scarce resource here: a search that spends its one allowed request on a
peer that has been refusing connections for hours learns nothing. `link_quality` records whether
each interaction actually delivered -- a route-search reply, or a completed `pull_and_merge` -- and
the search asks its peers best-first.

**It orders; it never excludes.** A peer at score `0.0` is asked *last*, not dropped. This is the
standing "degrade, don't drop" decision applied to connectivity: a peer that is down today may be
the only path tomorrow, and nothing here gives this node a reason to forget an address its
operator configured. The guarantee is a property of the ordering function -- it is a permutation
of the input, tested as such -- not a convention.

The score is an exponential moving average of the 1.0/0.0 outcome, with the same learning rate as
the base project's tensor pad (`0.1`). That value is deliberately conservative: a single dropped
packet moves a healthy peer's score by one tenth of the gap to the observation, so routing does not
oscillate, while a peer that fails consistently is demoted within a handful of rounds. A peer this
node has never interacted with scores `0.5` -- neutral, not optimistic -- so a node with no
history yet spreads its fan-out across everyone rather than preferring whichever address was
configured first.

Outcomes are recorded on **both** sides of every interaction: a peer that did not answer is
exactly the observation the next search needs, and it is invisible if only successes are counted.
`pull_and_merge` returns whether the interaction delivered, which is the distinction the fan-out
budget is spent on.

**In-memory only.** A restart forgets every peer's quality and re-learns it within a few rounds.
That is consistent with this crate's posture on its other limiter state (`route_search_limiter`,
`responder_ack_limiter`): losing it costs a little wasted fan-out, not anything irrecoverable. It
also avoids adding an eighth persisted store, which would change the commit-marker set
(`spec/08-persistence.md`) for a value that is by nature ephemeral.

**This is a liveness signal, not a trust signal.** A peer that replies with garbage scores exactly
as well as one that replies correctly. Honesty is `spec/05`'s corroboration layer's job, and
nothing here should be read as a reputation system.

### Measured

`a_failed_fan_out_is_recorded_and_the_next_search_spends_its_budget_better` is a real network
measurement, not a unit test of the ordering function: a node configured with `[dead, live]`, a
fan-out budget of one, and no history spends its only slot on the dead peer and fails; the *next*
search, same budget, puts the now-proven live peer first and succeeds. The adaptation is
observable in behaviour, and it happens after a single observation.

## What this explicitly is not

- **Not a global shortest path, even when it finds one.** A path this returns is real --every
  edge on it is a genuinely verified `BridgeDeclaration` somewhere in the mesh, the same
  guarantee any `shortest_path` result carries -- but it is only the shortest path *this specific
  search happened to find* within `max_hops`, which depends on which peers answered and in what
  order their responses arrived back. A different `max_hops`, a different moment, or a
  differently-populated `already_asked` could find a different (possibly shorter, possibly
  longer) path, or none at all. `None` means "not found within this search's hop budget," never
  "proven not to exist anywhere in the mesh."
- **Cannot stitch together knowledge split across multiple peers.** This is the single most
  important limitation, demonstrated directly by a test rather than left to theory: if peer B
  knows "global contains north-america" and peer C separately knows "north-america contains
  ny-dc1," but *neither* B nor C has pulled the other's declaration into its own local
  `MeshTree` (e.g. via `spec/10-anti-entropy.md`'s `pull_and_merge`), this search asks B "do you
  know a path from global to ny-dc1" and gets `None`, asks C the same and also gets `None` --
  each one's own local `shortest_path` genuinely doesn't have enough edges to answer, even though
  the *union* of what B and C each know describes a real, complete two-hop path. Running
  anti-entropy first (so one node's local tree actually contains both edges) turns this into an
  ordinary local `shortest_path` call that succeeds immediately -- the fix is consolidation, not
  a smarter distributed search, and this mechanism does not attempt the latter.
- **Anti-amplification now exists, but it is a cost bound, not an authentication mechanism.**
  See "Anti-amplification" above: a per-search fan-out budget caps the total outbound requests a
  single search can cause, and a node-wide token bucket rate-limits inbound requests. Neither
  verifies who is asking, and the token bucket is node-wide because the transport has no
  requester identity. A real deployment exposing this to anything less trusted than its own
  operator-configured peer list still needs its own authentication and per-requester limits.
- **No general deduplication against results already in flight.** If two different branches
  both eventually find *a* path to the same target, both are collected and compared by length.
  The one exception is a direct edge: a two-member path is the shortest possible for distinct
  `from`/`target`, so the fan-out stops as soon as one arrives rather than waiting for every
  peer -- the "shortest among those found" guarantee is preserved because a direct edge is the
  global minimum. A broader short-circuit-on-first-result would trade that guarantee for less
  work, and that trade is not made here.

## Tests

`crates/oag-mesh/src/transport.rs` adds 7 integration tests, real axum servers, real HTTP round
trips: a path already in a node's own local tree is found without any network call at all
(`peers: vec![]`, so this is structurally guaranteed, not just empirically faster); a path known
only by a direct peer is found within one hop; a path known only two hops away (through an
intermediate peer that must itself forward the query onward) is correctly unreachable with
`max_hops = 1` but found with `max_hops = 2`, demonstrating the hop budget actually bounding how
far the search reaches; the split-knowledge limitation above, demonstrated end to end --
unreachable via distributed search alone, then immediately resolvable via a plain local
`shortest_path` once `spec/10-anti-entropy.md`'s `pull_and_merge` has consolidated both peers'
edges onto the searching node; a zero fan-out budget makes no network call at all even when a
direct peer knows the path; a fan-out budget of 1 cannot cross a two-hop chain while a budget of
2 can, demonstrating the budget being divided among hops; and the inbound rate limiter rejects
a burst with `429`/`Retry-After` and recovers after the bucket refills.
`crates/oag-mesh/src/rate_limit.rs` adds 4 unit tests for the token bucket itself: capacity,
refill at the configured rate, the reported wait when empty, and never exceeding capacity.
`crates/oag-mesh/src/link_quality.rs` adds 6 unit tests for the ledger: an unseen peer is neutral
rather than zero; a consistently-dead peer sorts last and a consistently-healthy one first; the
ordering is a permutation that never drops an address, asserted as a property; the score is
smoothed rather than a raw ratio; a recovered peer climbs back above an unknown one; and with a
budget of one the proven peer is the one asked.
