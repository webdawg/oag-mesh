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
- **No anti-amplification protection on the wire.** `/oag-mesh/v1/route-search` has no rate
  limiting, no proof-of-work, no per-requester budget -- same "no auth at all" posture every
  other endpoint in this crate states, but with a sharper consequence here: a caller (or a
  malicious one) can trigger real fan-out network traffic across however many peers and hops it
  asks for, bounded only by `max_hops` and however many peers each node happens to have
  configured. A real deployment exposing this to anything less trusted than its own
  operator-configured peer list would need its own rate limiting; none exists here.
- **No deduplication against results already in flight.** If two different branches both
  eventually find *a* path to the same target, both are collected and compared by length; there's
  no short-circuiting the moment the first result arrives, so a search can do more network work
  than the minimum needed to answer the question.

## Tests

`crates/oag-mesh/src/transport.rs` adds 4 integration tests, real axum servers, real HTTP round
trips: a path already in a node's own local tree is found without any network call at all
(`peers: vec![]`, so this is structurally guaranteed, not just empirically faster); a path known
only by a direct peer is found within one hop; a path known only two hops away (through an
intermediate peer that must itself forward the query onward) is correctly unreachable with
`max_hops = 1` but found with `max_hops = 2`, demonstrating the hop budget actually bounding how
far the search reaches; and the split-knowledge limitation above, demonstrated end to end --
unreachable via distributed search alone, then immediately resolvable via a plain local
`shortest_path` once `spec/10-anti-entropy.md`'s `pull_and_merge` has consolidated both peers'
edges onto the searching node.
