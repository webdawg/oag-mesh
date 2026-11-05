# oag-mesh

The cluster-bridging / federated-trust layer one level above a single Open Agent Graph peer or
peer cluster.

**Base project**: [`github.com/webdawg/open-agent-graph`](https://github.com/webdawg/open-agent-graph)
(`oag`) — a single peer's signed event graph, replication, peer clustering
(`spec/26-peer-clustering.md` there), and the verified internet gateway
(`spec/32-verified-internet-gateway.md` there). This repository builds the next layer up: bridging
multiple peer clusters together, and the federated corroboration mechanism — multiple independent
nodes passing/verifying the same claim or content, so disagreement between them is detectable —
that `oag`'s own `spec/22-future-work.md` already named and deliberately left unbuilt.

## Why a separate repository

- **Separate concern, separate lifecycle.** This layer coordinates *across* clusters of `oag`
  peers; it is not itself a change to how one peer or one cluster works internally.
- **Separate spec numbering.** `spec/` here starts fresh at `01` — see `spec/README.md`. It is not
  a continuation of the base project's `spec/NN-name.md` sequence, to avoid implying this is part
  of that repository's own feature set.
- **Reuses, doesn't fork.** `oag-core`/`oag-crypto` (identifiers, canonical JSON, Ed25519
  signing-with-domain-separation) are pulled in via a git dependency on the base repository rather
  than vendored or reimplemented — a signature produced here verifies the same way a base-project
  peer's does.

## Founding principle: bounded-hop reachability

> "there are only so many degrees of seperation, go in any direction and get there"
> — the user, stating directly the idea this layer's cluster-nesting graph exists to serve

> "you can route faster in any direction - you search for the host moving forward through random
> clusters of nodes - their are only so many degrees of seperation"
> — the user, expanding the same principle into how search/routing should actually behave

Interpreted concretely, in two parts matching the two quotes above:

**Any direction.** Wherever you start in the mesh — a base cluster, a mesh-group, a peer's own
local view of it — there should be a short, findable chain of real `BridgeDeclaration`s to
anywhere else in it, and that chain has to be walkable in *any* direction, not just the one a
`BridgeDeclaration` happens to be worded in. "`member` belongs to `mesh_group`" is a directional
*claim*; for routing purposes the edge it describes is not one-way. `bridge::MeshTree::
shortest_path`/`degrees_of_separation` (`spec/02-cluster-nesting.md`) make this literal and
queryable from one node's own knowledge: breadth-first search over every
sufficiently-corroborated edge, going "down" into a mesh-group's members or "up" out of a
cluster to whatever contains it with equal ease.

**Moving forward through random clusters of nodes.** One node's own knowledge is not the whole
mesh's knowledge. `find_route_across_mesh` (`spec/13-distributed-route-search.md`) is what
"search for the host" becomes concretely: when a node's own local `shortest_path` can't answer,
it asks its peers the identical question, who ask theirs, moving the search outward through
cluster after cluster rather than stopping at the edge of one node's own view. "Only so many
degrees of separation" is the literal hop budget (`max_hops`) bounding that search -- the reason
it's guaranteed to terminate rather than flood the mesh forever, exactly the same idea
`degrees_of_separation` already named for a single node's local data, now applied to the search
itself.

Both are stated as **design goals for how the mesh behaves, not guarantees the protocol
enforces** — the same honesty-over-overclaiming posture every other mechanism in this repository
holds to. If two clusters are never bridged at all, or only through a long, sparse chain,
`degrees_of_separation` says so plainly (a large hop count, or `None` if genuinely unreachable)
rather than pretending otherwise. And `find_route_across_mesh` has a real, demonstrated limit of
its own: it cannot stitch together a path whose two halves are known only by two *different*
peers that haven't already consolidated their knowledge (`spec/10-anti-entropy.md`'s
pull-based sync) — each hop's answer comes from one node's own complete local view, never
several nodes' partial views combined on the fly. What both mechanisms guarantee is that the
question has a real, computable answer from whatever `BridgeDeclaration` data the mesh has
actually propagated to wherever the search reaches — not that the mesh will stay small, or
fully-known to any one node, on its own; that's still up to whoever's doing the bridging and the
syncing.

## Scope — what this is, and what it explicitly is not

This layer connects clusters and corroborates *data/claims* (content a peer crawled, evidence it
holds, a value a gateway resolved) across organizational boundaries — the same evidence-backed,
non-authoritative claim model the base project already uses, extended across cluster lines. It is
**not** a tool for monitoring individuals, communications, or populations, and that boundary is
load-bearing, not incidental: see `USER_INPUT_RECORD.md` Entry 25 in the base repository for the
exact exchange that drew this line, and why a request to build this layer as mass-surveillance
infrastructure was declined before this repository existed.

## Proposed research-data extension

[Owner-controlled cancer research data RFC](spec/06-owner-controlled-cancer-research-data-rfc.md)
records a proposed, **not implemented**, opt-in mechanism for small environmental, lifestyle,
and genetic observations. The person the data concerns is its creator and owner, choosing
public research dedication, private encrypted vault storage, or release at an owner-selected
date/time. This is separate from anonymous emergency messaging, not permission for passive
population monitoring. No collector, health-data vault, or scheduled-release service exists yet.

## Proposed object-history and audit extension

[Object identity, ownership-gated exchange, and gated auditability](spec/07-object-history-and-ownership-rfc.md)
is a **not implemented** protocol direction for globally addressable histories of houses,
cars, marbles, rocks, and other objects. It covers proof of ownership, renewable data
partnerships, documentary/distributed storage, and evidence-based audits of movements and
record correctness. Global coverage does not grant unrestricted access or authorize tracking people.

## Status

Six mechanisms are implemented: cluster nesting with its own escalating proof-of-work
anti-sybil protection (`spec/02-cluster-nesting.md`), the anonymous-event RFC schema with
escalating proof-of-work anti-spam/anti-replay protection (`spec/03-anonymous-event-rfc.md`),
federated corroboration weighted by distinct cluster rather than distinct peer, also with its own
escalating proof-of-work anti-sybil protection (`spec/05-federated-corroboration.md`), cluster
membership attestation — signed proof that a peer is a genuine member of a cluster, corroborated
by distinct attester count, with the same escalating proof-of-work treatment
(`spec/09-cluster-membership-attestation.md`) — and responder acknowledgment — a signed,
identity-bearing (unlike the reporter side) claim that a responder is handling an event,
advisory only, deliberately carrying no proof-of-work
(`spec/12-responder-acknowledgment.md`) — all five over a real HTTP transport
(`spec/04-transport.md`), both pushed to configured peers and pullable later by one that
missed a broadcast, optionally on an opt-in schedule (`spawn_periodic_sync`,
`spec/10-anti-entropy.md`), and manual (not automatic, not crash-safe) disk
persistence for all five stores (`spec/08-persistence.md`). A `ClaimReport`'s self-asserted
cluster can be cross-checked against real cluster-nesting data alone
(`best_corroborated_value_cross_checked`, `GET .../best-cross-checked`) — confirming the claimed
cluster *name* was really attested by a `BridgeDeclaration` — or against that **and** real
membership-attestation data (`best_corroborated_value_fully_cross_checked`,
`GET .../best-fully-cross-checked`) — additionally confirming the reporting peer actually belongs
to that cluster, not just that the name is real. A node's own anonymous-event log can also be
searched/filtered by kind, minimum severity, location prefix, or recency
(`spec/11-responder-search.md`), and a responder can acknowledge an event so another checking
first can stand down (`spec/12-responder-acknowledgment.md`) — two narrow, explicitly-bounded
slices of "reaching a responder," neither of them dispatch, notification, or a guarantee that a
claimed response is real. A sixth mechanism, distributed route search
(`spec/13-distributed-route-search.md`), extends cluster nesting's own `shortest_path` across
the network: `find_route_across_mesh` asks peer after peer, bounded by a hop budget, when one
node's local knowledge isn't enough — the concrete realization of this repository's own founding
principle, above. Still open: verifying that distinct `PeerIdentity`s are genuinely
different organizations rather than just different keys (proof-of-work taxes cost, not
identity, all the way down — even an attester's own standing in a cluster is itself unverified),
a bad-faith responder falsely claiming to handle events (proof-of-work wouldn't help here
either — see `spec/12`), full dispatch-to-a-responder, pull-based anti-entropy's own stated
trade-off — it trusts a peer's prior verification instead of re-checking a signature, a weaker
guarantee than push — and distributed route search's own amplification cost and inability to
stitch together knowledge split across peers who haven't already synced. See
`spec/01-overview.md`.
