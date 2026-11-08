# oag-mesh — Specification

One file per feature, same convention as the base project
(`github.com/webdawg/open-agent-graph`'s `spec/README.md`) — what each part does, what it
guarantees, and what's deliberately not built yet. Numbering here is independent of that
repository's `spec/NN`; don't cross-reference by number between the two, only by name/URL.

## Index

| File | Feature |
|---|---|
| [01-overview.md](01-overview.md) | Scope, relationship to the base project, and what this layer is not |
| [02-cluster-nesting.md](02-cluster-nesting.md) | Signed bridge declarations placing a base-layer cluster (or another mesh-group) into a mesh-group, recursively, with corroboration by distinct-peer count |
| [03-anonymous-event-rfc.md](03-anonymous-event-rfc.md) | Identity-stripped event reports ("SAW THIS EVENT") for life-saving actions — strict schema, coarse location/time, corroboration without identity |
| [04-transport.md](04-transport.md) | A real HTTP transport for all four mechanisms, on its own layer/port, with both push and pull — explicit that it gives `AnonymousEvent` submission no network-level anonymity on top of its already-anonymous payload |
| [05-federated-corroboration.md](05-federated-corroboration.md) | Signed claim reports, weighted by distinct self-asserted cluster rather than distinct peer — generalizes the base project's gateway quorum fan-out across organizational boundaries |
| [08-persistence.md](08-persistence.md) | One JSON file per in-memory store, written/read on demand — not automatic, not atomic, not a database |
| [09-cluster-membership-attestation.md](09-cluster-membership-attestation.md) | Signed attestations that a peer is a genuine member of a cluster, corroborated by distinct attester count — closes the "is the reporter really in that cluster" half of `05`'s cross-check that `02` alone couldn't |
| [10-anti-entropy.md](10-anti-entropy.md) | Pull-based catch-up for all four stores — fetch a peer's whole snapshot and merge it in, closing the "offline during a broadcast" gap push-only transport left open, at the cost of a weaker (unverified) trust model than push |
| [11-responder-search.md](11-responder-search.md) | Filterable search over a node's own `AnonymousEvent` log (kind, minimum severity, location prefix, recency) — the one narrow slice of "reaching a responder" this crate answers; explicitly not dispatch or notification |
| [12-responder-acknowledgment.md](12-responder-acknowledgment.md) | A signed, identity-bearing claim that a responder is handling an event — advisory, not a lock; no proof-of-work (there's no corroboration count to protect); the first mechanism here to carry a real `PeerIdentity` on the responder side while the reporter side stays anonymous |
| [13-distributed-route-search.md](13-distributed-route-search.md) | Finding a path across the mesh by asking peer after peer when one node's own knowledge isn't enough — bounded strictly by a hop budget, not by perfect deduplication; cannot stitch together knowledge split across multiple peers (that needs `10`'s anti-entropy first) |
| [14-responder-dispatch.md](14-responder-dispatch.md) | Blinded responder subscriptions and a poll inbox — the narrowest slice of "reaching a responder": the node never learns which `PeerIdentity` stands behind a subscription |

## Proposed research-data extension (not implemented)

| File | Proposal |
|---|---|
| [06-owner-controlled-cancer-research-data-rfc.md](06-owner-controlled-cancer-research-data-rfc.md) | Voluntary small-data collection for cancer research; the person the data concerns is its creator/owner; public dedication or encrypted vault storage with owner-selected scheduled release |

This proposal is separate from anonymous emergency reports and does not add personal health
or genetic records to `AnonymousEvent`.

## Proposed object-history and audit extension (not implemented)

| File | Proposal |
|---|---|
| [07-object-history-and-ownership-rfc.md](07-object-history-and-ownership-rfc.md) | Global object IDs and histories, ownership-gated exchange, data partnerships, documentary/distributed storage, and gated audits of movements and data correctness |

## Founding context

See the base repository's `USER_INPUT_RECORD.md` Entry 24 (the verified-internet-gateway request)
and Entry 25 (this layer's request, and why it was scoped down before any code was written) for
the founding exchange this repository continues from.
