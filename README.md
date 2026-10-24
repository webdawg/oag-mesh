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

## Scope — what this is, and what it explicitly is not

This layer connects clusters and corroborates *data/claims* (content a peer crawled, evidence it
holds, a value a gateway resolved) across organizational boundaries — the same evidence-backed,
non-authoritative claim model the base project already uses, extended across cluster lines. It is
**not** a tool for monitoring individuals, communications, or populations, and that boundary is
load-bearing, not incidental: see `USER_INPUT_RECORD.md` Entry 25 in the base repository for the
exact exchange that drew this line, and why a request to build this layer as mass-surveillance
infrastructure was declined before this repository existed.

## Status

Cluster nesting (`spec/02-cluster-nesting.md`), the anonymous-event RFC schema with escalating
proof-of-work anti-spam/anti-replay protection (`spec/03-anonymous-event-rfc.md`), and a real HTTP
transport for both (`spec/04-transport.md`) are implemented. Federated corroboration across
clusters (mechanism 2 in `spec/01-overview.md`) is not. See
`spec/01-overview.md`.
