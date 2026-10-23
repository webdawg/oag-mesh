# Overview

**Status: design only, nothing implemented yet.**

## What this layer is

Two related mechanisms, one level above a single `oag` peer or peer cluster:

1. **Bridge nodes between clusters.** The base project's peer clustering
   (`spec/26-peer-clustering.md` there) is deliberately one-cluster-per-peer in its first version
   — a peer declares membership in exactly one cluster, gets a full federation-trust bypass with
   that cluster's other members, and nothing else. This layer's first piece lifts that constraint:
   a peer may belong to more than one cluster at once, making it a *bridge* — "a group of these
   each connected by at least, and at minimum, one node," in the words that started this design.
   Two clusters stay distinct groups; they are connected *through* whichever peer(s) are members
   of both, not silently merged into one combined trust domain. Membership bridging is a
   networking/federation-policy fact, the same as clustering itself already is — it does not by
   itself make every member of cluster A trust every member of cluster B; that still depends on
   each receiving peer's own `FederationPolicy`/trust configuration, exactly as it does today.
2. **Federated corroboration.** Multiple independently-operated nodes (potentially across
   different clusters/organizations) receive or fetch the *same* claim, content, or gateway
   answer, each through its own path. Comparing what they each independently got — do the content
   hashes agree? — is a verification signal: agreement across independent paths is corroboration;
   disagreement localizes which path (or which node on it) diverged. This is the witness/audit
   mechanism named in the base project's `spec/22-future-work.md` and its
   `future_flood_propagation_and_anonymity.md`/`future_service_announcements_and_audit.md` memory
   entries, and the mechanism `spec/32-verified-internet-gateway.md`'s own quorum fan-out already
   implements for one peer's gateway queries — this layer is the same idea generalized across
   organizational/cluster boundaries instead of one peer's own configured query_peers.

## What this layer explicitly is not

- **Not a tool for monitoring individuals, communications, or populations.** The data being
  corroborated is a claim or content a peer already holds or fetched — the same evidence-backed,
  non-authoritative model the base project's whole graph is built on — not a feed of information
  *about* a person or group. A request to build this layer as mass-surveillance infrastructure
  ("global cluster surveillance," multiple organizations monitoring and redacting shared data
  streams) was made and explicitly declined before this repository existed — see the base
  repository's `USER_INPUT_RECORD.md` Entry 25 for the verbatim exchange. This boundary is a
  condition of this repository's existence, not a footnote.
- **Not a trust merger.** Cluster A and cluster B stay separate federation domains even after a
  bridge peer connects them. No change here makes a non-bridge member of A automatically trust a
  non-bridge member of B.
- **Not yet a video streaming protocol.** Raised in the same conversation as this layer, but
  independent of it — if built, it's a new `GatewayService` variant in the base project's
  `spec/32-verified-internet-gateway.md`, not part of this repository.

## Open design questions (not yet resolved)

- Exact schema/wire-format change needed in the base project's `oag-sync` to support more than one
  cluster membership per peer (today: `ClusterDeclaration.cluster: String`, `SyncService.
  own_cluster: Option<String>`, and `peer_cluster_claims` storage are all single-valued) — this is
  a change to that repository, not this one, and needs to land there first or alongside this
  layer's own client code.
- Whether corroboration findings (agreement/disagreement across paths) get written back into the
  base project's evidence/corroboration model, or live entirely in this layer's own storage.
- What counts as "independent enough" paths for corroboration to mean anything (two nodes
  operated by the same organization corroborating each other proves less than two genuinely
  separate ones).
