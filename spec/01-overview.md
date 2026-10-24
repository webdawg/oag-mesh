# Overview

**Status: cluster nesting (`spec/02-cluster-nesting.md`), the anonymous-event schema
(`spec/03-anonymous-event-rfc.md`), and a real HTTP transport for both (`spec/04-transport.md`)
are implemented. Federated corroboration across clusters (mechanism 2 below) is not yet built.**

## What this layer is

Two related mechanisms, one level above a single `oag` peer or peer cluster:

1. **Clusters within clusters, implemented — see `spec/02-cluster-nesting.md`.** The base
   project's peer clustering (`spec/26-peer-clustering.md` there) gives a peer exactly one flat
   cluster name, by design, in its first version. Rather than lifting that constraint inside the
   base project's own `oag-sync` (changing working code to fit a new, separate layer's needs),
   nesting is implemented entirely in *this* repository instead: a peer signs a
   `BridgeDeclaration` placing a base-layer cluster name — or another mesh-group, recursively —
   into a named mesh-group, under this crate's own domain-separated message format. The base
   project is completely untouched; a `[cluster].name` keeps meaning exactly what it already
   means there. Two base clusters nested under the same mesh-group stay distinct federation
   domains; nesting is a fact tracked here, not a change to how the base project's own
   `FederationPolicy`/trust configuration works for either cluster's members.
2. **Federated corroboration.** Multiple independently-operated nodes (potentially across
   different clusters/organizations) receive or fetch the *same* claim, content, or gateway
   answer, each through its own path. Comparing what they each independently got — do the content
   hashes agree? — is a verification signal: agreement across independent paths is corroboration;
   disagreement localizes which path (or which node on it) diverged. This is the witness/audit
   mechanism named in the base project's `spec/22-future-work.md` and its
   `future_flood_propagation_and_anonymity.md`/`future_service_announcements_and_audit.md` memory
   entries, and the mechanism `spec/32-verified-internet-gateway.md`'s own quorum fan-out already
   implements for one peer's gateway queries — this layer is the same idea generalized across
   organizational/cluster boundaries instead of one peer's own configured query_peers. Not yet
   built.
3. **Anonymous event reporting for life-saving actions, schema implemented — see
   `spec/03-anonymous-event-rfc.md`.** A deliberately different, identity-*stripped* mechanism
   from (1) and (2) above, which are both signed-identity-based: an `AnonymousEvent` ("SAW THIS
   EVENT" — a sighting, a hazard, a medical emergency, a resource need) carries no persistent
   signature, no precise location or time, and no free-text field that could smuggle an
   identifying description of a person. Corroboration here means independent reports converging
   on the same `corroboration_nonce`, not counting distinct signing peers.

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

- Whether corroboration findings (agreement/disagreement across paths) get written back into the
  base project's evidence/corroboration model, or live entirely in this layer's own storage.
- What counts as "independent enough" paths for corroboration to mean anything (two nodes
  operated by the same organization corroborating each other proves less than two genuinely
  separate ones) — applies to both mechanism (2) and the anonymous-event mechanism (3).
- A real HTTP transport exists now for both mechanisms (`spec/04-transport.md`), push-only with
  no pull-based anti-entropy, and explicit that it does not give `AnonymousEvent` submissions any
  network-level anonymity on top of their already-anonymous payload. See `spec/02`'s, `spec/03`'s,
  and `spec/04`'s own "open questions" sections for what's still unresolved there (anonymous
  events still have no anti-spam/sybil-resistance design).
