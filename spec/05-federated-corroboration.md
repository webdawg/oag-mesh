# Federated Corroboration

**Source**: `crates/oag-mesh/src/corroboration.rs`, `crates/oag-mesh/src/transport.rs` (`/oag-mesh/v1/claim-report*`).

Generalizes the base project's `spec/32-verified-internet-gateway.md` quorum fan-out -- one peer
comparing answers from its own configured `query_peers` -- across organizational/cluster
boundaries instead: here the question is "did enough *independent organizations* agree," not
"did enough of my own configured peers agree." This is `spec/01-overview.md`'s mechanism (2),
and the base project's own still-unbuilt witness/audit idea (`spec/22-future-work.md`,
`future_flood_propagation_and_anonymity.md`/`future_service_announcements_and_audit.md` memory
there) -- generalized across clusters.

## The mechanism

A peer that independently observes, fetches, or computes something for a `claim_id` (an opaque
string callers agree on out of band -- a URL, a gateway query key, a content identifier) signs a
`ClaimReport`: "I, as a member of `reporter_cluster`, observed `observed_value_hash` for this
claim." Signed with the same `oag_crypto::PeerIdentity` every other mechanism in this crate
reuses, under this file's own domain string.

`reporter_cluster` is a **bare self-assertion** -- not verified against anything, not cross-checked
against `bridge::MeshTree`'s actual cluster-nesting data. Exactly the same trust shape the base
project's own `[cluster].name` has (`spec/26-peer-clustering.md` there: "a name is a shared,
unauthenticated label until corroborated"). A caller weighing a corroboration count should weigh
this the same way.

## Why weight by cluster, not just by peer

`bridge::MeshTree` (spec/02) corroborates membership edges by counting *distinct peers*. That's
the right signal there -- two peers independently declaring the same bridge fact is stronger than
one. For claim corroboration specifically, distinct-peer counting has a real weakness: a single
organization can run many peers, and many peers independently "agreeing" with each other proves
nothing about whether the claim is actually true if they're all the same operator feeding them
the same (possibly wrong) answer. Counting **distinct clusters** instead directly answers
`spec/01-overview.md`'s open "what counts as independent enough" question for this mechanism: two
reports from the same self-asserted `reporter_cluster` corroborate each other no more than one
report alone does; agreement across *different* clusters is the real signal.

`ClaimCorroboration::best_corroborated_value` groups every report for a `claim_id` by
`observed_value_hash`, counts distinct clusters and distinct peers behind each value, and returns
whichever value has the most distinct corroborating clusters (ties broken by distinct peer
count). `cluster_corroboration_for` answers the same question for one specific value directly.

## What this explicitly is not (yet)

- **No cross-check against real cluster nesting.** `reporter_cluster` is never validated against
  `bridge::MeshTree` -- a report claiming a cluster name that doesn't exist, or that the
  reporting peer has no real standing in, is accepted exactly the same as a real one. Combining
  the two mechanisms (only count a report if its claimed cluster is a `BridgeDeclaration`-attested
  real cluster) is a real, un-built refinement, not an oversight.
- **No weighting by how deeply nested/large a cluster is.** A report from a cluster with one
  member counts exactly the same as one from a cluster with a thousand -- "distinct cluster"
  is binary, not a richer trust score.
- **No anti-spam/sybil resistance.** Unlike `anonymous_event.rs`'s proof-of-work, there's nothing
  here stopping one actor from minting many `PeerIdentity`s, each self-asserting a different
  fabricated `reporter_cluster`, to inflate a claim's apparent cluster diversity for free. This
  mechanism needs real identity (to make `reporter_cluster` meaningful at all), which rules out
  `anonymous_event.rs`'s identity-free proof-of-work approach directly -- a different anti-sybil
  mechanism (if any) would need to target fake *cluster* diversity specifically, not spam volume.
- **No persistence, no pull-based anti-entropy.** Same gaps as every other mechanism in this
  crate -- `ClaimCorroboration` is in-memory, and `broadcast_claim_report` is push-only.
- **The read endpoint is node-local, not network-wide.** `GET /oag-mesh/v1/claim-report/{claim_id}/best`
  answers from whatever this one node has received so far -- it does not fan out to other mesh
  nodes to assemble a wider view. A caller wanting the whole mesh's picture has to ask multiple
  nodes itself (the same way the base project's own gateway's `fanout_and_verify` does within one
  peer's `query_peers` -- that fan-out step doesn't exist here yet, across clusters).

## Tests

`crates/oag-mesh/src/corroboration.rs` (9 unit tests): sign/verify round trip and the usual
tamper/mismatched-key/stale-timestamp rejections; two reports from the same cluster count as one
cluster's worth of corroboration; reports from different clusters corroborate more strongly than
a lone dissenter; a peer re-reporting the same value doesn't inflate its own count; an unknown
claim has no best value; an invalid report is never recorded. `crates/oag-mesh/src/transport.rs`
adds 4 more: a pushed report is recorded and queryable over the wire; a tampered one is rejected;
`broadcast_claim_report` reaches every configured peer and each one independently corroborates
it; querying an unknown claim returns `null`.
