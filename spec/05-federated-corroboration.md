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
reuses, under this file's own domain string. A submission also carries a `ClaimReportProofOfWork`
-- see "Anti-sybil resistance" below for why.

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

## Anti-sybil resistance

Signature verification alone doesn't bound how many distinct `reporter_cluster` values one actor
can claim, because minting a fresh `PeerIdentity` costs nothing -- the exact gap this section
previously left open. Unlike `anonymous_event.rs`, this mechanism can't lean on proof-of-work
*instead of* identity, since `reporter_cluster` weighting only means anything if the reporter is
identified at all. What it can do is tax the specific resource an attacker actually wants: adding
a *new distinct cluster* to a claim's corroboration count.

`ClaimReportProofOfWork` (`corroboration.rs`) mirrors `anonymous_event::ProofOfWork`'s
blake3-based, Hashcash-style leading-zero-bit search, bound to one specific
`(peer_id, claim_id, reporter_cluster, observed_value_hash)` combination so a solved proof can't
be replayed for a different report. The difficulty it must meet, though, is keyed differently
from `anonymous_event`'s per-nonce escalation:

- **Free (`0` bits) if `reporter_cluster` already has a report recorded for this `claim_id`.** A
  second peer from an already-counted cluster, or the same peer re-reporting, doesn't move
  `distinct_clusters` at all -- there's nothing to tax, so nothing is charged.
- **Otherwise, `BASE_CLAIM_REPORT_DIFFICULTY_BITS` plus `CLAIM_REPORT_DIFFICULTY_STEP_BITS` for
  every distinct cluster already corroborating this claim.** Becoming the claim's first
  corroborating cluster is cheap (so a lone genuine reporter from a brand-new claim isn't
  deterred); becoming its fifth costs real, escalating work.

`ClaimCorroboration::required_difficulty_bits(claim_id, reporter_cluster)` tells a submitting
client what to solve for before it spends the work; `add` enforces it, rejecting an
under-difficulty submission with `ClaimReportError::InsufficientProofOfWork` and never recording
it -- the same "verify before you record anything" posture `AnonymousEventLog::record` uses.

This raises the cost of inflating a claim's apparent cluster diversity from free to real, exactly
like `anonymous_event.rs`'s proof-of-work does for raw report volume -- and has the identical
limit, stated plainly rather than implied away: **it does not, and cannot, stop a well-resourced
attacker.** A botnet solves proof-of-work exactly as fast as anyone else; what changes is that
doing so now costs something at all, instead of nothing.

## Cross-checking against real cluster nesting

`ClaimCorroboration::add` and `best_corroborated_value` still accept and count any
`reporter_cluster` string at all -- no change there, since `ClaimCorroboration` has no inherent
reason to know about `bridge::MeshTree`. `best_corroborated_value_cross_checked(claim_id,
mesh_tree, min_bridge_corroboration)` is the combined view: it drops every report whose
`reporter_cluster` is not attested anywhere in `mesh_tree` as a real base-layer cluster
(`bridge::MeshTree::is_attested_base_cluster`), before counting distinct clusters/peers the same
way `best_corroborated_value` does. It returns a `CrossCheckedAgreement { best,
reports_dropped_unattested_cluster }` so a caller can see how much was excluded, not just the
surviving result.

This closes **half** of the original gap, not all of it. `is_attested_base_cluster` confirms a
cluster *name* is real -- some peer somewhere signed a `BridgeDeclaration` nesting it under a
mesh-group. It does **not** confirm the *reporting* peer has any real standing in that cluster: a
`BridgeDeclaration` only ever says "cluster C is nested under mesh-group M," signed by whichever
peer felt like asserting that, never "peer P is a genuine member of cluster C." A reporting peer
that picks a real, attested cluster name it has nothing to do with still passes this check. Fully
closing that requires a new kind of signed fact this crate doesn't have -- something like other
members of cluster C attesting "peer P really is one of us" -- which is a real, separate,
unbuilt mechanism, not a refinement of this one.

`GET /oag-mesh/v1/claim-report/{claim_id}/best-cross-checked?min_bridge_corroboration=N` exposes
this over the wire (`spec/04-transport.md`), reading from the same node-local `state.tree` and
`state.claim_corroboration` the plain `.../best` endpoint does -- same "this node's own view,
no network fan-out" scope.

Worth being honest about: this cross-check's real-world value is currently bounded by
`BridgeDeclaration` submission having no anti-sybil protection of its own (unlike `ClaimReport`,
as of this file's "Anti-sybil resistance" section above). An attacker can still mint a
`BridgeDeclaration` attesting a fabricated base cluster for free, satisfying
`is_attested_base_cluster` at `min_bridge_corroboration = 1` just as easily as a real cluster
would. Raising `min_bridge_corroboration` raises the cost (more free-but-independent-looking
declarations needed), but doesn't close the gap -- see `spec/04-transport.md`'s open questions
for this noted against `BridgeDeclaration` directly.

## What this explicitly is not (yet)

- **No cross-check of reporting-peer standing in a cluster.** Stated above: the cross-check
  confirms the cluster name is real, never that the reporter belongs to it. See that section for
  why, and what closing it fully would need.
- **No weighting by how deeply nested/large a cluster is.** A report from a cluster with one
  member counts exactly the same as one from a cluster with a thousand -- "distinct cluster"
  is binary, not a richer trust score.
- **Proof-of-work raises the cost of fake cluster diversity, it does not eliminate it.** See
  "Anti-sybil resistance" above for what `ClaimReportProofOfWork` does and does not achieve --
  stated there as plainly as `anonymous_event.rs`'s own identical caveat: a well-resourced
  attacker is not stopped, only taxed.
- **No persistence, no pull-based anti-entropy.** Same gaps as every other mechanism in this
  crate -- `ClaimCorroboration` is in-memory, and `broadcast_claim_report` is push-only.
- **The read endpoint is node-local, not network-wide.** `GET /oag-mesh/v1/claim-report/{claim_id}/best`
  answers from whatever this one node has received so far -- it does not fan out to other mesh
  nodes to assemble a wider view. A caller wanting the whole mesh's picture has to ask multiple
  nodes itself (the same way the base project's own gateway's `fanout_and_verify` does within one
  peer's `query_peers` -- that fan-out step doesn't exist here yet, across clusters).

## Tests

`crates/oag-mesh/src/corroboration.rs` (16 unit tests): sign/verify round trip and the usual
tamper/mismatched-key/stale-timestamp rejections; two reports from the same cluster count as one
cluster's worth of corroboration; reports from different clusters corroborate more strongly than
a lone dissenter; a peer re-reporting the same value doesn't inflate its own count; an unknown
claim has no best value; an invalid report is never recorded (proof-of-work never even checked,
since signature verification fails first); the cross-check drops a report claiming an unattested
cluster while leaving an attested one's corroboration intact; the cross-check returns a `None`
best value (with a non-zero drop count) when every report for a known claim is unattested; the
cross-check against a genuinely unknown claim still returns `None`; a report with no
proof-of-work is rejected; a second report from an already-counted cluster requires no
proof-of-work at all; required difficulty escalates with each additional distinct cluster on one
claim, and a proof solved for an earlier difficulty is no longer enough; a proof-of-work is bound
to its own report and can't be reused for a different one. `crates/oag-mesh/src/transport.rs`
adds 6 more: a pushed report (with valid proof-of-work) is recorded and queryable over the wire;
a tampered one is rejected; `broadcast_claim_report` reaches every configured peer and each one
independently corroborates it; querying an unknown claim returns `null`; `.../best-cross-checked`
drops a report from a fabricated cluster while the plain `.../best` endpoint still counts it;
`.../best-cross-checked` against an unknown claim returns a `null` result.
