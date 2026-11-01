# Transport

**Source**: `crates/oag-mesh/src/transport.rs`.

**What layer this is on**: its own, not a part of the base project's `open-agent-graph`. That
repository's `oag-sync` (`spec/14-replication-sync.md` there) is *its* peer-to-peer transport
layer, carrying `/oag/sync/v1/*`; `spec/32-verified-internet-gateway.md` there added a second,
separate endpoint (`/oag/gateway/v1/query`) for a different protocol rather than extending
`oag-sync`'s wire format. This file is the same move again, one repository up: `oag-mesh` gets its
own HTTP transport, its own listen address/port, its own `/oag-mesh/v1/*` routes — structurally
parallel to `oag-sync`, but a different crate, a different repository, and a different wire
protocol entirely. Nothing in the base project needs to know this exists.

## Three message types, different transport guarantees

- **`BridgeDeclaration`** (`spec/02-cluster-nesting.md`) is signed by a real identity and gains
  nothing from hiding who sent it. `POST /oag-mesh/v1/bridge-declaration` carries a
  `BridgeDeclarationSubmission { declaration, pow }`; it verifies the signature *and* checks the
  `BridgeProofOfWork` against `MeshTree::required_difficulty_bits` (`spec/02`'s "Anti-sybil
  resistance" section) before recording anything, rejecting an insufficient proof with `400` the
  same way the other two mechanisms' proofs are.
- **`ClaimReport`** (`spec/05-federated-corroboration.md`) is signed, same as `BridgeDeclaration`
  -- nothing about who sent it needs hiding. `POST /oag-mesh/v1/claim-report` carries a
  `ClaimReportSubmission { report, pow }`; it verifies the signature *and* checks the
  `ClaimReportProofOfWork` against `ClaimCorroboration::required_difficulty_bits` (spec/05's
  "Anti-sybil resistance" section) before recording anything, rejecting an insufficient proof
  with `400` the same way an insufficient `AnonymousEvent` proof is. `GET
  /oag-mesh/v1/claim-report/{claim_id}/best` reads back this node's own current view (not a
  network-wide fan-out -- see `spec/05`'s own "what this is not" section). `GET
  /oag-mesh/v1/claim-report/{claim_id}/best-cross-checked?min_bridge_corroboration=N` reads back
  the same thing, but cross-checked against this node's own `bridge::MeshTree` -- dropping any
  report whose `reporter_cluster` isn't attested by a real `BridgeDeclaration` first. Same
  node-local scope as the plain `.../best` endpoint; see `spec/05`'s "Cross-checking against
  real cluster nesting" section for exactly what that cross-check does and does not confirm.
- **`AnonymousEvent`** (`spec/03-anonymous-event-rfc.md`) is a different story, and this is the
  important part of this file: **`POST /oag-mesh/v1/anonymous-event` does not, and cannot, hide
  the submitting connection's source IP from the receiving peer.** That's an inherent property of
  a plain HTTP POST, not a choice the handler makes. The *payload* carries no identity by
  `anonymous_event.rs`'s own design — the *transport* carrying it here provides zero additional
  anonymity on top of that. Treat this endpoint as "gets an already-anonymous payload from A to
  B," never as "hides who submitted it." A real anonymizing submission path (routing through an
  intermediary that doesn't log source-to-content correlation, onion-style layered relaying, or
  similar) is explicitly not built here — see "Open questions" below, and the identical
  unresolved gap in the base project's own `spec/22-future-work.md` ("never ending morphing
  encryption," traffic-analysis resistance).

Shipping a transport for `AnonymousEvent` at all, with this gap stated plainly, was a deliberate
choice over waiting for the harder anonymity problem to be solved first — the payload-level
anonymity guarantee (no identifying field) still holds and still has real value even without
network-level anonymity; overstating what's achieved would be worse than being honest about a
partial guarantee.

## How a declaration/event/report actually reaches the rest of the mesh

`MeshState.peers`: a static, hand-written list of other mesh node addresses — the same
"operator-configured topology, no automatic discovery" posture as the base project's
`[transfer].relay_peers`/`[gateway].query_peers`. `broadcast_bridge_declaration`/
`broadcast_anonymous_event`/`broadcast_claim_report` push to every configured peer, best-effort
(one unreachable peer doesn't stop the others reaching it). There is **no pull-based
anti-entropy** — a peer offline at broadcast time simply never receives that message unless
something else re-pushes it later. This is a real, accepted gap for a first version, not a
hidden one.

`POST /oag-mesh/v1/anonymous-event` carries an `AnonymousEventSubmission { event, pow }` --
`anonymous_event::AnonymousEventLog::record` enforces the escalating proof-of-work check
(`spec/03-anonymous-event-rfc.md`'s "Anti-spam and anti-replay") before recording anything, so a
submission with no or insufficient proof-of-work is rejected here with `400` the same way a
tampered `BridgeDeclaration` or an under-difficulty `ClaimReportSubmission` is. All three message
types now carry a proof-of-work alongside their payload over the wire -- the one difference left
between them is what each proof is actually bound to and what resource it taxes (see each
mechanism's own "Anti-spam"/"Anti-sybil resistance" section).

## Tests

`crates/oag-mesh/src/transport.rs` (12 integration tests, real axum servers bound to real
loopback ports, real HTTP round trips — no mocking): a pushed `BridgeDeclaration` (with valid
proof-of-work) is recorded and corroborated on the receiving side; a tampered declaration is
rejected over the wire with `400` and never recorded; `broadcast_bridge_declaration` reaches
every one of several independently running peers; a pushed `AnonymousEvent` (with valid
proof-of-work) is recorded; an invalid one (unrounded timestamp) is rejected over the wire and
never recorded; one with insufficient proof-of-work is rejected over the wire and never recorded;
a pushed `ClaimReport` (with valid proof-of-work) is recorded and readable back over
`GET .../best`; a tampered one is rejected over the wire; `broadcast_claim_report` reaches every
configured peer and each independently corroborates it; querying an unknown claim returns `null`;
`GET .../best-cross-checked` drops a report claiming a fabricated cluster name while the plain
`.../best` endpoint still counts it, over the wire; `.../best-cross-checked` against an unknown
claim returns a `null` result.

## Open questions (genuinely unresolved)

- **Network-level anonymity for `AnonymousEvent` submission.** Stated above, repeated here
  because it's the single most important gap in this file: nothing here hides a reporter's
  source IP from the peer they submit to. Proof-of-work (below) is an orthogonal mechanism and
  does nothing about this.
- **No pull-based sync/anti-entropy.** A declaration, event, or report only reaches a peer that
  was online and reachable at broadcast time. The base project's `oag-sync` solves exactly this
  for its own event log (`hello`/`heads` + anti-entropy pull) — whether `oag-mesh` should
  eventually grow the same mechanism, or stay push-only given its different
  (lower-stakes-per-message, higher-volume) traffic pattern, is undecided.
- **All three submission types now cost real, escalating proof-of-work, but none of them stop a
  well-resourced attacker.** `AnonymousEvent` (`spec/03`'s "Anti-spam and anti-replay"),
  `ClaimReport` (`spec/05`'s "Anti-sybil resistance"), and `BridgeDeclaration` (`spec/02`'s
  "Anti-sybil resistance") each tax a different specific resource -- raw report volume under a
  nonce, a new distinct cluster on a claim, and a new distinct peer on a mesh edge, respectively
  -- and each says so plainly: a botnet solves proof-of-work exactly as fast as anyone else, so
  this raises cost from free to real, it does not bound submission volume outright. Minting many
  real `PeerIdentity`s and paying for each one is still a working (if no longer free) attack on
  every mechanism here.
- **Proof-of-work doesn't verify *who* a peer really is, only that solving a puzzle cost
  something.** A well-resourced single operator can solve enough proof-of-work to mint several
  real, distinct `PeerIdentity`s and look just as independent as genuinely separate
  organizations -- across all three mechanisms. See `spec/01-overview.md`'s open questions for
  this stated as the remaining "independent enough" gap.
- **The `GET .../best` and `GET .../best-cross-checked` read endpoints have no auth at all.**
  Anyone who can reach the listen address can read any node's current corroboration view for any
  `claim_id` -- whether that's fine (mirroring `GET /metrics`'s "aggregate, nothing sensitive"
  posture in the base project) or needs gating depends on what real `claim_id`/
  `observed_value_hash` content ends up flowing through a real deployment, which isn't decided
  yet.
