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
  nothing from hiding who sent it — `POST /oag-mesh/v1/bridge-declaration` just verifies and
  records it (`bridge::MeshTree::add`), the same way the base project's own signed-declaration
  endpoints work.
- **`ClaimReport`** (`spec/05-federated-corroboration.md`) is the same shape as
  `BridgeDeclaration` -- signed, nothing to hide, `POST /oag-mesh/v1/claim-report` just verifies
  and records it. `GET /oag-mesh/v1/claim-report/{claim_id}/best` reads back this node's own
  current view (not a network-wide fan-out -- see `spec/05`'s own "what this is not" section).
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
tampered `BridgeDeclaration` is.

## Tests

`crates/oag-mesh/src/transport.rs` (10 integration tests, real axum servers bound to real
loopback ports, real HTTP round trips — no mocking): a pushed `BridgeDeclaration` is recorded and
corroborated on the receiving side; a tampered declaration is rejected over the wire with `400`
and never recorded; `broadcast_bridge_declaration` reaches every one of several independently
running peers; a pushed `AnonymousEvent` (with valid proof-of-work) is recorded; an invalid one
(unrounded timestamp) is rejected over the wire and never recorded; one with insufficient
proof-of-work is rejected over the wire and never recorded; a pushed `ClaimReport` is recorded
and readable back over `GET .../best`; a tampered one is rejected over the wire;
`broadcast_claim_report` reaches every configured peer and each independently corroborates it;
querying an unknown claim returns `null`.

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
- **No authentication/rate-limiting on `BridgeDeclaration`/`ClaimReport` submission.** Anyone who
  can reach a mesh node's listen address can submit either — both are still subject to signature
  verification, but anyone can mint a fresh `PeerIdentity` for free, so verification alone
  doesn't bound submission volume, and for `ClaimReport` specifically doesn't bound how many
  distinct (fabricated) `reporter_cluster` values one actor can claim either. `AnonymousEvent`
  submission costs real, escalating proof-of-work instead (`spec/03`'s "Anti-spam and
  anti-replay") — a real mitigation, not a full solution; see that section's own stated limits
  (doesn't stop a well-resourced attacker). No equivalent exists for `ClaimReport` yet
  (`spec/05`'s own open question).
- **The `GET .../best` read endpoint has no auth at all.** Anyone who can reach the listen
  address can read any node's current corroboration view for any `claim_id` -- whether that's
  fine (mirroring `GET /metrics`'s "aggregate, nothing sensitive" posture in the base project) or
  needs gating depends on what real `claim_id`/`observed_value_hash` content ends up flowing
  through a real deployment, which isn't decided yet.
