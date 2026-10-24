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

## Two message types, two different transport guarantees

- **`BridgeDeclaration`** (`spec/02-cluster-nesting.md`) is signed by a real identity and gains
  nothing from hiding who sent it — `POST /oag-mesh/v1/bridge-declaration` just verifies and
  records it (`bridge::MeshTree::add`), the same way the base project's own signed-declaration
  endpoints work.
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

## How a declaration/event actually reaches the rest of the mesh

`MeshState.peers`: a static, hand-written list of other mesh node addresses — the same
"operator-configured topology, no automatic discovery" posture as the base project's
`[transfer].relay_peers`/`[gateway].query_peers`. `broadcast_bridge_declaration`/
`broadcast_anonymous_event` push to every configured peer, best-effort (one unreachable peer
doesn't stop the others reaching it). There is **no pull-based anti-entropy** — a peer offline at
broadcast time simply never receives that message unless something else re-pushes it later. This
is a real, accepted gap for a first version, not a hidden one.

## Tests

`crates/oag-mesh/src/transport.rs` (5 integration tests, real axum servers bound to real
loopback ports, real HTTP round trips — no mocking): a pushed `BridgeDeclaration` is recorded and
corroborated on the receiving side; a tampered declaration is rejected over the wire with `400`
and never recorded; `broadcast_bridge_declaration` reaches every one of several independently
running peers; a pushed `AnonymousEvent` is recorded; an invalid one (unrounded timestamp) is
rejected over the wire and never recorded.

## Open questions (genuinely unresolved)

- **Network-level anonymity for `AnonymousEvent` submission.** Stated above, repeated here
  because it's the single most important gap in this file: nothing here hides a reporter's
  source IP from the peer they submit to.
- **No pull-based sync/anti-entropy.** A declaration or event only reaches a peer that was online
  and reachable at broadcast time. The base project's `oag-sync` solves exactly this for its own
  event log (`hello`/`heads` + anti-entropy pull) — whether `oag-mesh` should eventually grow the
  same mechanism, or stay push-only given its different (lower-stakes-per-message, higher-volume)
  traffic pattern, is undecided.
- **No authentication/rate-limiting on either endpoint.** Anyone who can reach a mesh node's
  listen address can submit a `BridgeDeclaration` (it's still subject to signature verification,
  but anyone can mint a fresh `PeerIdentity` for free) or an `AnonymousEvent` (no identity to even
  check). Both are spammable; see `spec/03`'s own anti-spam/sybil open question for the event
  side specifically.
