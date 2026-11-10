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

## Five message types, different transport guarantees

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
  real cluster nesting" section for exactly what that cross-check does and does not confirm. `GET
  /oag-mesh/v1/claim-report/{claim_id}/best-fully-cross-checked?min_bridge_corroboration=N&min_membership_corroboration=M`
  goes further still, additionally cross-checking against this node's own
  `membership::MembershipRegistry` -- see `spec/09-cluster-membership-attestation.md`.
- **`MembershipAttestation`** (`spec/09-cluster-membership-attestation.md`) is signed, same
  posture as `BridgeDeclaration`/`ClaimReport` -- nothing about who's attesting needs hiding.
  `POST /oag-mesh/v1/membership-attestation` carries a `MembershipAttestationSubmission
  { attestation, pow }`; it verifies the signature, the self-attestation rejection, and the
  `MembershipProofOfWork` against `MembershipRegistry::required_difficulty_bits` (`spec/09`'s
  "Anti-sybil resistance" section) before recording anything, rejecting an insufficient proof
  with `400` the same way the other mechanisms' proofs are.
- **`ResponderAcknowledgment`** (`spec/12-responder-acknowledgment.md`) is signed, same
  accountability posture as `BridgeDeclaration`/`ClaimReport`/`MembershipAttestation` -- but
  deliberately carries **no proof-of-work**, unlike every other signed submission here (see
  `spec/12`'s own reasoning for why one doesn't fit this mechanism). `POST
  /oag-mesh/v1/responder-acknowledgment` carries just `ResponderAcknowledgmentSubmission
  { acknowledgment }`; it verifies the signature, pairing, and freshness, same three checks as
  every other signed message, nothing more. `GET
  /oag-mesh/v1/responder-acknowledgment/{corroboration_nonce}` reads back every responder
  currently claiming to handle that event -- advisory only, see `spec/12`'s own "what this
  explicitly is not" for what a non-empty result does and does not guarantee.
- **`AnonymousEvent`** (`spec/03-anonymous-event-rfc.md`) is a different story, and this is the
  important part of this file: **`POST /oag-mesh/v1/anonymous-event` does not, and cannot, hide
  the submitting connection's source IP from the receiving peer.** That's an inherent property of
  a plain HTTP POST, not a choice the handler makes. The *payload* carries no identity by
  `anonymous_event.rs`'s own design — the *transport* carrying it here provides zero additional
  anonymity on top of that. Treat this endpoint as "gets an already-anonymous payload from A to
  B," never as "hides who submitted it." A one-hop relay is now available as an explicit
  configuration (`MeshState::anonymous_event_relay_target`): a node configured with a target
  forwards every verified event to it, so the target sees the relay's address rather than the
  original submitter's. And onion routing (`spec/15-onion-routing.md`) wraps the submission in
  layered encryption through a path of relays, so no single relay sees both ends. Neither is
  traffic-analysis resistance (the base project's `spec/22-future-work.md` "never ending
  morphing encryption") -- that remains unresolved. `GET
  /oag-mesh/v1/anonymous-event/search` reads
  back this node's own log, filtered by kind/minimum severity/location prefix/recency -- see
  `spec/11-responder-search.md` for exactly what that is (a discovery primitive) and is not
  (dispatch, notification, or anything that identifies a responder).

`POST /oag-mesh/v1/route-search` is a different shape entirely from the five above: not a
submission that gets recorded anywhere, but a query (`RouteSearchRequest { from, target,
min_corroboration, remaining_hops, already_asked }`) that a receiving node answers by checking
its own local `bridge::MeshTree::shortest_path` and, if that's not enough, *forwarding the same
query to its own peers* -- the one endpoint in this file that triggers further outbound requests
rather than simply reading or writing local state. See `spec/13-distributed-route-search.md` for
the full mechanism, including the real amplification cost of a query that can fan out across
multiple hops with no rate limiting.

Shipping a transport for `AnonymousEvent` at all, with this gap stated plainly, was a deliberate
choice over waiting for the harder anonymity problem to be solved first — the payload-level
anonymity guarantee (no identifying field) still holds and still has real value even without
network-level anonymity; overstating what's achieved would be worse than being honest about a
partial guarantee.

## How a declaration/event/report actually reaches the rest of the mesh

`MeshState.peers`: a static, hand-written list of other mesh node addresses — the same
"operator-configured topology, no automatic discovery" posture as the base project's
`[transfer].relay_peers`/`[gateway].query_peers`. `broadcast_bridge_declaration`/
`broadcast_anonymous_event`/`broadcast_claim_report`/`broadcast_membership_attestation`/
`broadcast_responder_acknowledgment` push to every configured peer, best-effort (one unreachable
peer doesn't stop the others reaching it). A
peer offline at broadcast time doesn't get left behind forever, though: pull-based anti-entropy
now exists (`spec/10-anti-entropy.md`) -- `pull_and_merge`/`sync_with_all_peers` check a peer's
`GET /oag-mesh/v1/sync/heads` stamps and pull only the stores whose sequence changed, merging
each into the puller's own, closing that gap at the cost of a weaker, unverified trust model
than push's own re-verification (see `spec/10`'s own "trade-off" section). Nothing calls this
automatically; a caller decides when and how often.

`POST /oag-mesh/v1/anonymous-event` carries an `AnonymousEventSubmission { event, pow }` --
`anonymous_event::AnonymousEventLog::record` enforces the escalating proof-of-work check
(`spec/03-anonymous-event-rfc.md`'s "Anti-spam and anti-replay") before recording anything, so a
submission with no or insufficient proof-of-work is rejected here with `400` the same way a
tampered `BridgeDeclaration` or an under-difficulty `ClaimReportSubmission` is. Four of these
five message types now carry a proof-of-work alongside their payload over the wire -- the one
difference left between them is what each proof is actually bound to and what resource it taxes
(see each mechanism's own "Anti-spam"/"Anti-sybil resistance" section). `ResponderAcknowledgment`
is the deliberate exception -- see `spec/12-responder-acknowledgment.md` for why one doesn't fit.

## Every outbound request is bounded by a timeout

`reqwest::Client::new()` sets no timeout at all. For a client talking to an operator-configured
list of arbitrary peer addresses, that is not a theoretical concern: a peer that is unreachable
*and silently dropping packets* -- rather than refusing the connection -- holds the request open
until the operating system gives up, which can be minutes. Two things in this crate make that
worse than a slow pull:

- `sync_with_all_peers` pulls peers **sequentially**, so one black-holed peer stalls the whole
  tick before any live peer is reached.
- `search_for_route` fans out by calling `push_route_search` directly, and that fan-out is on the
  path of an *inbound* `POST /oag-mesh/v1/route-search`. One broken peer can therefore hang a
  request from a third party, not only this node's own background work.

Every outbound request now goes through `build_http_client`, which sets both a connect timeout
(`HTTP_CONNECT_TIMEOUT`, 5s -- the case where the peer never answers the TCP handshake) and a
total request timeout (`HTTP_REQUEST_TIMEOUT`, 30s -- the case where the connection succeeds and
then nothing arrives). Both are named constants so a deployment can retune them, and
`build_http_client` takes them as parameters so a test can prove the bound holds without waiting
the production value out.

A timed-out request is an ordinary failed interaction: `pull_and_merge` reports it as a failed
delivery and `link_quality` records it, which is exactly the observation that makes the next
fan-out spend its budget better.

## Tests

`crates/oag-mesh/src/transport.rs` (33 integration tests, real axum servers bound to real
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
claim returns a `null` result; save-then-load round-trips all five stores through disk; loading
from a nonexistent directory starts every store empty; a pushed `MembershipAttestation` (with
valid proof-of-work) is recorded; a tampered one is rejected over the wire;
`broadcast_membership_attestation` reaches every configured peer; `GET
.../best-fully-cross-checked` drops a report from a peer with no membership attestation while
still counting one that passes both checks; `.../best-fully-cross-checked` against an unknown
claim returns a `null` result; `GET .../anonymous-event/search` filters by kind and by minimum
severity correctly, with an empty query string returning everything (`spec/11-responder-
search.md`); a pushed `ResponderAcknowledgment` (no proof-of-work required) is recorded and
readable back, a tampered one is rejected, `broadcast_responder_acknowledgment` reaches every
configured peer, and querying an unacknowledged nonce returns an empty list
(`spec/12-responder-acknowledgment.md`); plus 5 more for pull-based anti-entropy, listed in
`spec/10-anti-entropy.md`'s own "Tests" section, and 4 more for distributed route search, listed
in `spec/13-distributed-route-search.md`'s own "Tests" section.

## Open questions (genuinely unresolved)

- **Network-level anonymity for `AnonymousEvent` submission.** Stated above, repeated here
  because it's the single most important gap in this file: a plain POST reveals the reporter's
  source IP to the peer they submit to, and proof-of-work is orthogonal. Two layers now exist --
  a one-hop relay (`MeshState::anonymous_event_relay_target`) hides the reporter from the final
  target, and onion routing (`spec/15-onion-routing.md`) hides both ends from any single relay.
  Traffic-analysis resistance remains unresolved.
- **Pull-based anti-entropy exists now (`spec/10-anti-entropy.md`), but it's a weaker trust
  model than push, not a free upgrade.** Merging a pulled snapshot trusts the source peer's own
  prior verification instead of re-deriving it -- see `spec/10`'s own "trade-off" section for
  exactly what that costs. It's still not a delta sync -- a changed store is fetched whole --
  but a heads check (`GET /oag-mesh/v1/sync/heads`) now skips stores that haven't changed since
  the last pull, so an unchanged store costs one small stamp rather than a full snapshot. A
  scheduling opt-in exists (`spawn_periodic_sync`, plus
  `spawn_periodic_sync_with_jitter` for a random phase), with no default cadence or cross-node
  coordination.
- **Four of five submission types now cost real, escalating proof-of-work, but none of them stop
  a well-resourced attacker, and the fifth has a different problem entirely.**
  `AnonymousEvent` (`spec/03`'s "Anti-spam and anti-replay"), `ClaimReport` (`spec/05`'s
  "Anti-sybil resistance"), `BridgeDeclaration` (`spec/02`'s "Anti-sybil resistance"), and
  `MembershipAttestation` (`spec/09`'s "Anti-sybil resistance") each tax a different specific
  resource -- raw report volume under a nonce, a new distinct cluster on a claim, a new distinct
  peer on a mesh edge, and a new distinct attester on a membership claim, respectively -- and each
  says so plainly: a botnet solves proof-of-work exactly as fast as anyone else, so this raises
  cost from free to real, it does not bound submission volume outright. Minting many real
  `PeerIdentity`s and paying for each one is still a working (if no longer free) attack on every
  one of those four. `ResponderAcknowledgment` has no proof-of-work at all, by design -- its open
  risk isn't sybil-inflated corroboration, it's a single identity falsely claiming to handle
  real events to suppress genuine responders, which proof-of-work wouldn't have stopped anyway.
  A per-identity fixed-window rate limit now bounds that flood (`RESPONDER_ACK_RATE_LIMIT_MAX`
  per `RESPONDER_ACK_RATE_LIMIT_WINDOW`, 60 per 60s by default, `429` + `Retry-After` when the
  window is full) -- a rate limit, not a reputation system or an allowlist, and a genuine
  responder who exceeds the cap is throttled too. See
  `spec/12-responder-acknowledgment.md`'s own "what this explicitly is not" for that stated
  plainly.
- **Proof-of-work doesn't verify *who* a peer really is, only that solving a puzzle cost
  something.** A well-resourced single operator can solve enough proof-of-work to mint several
  real, distinct `PeerIdentity`s and look just as independent as genuinely separate
  organizations -- across all four proof-of-work-bearing mechanisms. See `spec/01-overview.md`'s
  open questions for this stated as the remaining "independent enough" gap.
- **The `GET .../best`, `.../best-cross-checked`, and `.../best-fully-cross-checked` read
  endpoints have no auth at all.** Anyone who can reach the listen address can read any node's
  current corroboration view for any `claim_id` -- whether that's fine (mirroring `GET /metrics`'s
  "aggregate, nothing sensitive" posture in the base project) or needs gating depends on what real
  `claim_id`/`observed_value_hash` content ends up flowing through a real deployment, which isn't
  decided yet.
- **`POST /oag-mesh/v1/route-search` now has a per-search fan-out budget and a node-wide rate
  limiter, but neither is authentication.** See `spec/13-distributed-route-search.md`'s
  "Anti-amplification" section: the fan-out budget caps the total outbound requests a single
  search can cause, and the token bucket rate-limits inbound requests with
  `429`/`Retry-After`. The bucket is node-wide, not per-requester, because the transport has no
  requester identity. A real deployment exposing this to anything less trusted than its own
  operator-configured peer list still needs its own authentication and per-requester limits.
