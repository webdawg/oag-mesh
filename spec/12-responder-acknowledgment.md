# Responder Acknowledgment

**Source**: `crates/oag-mesh/src/responder.rs`, `crates/oag-mesh/src/transport.rs`
(`/oag-mesh/v1/responder-acknowledgment*`).

Closes the specific gap `spec/11-responder-search.md`'s own "what this explicitly is not" named:
"no claim-to-avoid-duplicate-response." Two responders running the same
`anonymous_event::AnonymousEventLog::search` against the same filter would otherwise see
identical results with no way to tell whether someone's already acting on one. This adds a
signed claim a responder can make -- "I am handling the event at this `corroboration_nonce`" --
so a second responder checking first can see it and decide not to duplicate the effort.

**This is advisory, not a lock.** Nothing here *prevents* two responders from both showing up, or
*guarantees* that an active-looking claim reflects real action. See "What this explicitly is
not" below.

## Why this reuses a real signed identity

Every other signed mechanism in this crate (`bridge::BridgeDeclaration`, `corroboration::
ClaimReport`, `membership::MembershipAttestation`) uses a real `oag_crypto::PeerIdentity`
because the thing being claimed benefits from accountability, and the claimant isn't a
vulnerable party. `anonymous_event::AnonymousEvent` is the deliberate exception -- its whole
design exists to protect a *reporter* who may be in danger. A responder is not that: it's an
organization or individual choosing to act, the same shape as every other identity-bearing claim
here. `ResponderAcknowledgment` reuses `PeerIdentity` and this crate's usual signed-message
pattern (domain-separated signing, `(peer_id, public_key)` pairing check, `MAX_CLOCK_SKEW_SECONDS`
freshness) accordingly.

## Why this carries no proof-of-work, unlike every other signed submission here

`bridge::BridgeProofOfWork`, `corroboration::ClaimReportProofOfWork`, and `membership::
MembershipProofOfWork` all tax the cost of inflating a *corroboration count* -- becoming a new
distinct peer, cluster, or attester that makes a trust signal stronger. An acknowledgment has no
such count to protect: more distinct identities claiming to handle the *same* event isn't a
stronger signal, it's just noise (see "What this explicitly is not" below for the actual spam
risk this leaves open). There's nothing proportionate here for an escalating-difficulty scheme to
tax. Requiring proof-of-work would also work directly against this mechanism's purpose: it would
slow down a genuine responder's ability to claim a life-safety event they're about to act on, to
buy protection against a threat proof-of-work can't stop anyway. The only protection here is a
signed identity's accountability -- weaker than proof-of-work in some ways, stronger in others
(a `PeerIdentity` behind a bad-faith acknowledgment is at least traceable after the fact, which
no amount of anonymous proof-of-work ever offers).

## The mechanism

`UnsignedResponderAcknowledgment { responder_peer_id, responder_public_key, corroboration_nonce,
active, acknowledged_at }`, signed under `OAG-MESH:RESPONDER_ACKNOWLEDGMENT:v1:`.
`corroboration_nonce` identifies the event being acknowledged -- the stable value shared by every
independent report of the same real event, not any one report's random `event_id` -- and is not
checked against any `AnonymousEventLog` at verify time, the same "verify doesn't check
cross-references" posture every other mechanism here has (a `ClaimReport`'s `claim_id`, a
`BridgeDeclaration`'s cluster name).

There is no separate "retract" message. A responder standing down signs a fresh acknowledgment
with `active: false` instead -- `ResponderAcknowledgmentLog` keeps the single most recent
acknowledgment per `(corroboration_nonce, responder_peer_id)` pair, replacing on `add` only when
the incoming `acknowledged_at` is at least as recent as what's already recorded (so an
out-of-order, retried delivery of a stale claim can't silently undo a more recent stand-down).
`active_responders_for(nonce)` is the one query this exists to answer: every responder whose most
recent acknowledgment for that nonce is still `active`.

`GET /oag-mesh/v1/responder-acknowledgment/{corroboration_nonce}` exposes this read, same
node-local-only, no-auth scope as every other `GET` endpoint in this crate.
`POST /oag-mesh/v1/responder-acknowledgment` records a submission -- no proof-of-work field in
the wire shape, unlike `BridgeDeclarationSubmission`/`ClaimReportSubmission`/
`MembershipAttestationSubmission`.

Persistence (`spec/08-persistence.md`) and pull-based anti-entropy (`spec/10-anti-entropy.md`)
both cover this store the same way as the other four: `snapshot`/`from_snapshot`/
`merge_snapshot`, a `responder_acknowledgments.json` file, and a
`GET /oag-mesh/v1/sync/responder-acknowledgments` pull endpoint. `merge_snapshot` applies the
same freshness rule `add` does per `(corroboration_nonce, responder_peer_id)` pair, so merging is
idempotent and cannot regress a more recent stand-down into a stale claim.

## What this explicitly is not

- **Not a lock, not exclusive.** Two different responders can both acknowledge the same event as
  `active`, and nothing here treats that as a conflict -- the query answers "who's claiming to
  handle this," not "who's authorized to." Real-world deduplication is still a human or
  out-of-band process decision; this mechanism only gives it the shared view to decide from.
- **An active acknowledgment is a claim, not a guarantee.** Nothing verifies a responder claiming
  to handle an event is actually, genuinely doing so. A responder could acknowledge and never
  follow through, and nothing here would know.
- **A real griefing vector, bounded but not eliminated.** Because there's no proof-of-work and
  no cost to acknowledging, a bad-faith (or compromised) `PeerIdentity` could acknowledge every
  event in a region as `active` specifically to suppress real responders who check first and
  stand down, believing it's already handled. A per-identity fixed-window rate limit now bounds
  that: `RESPONDER_ACK_RATE_LIMIT_MAX` acknowledgments per `PeerId` per
  `RESPONDER_ACK_RATE_LIMIT_WINDOW` (60 per 60s by default), returning `429` with `Retry-After`
  once the window is full. That is a rate limit, not a reputation system or an allowlist -- a
  griefer is throttled to the cap, not stopped, and a genuine responder who acknowledges more
  than the cap in a window is throttled too. The defaults are a starting point, not a derived
  value; a real deployment should tune them to its own responder traffic. Identity accountability
  still matters after the fact, and the limiter is in-memory only, so a restart resets it.
- **No notification.** Same as `spec/11-responder-search.md`'s own limits: nothing pushes an
  acknowledgment to anyone. A responder has to already be polling `GET
  .../responder-acknowledgment/{nonce}` (or re-running a search) to see one.
- **Node-local only, no auth** -- same posture, same caveats, as every other `GET` endpoint in
  this crate.

## Tests

`crates/oag-mesh/src/responder.rs` (11 unit tests): sign/verify round trip; tampered-field/
mismatched-key/stale-timestamp rejection; an invalid acknowledgment is never recorded;
`active_responders_for` lists only currently-active claims, excluding a responder who stood down;
a fresh acknowledgment from the same responder replaces their prior one; an out-of-order stale
acknowledgment does not regress a newer one already recorded; two different responders can both
claim the same event; a snapshot round-trips through `from_snapshot`; `merge_snapshot` keeps
whichever of a local and incoming entry is more recent per responder, in both directions.
`crates/oag-mesh/src/transport.rs` adds 5 more: a pushed acknowledgment (no proof-of-work
required) is recorded and readable back over `GET .../responder-acknowledgment/{nonce}`; a
tampered one is rejected over the wire; `broadcast_responder_acknowledgment` reaches every
configured peer; querying an unknown nonce returns an empty list rather than an error; and the
per-identity rate limiter rejects a burst from one identity with `429` while a different identity
is unaffected. Plus 1 more in the shared persistence/anti-entropy round-trip tests (`spec/08`,
`spec/10`), extended to cover this fifth store alongside the other four. The fixed-window limiter
itself gets 3 unit tests in `crates/oag-mesh/src/rate_limit.rs`.
