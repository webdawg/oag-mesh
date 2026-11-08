# Responder-Side Event Search

**Source**: `crates/oag-mesh/src/anonymous_event.rs` (`EventFilter`, `EventKindCategory`,
`AnonymousEventLog::search`), `crates/oag-mesh/src/transport.rs`
(`GET /oag-mesh/v1/anonymous-event/search`).

**This is not "dispatch-to-a-responder."** `spec/03-anonymous-event-rfc.md`'s "Reaching a
responder" open question asks something much larger: how does a report reach someone who can act
on it, without identifying either the reporter or the responder? This file answers a much
narrower, deliberately bounded slice of that: a way to **find** events relevant to a responder
inside a node's own already-public, already-anonymous log. It does not notify anyone, does not
know who any responder is, does not deliver anything, and does not prevent two responders from
duplicating the same response. Read the rest of this file as "the discovery primitive a real
dispatch system could be built on top of," not as dispatch itself.

## The mechanism

`EventFilter { kind, min_severity, location_prefix, since }` -- every field optional, `None`
meaning "no constraint on this dimension":

- `kind: Option<EventKindCategory>` -- `EventKindCategory` mirrors `EventKind` without its
  `MedicalEmergencyKind` payload, so a filter can ask "any `MedicalEmergency`, regardless of
  sub-kind" without needing to enumerate every sub-kind as it grows.
- `min_severity: Option<Severity>` -- matches events at least this urgent. `Severity` now
  derives `PartialOrd`/`Ord` in declaration order (`Low < Medium < High < Critical`) specifically
  to make this comparison meaningful; this is the only place in the crate that orders severity
  rather than just comparing it for equality.
- `location_prefix: Option<String>` -- a plain string prefix match on `CoarseLocation`'s
  geohash-style string, so a responder covering one region searches by that region's prefix.
- `since: Option<i64>` -- matches `observed_at >= since` (unix seconds); only as precise as
  `observed_at` already is, given it's rounded to `TIME_ROUNDING_SECONDS`.

`AnonymousEventLog::search(filter)` applies this across every recorded event, regardless of
nonce. `GET /oag-mesh/v1/anonymous-event/search?kind=MedicalEmergency&min_severity=High&...`
exposes it over the wire -- query-string parameters map directly onto `EventFilter`'s fields, all
optional, an empty query string returning every event the node has.

This adds **no new identifying surface**. Every field a filter can match on was already part of
`AnonymousEvent`'s own schema (`spec/03`'s closed-enum, coarsened-location-and-time constraints
still apply unchanged) -- search only narrows what's already there, it cannot reveal anything an
`AnonymousEvent` didn't already carry.

## What this explicitly is not (yet)

- **Not dispatch.** Stated above, worth repeating precisely because the filename and the
  surrounding feature could be misread as more than it is: nobody is identified, nothing is
  pushed, nothing is delivered, nothing is claimed. A responder has to already know to poll this
  endpoint; nothing here tells them to.
- **No responder identity or subscription.** There is no concept of "a responder" anywhere in
  this crate -- no registration, no address, no notification preference. Search is anonymous and
  stateless on both sides: querying it reveals nothing about who's asking, and it remembers
  nothing about who asked.
- **Claim-to-avoid-duplicate-response now exists (`spec/12-responder-acknowledgment.md`), but
  it's advisory, not a lock.** A responder can sign a `ResponderAcknowledgment` saying "I am
  handling this," queryable alongside a search, so a second responder checking first can stand
  down -- but nothing *enforces* that, nothing verifies the claim reflects real action, and a
  per-identity rate limit (`spec/12`) only bounds how fast a bad-faith identity can acknowledge
  events it never intends to act on, not whether it can. See `spec/12`'s own "what this
  explicitly is not" for that stated plainly.
- **Node-local only, same as every other `GET` endpoint in this crate.** Search answers from
  whatever this one node's `AnonymousEventLog` holds -- its own received submissions, plus
  whatever `spec/10-anti-entropy.md`'s pull-based sync has merged in from peers. It does not fan
  out to the wider mesh on a search request.
- **No auth, same as every other `GET` endpoint in this crate.** Anyone who can reach the listen
  address can run any search. Whether that's acceptable depends on what's actually flowing
  through a real deployment's event log -- unchanged from the posture `spec/04-transport.md`
  already states for its other read endpoints.
- **Pagination and a default result bound now exist, but they are a ceiling, not a dispatch
  mechanism.** `limit`/`offset` page through a search, `limit` defaults to
  `DEFAULT_EVENT_SEARCH_LIMIT` (100) and is clamped to `MAX_EVENT_SEARCH_LIMIT` (1000), and the
  response carries `total` so a caller can page through a large result set. A caller can still
  page the entire log, one page at a time -- the bound is on one response, not on total access,
  and the endpoint remains node-local, no-auth, and unauthenticated.

## Tests

`crates/oag-mesh/src/anonymous_event.rs` adds 4 unit tests: an all-`None` filter returns every
event; a `kind` filter matches `MedicalEmergency` regardless of its `MedicalEmergencyKind`
payload while excluding other kinds; a `min_severity` filter keeps only events at least that
urgent; `location_prefix` and `since` each narrow results independently.
`crates/oag-mesh/src/transport.rs` adds 3 integration tests, over real HTTP round trips: searching
by `kind` and separately by `min_severity` each return only the matching event, while an empty
query string returns both; `limit`/`offset` page through a five-event result set and report the
`total` across pages; and the default limit bounds a response to `DEFAULT_EVENT_SEARCH_LIMIT`
while a request for more than `MAX_EVENT_SEARCH_LIMIT` is clamped to it.
