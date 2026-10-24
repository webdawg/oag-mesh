# RFC: Anonymous Event Sharing for Life-Saving Actions

**Status: schema and local corroboration bookkeeping implemented (`crates/oag-mesh/src/
anonymous_event.rs`). Transport, anti-spam/sybil resistance, and dispatch-to-a-responder are not
designed yet — this RFC defines the one thing it can define precisely today: the wire format,
and the hard constraints that keep it anonymous.**

## Why this is a separate mechanism from `spec/02-cluster-nesting.md`

`spec/02`'s `BridgeDeclaration` is signed by a real, persistent `PeerIdentity` on purpose — it's a
durable topology claim that benefits from accountability (who said this cluster belongs here, so a
bad-faith claim can be traced back). An anonymous event report is the opposite case on purpose:
"I saw this" should carry *no* information that could identify who's reporting it, because the
report itself may be sensitive (a reporter's location at the moment of reporting, for one) and
because requiring identity would chill exactly the reporting this mechanism exists to enable.

**Do not sign an `AnonymousEvent` with a `PeerIdentity`.** Doing so would defeat the entire point:
any public key that signs *anything* else non-anonymous anywhere (a `BridgeDeclaration`, a base-
project cluster declaration, a transfer receipt) links back to a real operator. This file's schema
has no signature field at all for exactly this reason.

## The strict event definition

```rust
pub enum EventKind {
    Sighting,          // someone/something matching a life-safety concern -- no name/photo/description
    HazardObserved,     // about the environment (fire, flood, collapse, ...), not a specific person
    MedicalEmergency(MedicalEmergencyKind),  // closed sub-kind for routing, no identifying detail beyond it + Severity
    ResourceNeed,        // water, shelter, medical supplies needed at a location -- not immediate danger
    AllClear,            // CONVENTION ONLY: signals a nonce's situation has resolved -- see below, nothing enforces this
}

// Closed sub-classification of MedicalEmergency, for routing to the right kind of medical team --
// add more variants here, never a free-text field, when another specific category is needed.
pub enum MedicalEmergencyKind {
    HeartIssue,  // a suspected cardiac event
}

// The base triage signal, since the rest of the payload deliberately carries no identifying
// detail to triage on instead.
pub enum Severity {
    Low,       // worth recording, nothing to act on right now
    Medium,    // should be looked at, not an immediate emergency
    High,      // needs a response soon -- real but not immediately life-threatening
    Critical,  // immediate danger to life -- not enforced to require MedicalEmergency, see below
}

pub struct CoarseLocation(pub String);  // geohash-style, max 6 chars (MAX_PRECISION_CHARS)

pub struct AnonymousEvent {
    pub event_id: String,            // random, not derived from reporter identity
    pub kind: EventKind,
    pub severity: Severity,
    pub observed_at: i64,            // unix seconds, rounded to the nearest 300 (5 minutes)
    pub location: CoarseLocation,
    pub corroboration_nonce: String, // computed identically by independent observers of the same real event
}
```

**The closed `EventKind` enum is the schema's main anonymity safeguard, not an afterthought.**
There is no free-text field anywhere in `AnonymousEvent`. The single easiest way for this
mechanism to become a person-tracking tool instead of a life-safety one would be a "description"
or "details" string — there isn't one, and there must not be one added later without re-reading
this document's reasoning.

**Location and time are deliberately coarsened**, not just as a style choice but because either
one, precise, is itself identifying information: an exact GPS coordinate narrows a reporter to a
specific building; an exact timestamp can be correlated against other metadata (e.g. network-level
timing logs) to the same effect. `AnonymousEvent::validate()` enforces both bounds structurally —
an over-precise report is rejected, not silently accepted.

## What each event kind means, precisely

- **`Sighting`**, **`HazardObserved`**, **`ResourceNeed`** describe exactly what their name says
  and nothing more — there is no field anywhere that could add identifying detail about a person
  (see the closed-enum rationale above).
- **`MedicalEmergency(MedicalEmergencyKind)`** means "someone needs urgent attention at this
  location." `MedicalEmergencyKind` is a closed sub-classification letting a response get routed
  to the right kind of medical team — currently just `HeartIssue` (a suspected cardiac event);
  add more variants there, never a free-text field, when another specific category is needed.
  Beyond that sub-kind and `Severity`, it carries no information about who the person is — the
  same "no identifying detail" constraint as `Sighting`, for the same reason.
- **`AllClear` is a convention, not an enforced effect.** A reporter uses it to signal that the
  situation identified by a given `corroboration_nonce` has resolved. Nothing in
  `AnonymousEventLog` currently acts on this: `record()` stores an `AllClear` exactly like any
  other event under the same nonce — it does not remove or mark prior reports as resolved. A
  consumer reading `reports_for(nonce)` is responsible for noticing an `AllClear` in the list and
  treating it as superseding what came before. This is the same gap as this document's
  "Retention/expiry" open question below, stated here precisely rather than left implicit.
- **`Severity` is the base triage signal**, since the rest of the payload deliberately carries no
  identifying detail to triage on instead: `Low` (worth recording, nothing to act on right now),
  `Medium` (should be looked at, not an emergency), `High` (needs a response soon, real but not
  immediately life-threatening), `Critical` (immediate danger to life).
- **The pairing of `EventKind` and `Severity` is not enforced.** A `MedicalEmergency` reported as
  `Low` severity, or a `HazardObserved` reported as `Critical`, are both accepted by
  `AnonymousEvent::validate()` — the schema does not require, say, every `MedicalEmergency` to
  carry `Critical` severity. Enforcing that would mean encoding, in software, what counts as
  "immediately life-threatening" across every real-world reporting context this schema might be
  used in — deliberately left to the reporter's own judgment rather than guessed at here.

## Corroboration without identity

`spec/02`'s `MeshTree` corroborates by counting *distinct signing peers* asserting the same fact.
That signal doesn't exist here — there's no identity to be distinct. Instead, `corroboration_nonce`
must be a value any independent observer of the *same real event* would compute identically (e.g.
a hash of `(kind, coarse location, coarse time window)`), so that multiple unrelated reports of the
same real event collide on the same nonce and multiple *reports* under that nonce is the
corroboration signal. `AnonymousEventLog::corroboration_for`/`reports_for` do this bookkeeping.

A nonce the *reporter* picks freely (rather than deriving deterministically from the observable
facts of the event) would make every report "unique" and defeat corroboration entirely — this is
a real failure mode a transport/client implementation must guard against, not something the
schema itself can enforce.

## Open questions (genuinely unresolved, flagged rather than guessed at)

- **Anti-spam/sybil resistance with no identity.** The classic problem with anonymous reporting:
  nothing here stops one actor from submitting many fabricated reports. Proof-of-work per report,
  a resource-bounded submission channel, or accepting the risk and relying on corroboration
  (one report alone proves nothing; many independent ones are harder to fabricate) are all named,
  none designed.
- **Transport-level anonymity.** The payload itself carries no identifying field, but relaying it
  through any real network (this layer's own, or the base project's `oag-sync`/`oag-reticulum`)
  can still leak sender identity at the connection/timing level even with a clean payload — the
  same unresolved gap as the base project's own "never ending morphing encryption"/traffic-
  analysis-resistance entry in `spec/22-future-work.md` there. Not solved here either.
- **Reaching a responder.** A `MedicalEmergency` report is only useful for "life-saving actions"
  if it reaches someone who can act on it — and *that* delivery mechanism needs its own answer for
  "how does this happen without identifying the reporter or the responder," which this RFC does
  not attempt.
- **Retention/expiry.** Nothing here specifies how long an `AnonymousEventLog` keeps old reports,
  or when/how an `AllClear` actually removes a resolved situation from view rather than just
  adding one more entry under the same nonce.

## Tests

`crates/oag-mesh/src/anonymous_event.rs` (6 unit tests): a well-formed event validates; an
over-precise location is rejected; an unrounded timestamp is rejected; an invalid event is never
recorded into the log; independent reports sharing a `corroboration_nonce` corroborate each other
while an unrelated nonce stays separate; a `MedicalEmergency(HeartIssue)` report validates and
round-trips through the log correctly.
