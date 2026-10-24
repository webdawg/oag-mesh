# RFC: Anonymous Event Sharing for Life-Saving Actions

**Status: schema, local corroboration bookkeeping, a proof-of-work anti-spam/anti-replay check,
and a real transport (`spec/04-transport.md`) are all implemented. Dispatch-to-a-responder is
not designed. Proof-of-work raises the cost of spam/self-replay; it does not, and cannot, stop a
well-resourced attacker — see "Anti-spam and anti-replay" below for exactly what it does and
doesn't achieve.**

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

pub struct ProofOfWork { pub nonce: u64 }  // see "Anti-spam and anti-replay" below
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

**A sharper version of the same problem, found and fixed, not just theorized**: before
proof-of-work existed, `corroboration_for` was literally `Vec::len()` on whatever was pushed
under a nonce, with *zero* deduplication of any kind. One actor submitting the identical event
(or a trivially varied one — only `event_id` needs to differ, and that field is supposed to vary
per report anyway) under one nonce, repeatedly, inflated its own corroboration count for free.
That's not a theoretical spam concern, it's a direct break of the one signal this mechanism
exists to provide. See "Anti-spam and anti-replay" below for the fix.

## Anti-spam and anti-replay: escalating proof-of-work

`AnonymousEventLog::record` now requires a `ProofOfWork { nonce: u64 }` alongside the event.
`ProofOfWork::solve`/the log's internal check work the same way Hashcash does: a submission is
only accepted if `blake3("OAG-MESH:ANONYMOUS_EVENT_POW:v1:" || event fields || pow.nonce)` has at
least some number of leading zero bits — found by brute-force search, so producing a valid one
costs real, unavoidable computation, without the submission needing to prove who's making it.

**The difficulty escalates per additional report under the same nonce**
(`difficulty_bits_for_report_number`: `BASE_DIFFICULTY_BITS` (16) for the first report under a
fresh nonce, `+ DIFFICULTY_STEP_BITS` (4) for each one after that) — this is the direct fix for
the self-replay-inflation problem above. A handful of genuinely independent witnesses reporting
the same real event over time each pay only a modest, roughly-fixed cost (whatever the current
count happens to require when they submit). One actor trying to inflate a *single* event's own
corroboration count alone faces cost that grows exponentially with each additional fake report —
4 extra bits of required difficulty means roughly 16× more expected work per step.

**What this does not achieve, stated as plainly as everywhere else in this document uses "not
solved" or "flagged, not resolved"**: proof-of-work does not identify or exclude anyone. A
well-resourced attacker (a botnet, dedicated hardware) mints valid proofs exactly as fast as
anyone else, just at a real dollar cost instead of a free one. This mechanism raises the floor
from "free" to "costs something, and costs more the more you try to inflate one event alone" — it
does not raise it to "impossible," and claiming otherwise would overstate what a schema-level,
identity-free check can ever guarantee.

## Open questions (genuinely unresolved, flagged rather than guessed at)

- **Proof-of-work difficulty is untuned.** `BASE_DIFFICULTY_BITS`/`DIFFICULTY_STEP_BITS` are
  reasonable-sounding defaults, not derived from any real deployment's actual hardware/traffic
  profile. A real deployment under real load should expect to retune these, and there's no
  mechanism here for a network to agree on or adjust a shared difficulty over time.
- **No defense against a well-resourced attacker.** Named plainly in "Anti-spam and anti-replay"
  above — proof-of-work raises cost, it does not stop anyone with enough compute.
- **Transport-level anonymity.** The payload carries no identifying field and now costs real
  work to submit, but a plain HTTP POST (`spec/04-transport.md`,
  `POST /oag-mesh/v1/anonymous-event`) still reveals the submitting connection's source IP to the
  receiving peer — proof-of-work does nothing about this, it's an orthogonal property. The same
  unresolved gap as the base project's own "never ending morphing encryption"/traffic-analysis-
  resistance entry in `spec/22-future-work.md` there. Still not solved here.
- **Reaching a responder.** A `MedicalEmergency` report is only useful for "life-saving actions"
  if it reaches someone who can act on it — and *that* delivery mechanism needs its own answer for
  "how does this happen without identifying the reporter or the responder," which this RFC does
  not attempt.
- **Retention/expiry.** Nothing here specifies how long an `AnonymousEventLog` keeps old reports,
  or when/how an `AllClear` actually removes a resolved situation from view rather than just
  adding one more entry under the same nonce.

## Tests

`crates/oag-mesh/src/anonymous_event.rs` (9 unit tests): a well-formed event validates; an
over-precise location is rejected; an unrounded timestamp is rejected; an invalid event is never
recorded into the log (checked before any proof-of-work is even considered); independent reports
sharing a `corroboration_nonce` corroborate each other while an unrelated nonce stays separate; a
`MedicalEmergency(HeartIssue)` report validates and round-trips through the log correctly; a
report with no proof-of-work is rejected; required difficulty escalates with each additional
report under one nonce (and a proof solved for an earlier, lower difficulty is correctly rejected
against the new, higher one); a proof-of-work solved for one event cannot be reused for a
different one. `crates/oag-mesh/src/transport.rs` adds one more over the wire: a submission with
insufficient proof-of-work is rejected with `400`, never recorded.
