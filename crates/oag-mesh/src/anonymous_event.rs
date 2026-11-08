//! Strictly-defined, identity-stripped event reports for life-saving actions ("SAW THIS EVENT")
//! -- a deliberately different trust/privacy model from `bridge.rs`'s signed
//! `BridgeDeclaration`s. A `BridgeDeclaration` is signed by a real `PeerIdentity` because it's
//! making a durable claim about network topology that benefits from accountability; an
//! `AnonymousEvent` is the opposite on purpose: no signature by a persistent identity, no
//! precise location or time, and a closed set of event kinds that structurally cannot carry an
//! identifying description of a specific person. This file defines the strict schema, the
//! proof-of-work anti-spam/anti-replay check, and local corroboration bookkeeping -- it does not
//! define a transport (`spec/04-transport.md` does) and does not solve network-level anonymity
//! (see that file's own open questions).

use serde::{Deserialize, Serialize};

/// A closed, deliberately narrow set of what can be reported. Adding a free-text "description"
/// field here would be the single easiest way for this mechanism to become a person-tracking
/// tool instead of a life-safety one -- there isn't one, on purpose, and there must not be one
/// added later without re-reading this comment.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventKind {
    /// Something or someone matching a life-safety concern was sighted (e.g. a missing hiker, a
    /// search-and-rescue target, a lost child). Carries no name, photo, or physical description
    /// of any person -- identifying a specific individual needs a different, identity-
    /// accountable mechanism, not this one.
    Sighting,
    /// A hazard was observed (fire, flood, structural collapse, downed power line, ...) --
    /// about the environment, not about a specific person.
    HazardObserved,
    /// Someone needs urgent medical attention at this location. `MedicalEmergencyKind` is a
    /// closed sub-classification for routing to the right kind of medical team -- still no
    /// information about who they are beyond that, the same "no identifying detail" constraint
    /// as `Sighting`, for the same reason.
    MedicalEmergency(MedicalEmergencyKind),
    /// A need for a resource at a location (water, shelter, medical supplies) during a
    /// disaster/emergency response -- not urgent in the immediate-danger sense `MedicalEmergency`
    /// or a `Critical` `HazardObserved` is, but still something a responder should act on.
    ResourceNeed,
    /// A *convention*, not an enforced effect: reporters use this to signal that the situation
    /// identified by this event's `corroboration_nonce` has resolved or ended. Nothing in this
    /// crate currently acts on it -- `AnonymousEventLog::record` stores it exactly like any other
    /// event under the same nonce, it does not remove or mark prior reports resolved. A consumer
    /// reading `reports_for(nonce)` is responsible for noticing an `AllClear` and treating it as
    /// superseding what came before. See this RFC's "Open questions" (retention/expiry) --
    /// deliberately not implemented yet, not an oversight.
    AllClear,
}

/// `EventKind` without its `MedicalEmergencyKind` payload -- lets a search/filter (`EventFilter`)
/// ask "any `MedicalEmergency`, regardless of sub-kind" without needing to enumerate every
/// `MedicalEmergencyKind` variant whenever a new one is added. Exists only for filtering; nothing
/// here ever stores one of these in place of a real `EventKind`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventKindCategory {
    Sighting,
    HazardObserved,
    MedicalEmergency,
    ResourceNeed,
    AllClear,
}

impl EventKindCategory {
    fn matches(&self, kind: &EventKind) -> bool {
        matches!(
            (self, kind),
            (EventKindCategory::Sighting, EventKind::Sighting)
                | (EventKindCategory::HazardObserved, EventKind::HazardObserved)
                | (EventKindCategory::MedicalEmergency, EventKind::MedicalEmergency(_))
                | (EventKindCategory::ResourceNeed, EventKind::ResourceNeed)
                | (EventKindCategory::AllClear, EventKind::AllClear)
        )
    }
}

/// What `AnonymousEventLog::search` filters by -- every field is optional and `None` means "no
/// constraint on this dimension," so an all-`None` filter matches every event (equivalent to no
/// filter at all). Deliberately only ever narrows what's already in the log; it cannot reveal
/// anything beyond what an `AnonymousEvent`'s own fields already carry (no new identifying
/// surface, same constraint the rest of this schema holds to).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventFilter {
    pub kind: Option<EventKindCategory>,
    /// Matches events with severity *at least* this urgent (`Severity`'s derived `Ord`, so
    /// `High` also matches a `Critical` event).
    pub min_severity: Option<Severity>,
    /// A plain string prefix on `CoarseLocation`'s geohash-style string -- a responder covering
    /// a region searches by that region's geohash prefix, not an exact match.
    pub location_prefix: Option<String>,
    /// Matches events with `observed_at >= since` (unix seconds) -- a recency bound, not a
    /// precise one given `observed_at` is already rounded to `TIME_ROUNDING_SECONDS`.
    pub since: Option<i64>,
    /// Whether to include events under a nonce that has since been resolved by an `AllClear`.
    /// Defaults to `false` -- a resolved situation is removed from view, not just appended to.
    #[serde(default, deserialize_with = "deserialize_bool_from_str_or_bool")]
    pub include_resolved: bool,
}

/// Deserializes a boolean from either a JSON boolean or a query-string `"true"`/`"false"`.
/// `serde_urlencoded` hands a `#[serde(flatten)]` field to a `Content` buffer as a string, so a
/// plain `bool` fails there; this accepts both shapes.
fn deserialize_bool_from_str_or_bool<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct BoolOrStr;
    impl<'de> serde::de::Visitor<'de> for BoolOrStr {
        type Value = bool;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a boolean or a string \"true\"/\"false\"")
        }
        fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<bool, E> {
            Ok(value)
        }
        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<bool, E> {
            match value.to_ascii_lowercase().as_str() {
                "true" | "1" => Ok(true),
                "false" | "0" => Ok(false),
                _ => Err(E::custom("expected \"true\" or \"false\"")),
            }
        }
    }
    deserializer.deserialize_any(BoolOrStr)
}

impl EventFilter {
    /// Whether `event` passes every constraint this filter sets. `pub(crate)` so the dispatch
    /// layer (`crate::dispatch`) can route events to matching responder subscriptions.
    pub(crate) fn matches(&self, event: &AnonymousEvent) -> bool {
        if let Some(kind) = &self.kind {
            if !kind.matches(&event.kind) {
                return false;
            }
        }
        if let Some(min_severity) = self.min_severity {
            if event.severity < min_severity {
                return false;
            }
        }
        if let Some(prefix) = &self.location_prefix {
            if !event.location.0.starts_with(prefix.as_str()) {
                return false;
            }
        }
        if let Some(since) = self.since {
            if event.observed_at < since {
                return false;
            }
        }
        true
    }
}

/// Closed sub-classification for `EventKind::MedicalEmergency`, so a response can be routed to
/// the right kind of medical team without any free-text description -- the same "no identifying
/// detail, closed enum only" constraint as the rest of this schema. Add more variants here, not
/// a free-text field, when another specific category is needed.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MedicalEmergencyKind {
    /// A suspected cardiac event (heart attack, cardiac arrest, ...) -- for routing to a medical
    /// team equipped to respond to one specifically.
    HeartIssue,
}

/// How urgently a report needs a response -- the base signal a consumer triages on, since there
/// is no identifying detail in the rest of the payload to go on. Derives `PartialOrd`/`Ord` in
/// declaration order (`Low < Medium < High < Critical`) so `EventFilter::min_severity` can ask
/// "at least this urgent" -- a responder's own triage threshold, not a change to how severity is
/// assigned or interpreted anywhere else.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Worth recording, nothing to act on right now (e.g. a hazard that's already contained).
    Low,
    /// Should be looked at, not an immediate emergency (e.g. a `ResourceNeed` with no urgent
    /// time pressure).
    Medium,
    /// Needs a response soon -- a real but not immediately life-threatening situation.
    High,
    /// Immediate danger to life. The only level that should ever accompany `MedicalEmergency` in
    /// a well-formed report, though this schema does not enforce that pairing -- see "Open
    /// questions" in this RFC for why (enforcing it would mean defining, in software, what
    /// "immediately life-threatening" means across every reporting context, which this schema
    /// deliberately leaves to the reporter's own judgment rather than guessing at).
    Critical,
}

/// A deliberately imprecise, geohash-style location string. `MAX_PRECISION_CHARS` bounds how
/// *long* (i.e. how precise) a geohash may be -- short enough to be locally useful for
/// dispatching help, too short to pinpoint an individual building.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoarseLocation(pub String);

impl CoarseLocation {
    /// A geohash this short covers roughly a city-block-to-small-town sized area (actual ground
    /// size depends on latitude) -- the ceiling on precision this schema allows.
    pub const MAX_PRECISION_CHARS: usize = 6;
}

/// Unix seconds must be rounded to the nearest multiple of this -- a precise timestamp could
/// otherwise act as a correlation handle against other metadata (e.g. network-level timing)
/// that helps re-identify the reporter.
pub const TIME_ROUNDING_SECONDS: i64 = 300; // 5 minutes

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnonymousEvent {
    /// A random identifier, *not* derived from any reporter identity -- lets this exact report
    /// be referenced later (e.g. by a matching `AllClear`) without naming who sent it.
    pub event_id: String,
    pub kind: EventKind,
    pub severity: Severity,
    pub observed_at: i64,
    pub location: CoarseLocation,
    /// Lets independent reports of the *same* real-world event be matched/merged -- this
    /// mechanism's entire corroboration signal, since there is no peer id to count distinct
    /// reporters by. Must be computed identically by anyone observing the same real event (e.g.
    /// a hash of `(kind, coarse location, coarse time window)`) -- a value the reporter picks
    /// freely would make every report "unique" and defeat corroboration entirely.
    pub corroboration_nonce: String,
}

#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
pub enum AnonymousEventError {
    #[error("location is more precise than the maximum {0} characters allowed")]
    LocationTooPrecise(usize),
    #[error("observed_at is not rounded to the nearest {0} seconds")]
    TimeNotRounded(i64),
    #[error("proof of work does not meet the required {required_bits} leading zero bits for this report")]
    InsufficientProofOfWork { required_bits: u32 },
}

/// Computational proof bound to one specific submission -- the one anti-spam/anti-replay
/// mechanism compatible with this schema's "no identity" guarantee: it costs real work to
/// produce, without requiring anyone to prove who they are. It does **not**, and cannot, stop a
/// well-resourced attacker -- a botnet mints proof-of-work exactly as fast as anyone else. What
/// it actually buys is in `AnonymousEventLog::required_difficulty_bits`'s escalation: the first
/// report under a nonce is cheap (so a lone genuine witness isn't deterred), but each
/// *additional* report under the same nonce costs real, escalating work -- raising the cost of
/// one actor inflating a single event's own corroboration count from free (today, before this
/// change) to exponentially expensive, while a handful of genuinely independent reporters
/// trickling in over time each still pays only a modest, fixed increment.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofOfWork {
    pub nonce: u64,
}

/// The difficulty (in required leading zero bits of `proof_of_work_hash`) for the very first
/// report under a fresh `corroboration_nonce`. Tuned to be a real, felt cost on ordinary
/// hardware without being a real barrier to one honest witness -- not derived from any formal
/// economic analysis; a deployment under real load should expect to retune this.
pub const BASE_DIFFICULTY_BITS: u32 = 16;

/// How much the required difficulty grows for each additional report already recorded under the
/// same `corroboration_nonce`. See `ProofOfWork`'s own doc comment for why this escalates rather
/// than staying fixed.
pub const DIFFICULTY_STEP_BITS: u32 = 4;

/// The difficulty required for what would be the `existing_reports`-th report (0-indexed) under
/// one nonce -- the 1st report (`existing_reports == 0`) needs `BASE_DIFFICULTY_BITS`; each one
/// after that needs `DIFFICULTY_STEP_BITS` more.
pub fn difficulty_bits_for_report_number(existing_reports: usize) -> u32 {
    BASE_DIFFICULTY_BITS + (existing_reports as u32) * DIFFICULTY_STEP_BITS
}

/// Binds the proof to this *specific* event's content -- a solved `ProofOfWork` for one event
/// cannot be reused for a different one (different `event_id`/`corroboration_nonce`/etc. changes
/// the hash entirely, so a previously-found `nonce` almost certainly no longer satisfies any
/// real difficulty threshold).
fn proof_of_work_hash(event: &AnonymousEvent, pow: &ProofOfWork) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"OAG-MESH:ANONYMOUS_EVENT_POW:v1:");
    hasher.update(event.event_id.as_bytes());
    hasher.update(&event.observed_at.to_le_bytes());
    hasher.update(event.location.0.as_bytes());
    hasher.update(event.corroboration_nonce.as_bytes());
    hasher.update(&pow.nonce.to_le_bytes());
    hasher.finalize()
}

fn leading_zero_bits(hash: &blake3::Hash) -> u32 {
    let mut count = 0;
    for &byte in hash.as_bytes() {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

impl ProofOfWork {
    /// The client-side work: searches for a `nonce` whose `proof_of_work_hash` has at least
    /// `difficulty_bits` leading zero bits. Exposed publicly so a real submitting client (or a
    /// test) can actually produce a valid submission, not just so a receiver can check one.
    pub fn solve(event: &AnonymousEvent, difficulty_bits: u32) -> Self {
        let mut nonce = 0u64;
        loop {
            let candidate = ProofOfWork { nonce };
            if leading_zero_bits(&proof_of_work_hash(event, &candidate)) >= difficulty_bits {
                return candidate;
            }
            nonce += 1;
        }
    }

    fn satisfies(&self, event: &AnonymousEvent, difficulty_bits: u32) -> bool {
        leading_zero_bits(&proof_of_work_hash(event, self)) >= difficulty_bits
    }
}

impl AnonymousEvent {
    /// Checks the two structural anonymity constraints this schema can actually enforce by
    /// itself: location coarseness and time rounding. This does **not**, and cannot, check
    /// "does this payload contain identifying information" in general -- that depends on what a
    /// caller puts in `corroboration_nonce`, not on anything a type system alone can guarantee.
    /// Does not check proof-of-work either -- that's `AnonymousEventLog::record`'s job, since the
    /// required difficulty depends on how many reports already exist for this event's nonce, a
    /// fact only the log knows. See `spec/03-anonymous-event-rfc.md`'s open questions for what's
    /// still unresolved (transport-level anonymity, and the real limits of proof-of-work against
    /// a well-resourced attacker).
    pub fn validate(&self) -> Result<(), AnonymousEventError> {
        if self.location.0.len() > CoarseLocation::MAX_PRECISION_CHARS {
            return Err(AnonymousEventError::LocationTooPrecise(CoarseLocation::MAX_PRECISION_CHARS));
        }
        if self.observed_at % TIME_ROUNDING_SECONDS != 0 {
            return Err(AnonymousEventError::TimeNotRounded(TIME_ROUNDING_SECONDS));
        }
        Ok(())
    }
}

/// Collects `AnonymousEvent`s, grouped by `corroboration_nonce` -- the anonymous-reporting
/// equivalent of `bridge::MeshTree`'s distinct-peer corroboration count, except the signal here
/// is "how many independently-submitted reports share this nonce," since there's no identity to
/// count distinctness by.
///
/// Derives `Serialize`/`Deserialize` directly (no snapshot-type indirection, unlike
/// `bridge::MeshTree`/`corroboration::ClaimCorroboration`) because `AnonymousEvent` carries no
/// `PeerId` at all -- identity-stripped by design -- so there's nothing here that needs a
/// string round-trip to serialize. See `persistence::save_json`/`load_json` for how this gets
/// written to and read from disk.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AnonymousEventLog {
    events: std::collections::HashMap<String, Vec<AnonymousEvent>>,
    /// Nonces that have since been resolved by an `AllClear` -- the situation is removed from
    /// view (`search` hides them by default) rather than just appended to. The events
    /// themselves are kept, so the record is not destroyed.
    resolved: std::collections::HashSet<String>,
    /// Monotonic version, bumped whenever `events` or `resolved` actually changes -- the heads
    /// check in `transport::pull_and_merge`; see `spec/10-anti-entropy.md`.
    sequence: u64,
}

impl AnonymousEventLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// The proof-of-work difficulty a submission under `corroboration_nonce` must currently
    /// meet -- escalates with how many reports this nonce already has, per
    /// `difficulty_bits_for_report_number`. A submitting client should call this (or a remote
    /// equivalent exposed over the transport) before spending work solving a `ProofOfWork`, so
    /// it doesn't under-shoot and waste the attempt.
    pub fn required_difficulty_bits(&self, corroboration_nonce: &str) -> u32 {
        difficulty_bits_for_report_number(self.corroboration_for(corroboration_nonce))
    }

    /// Rejects (and never records) an event that fails `AnonymousEvent::validate`, or whose
    /// `pow` doesn't meet `required_difficulty_bits` for this event's nonce *at the moment this
    /// is called* -- the escalation means this check must happen here, inside the log, not in
    /// `AnonymousEvent::validate`, since only the log knows how many reports already exist for
    /// this nonce.
    pub fn record(&mut self, event: AnonymousEvent, pow: ProofOfWork) -> Result<(), AnonymousEventError> {
        event.validate()?;
        let required_bits = self.required_difficulty_bits(&event.corroboration_nonce);
        if !pow.satisfies(&event, required_bits) {
            return Err(AnonymousEventError::InsufficientProofOfWork { required_bits });
        }
        let nonce = event.corroboration_nonce.clone();
        let is_all_clear = event.kind == EventKind::AllClear;
        self.events.entry(nonce.clone()).or_default().push(event);
        self.sequence += 1;
        if is_all_clear {
            self.resolved.insert(nonce);
            self.sequence += 1;
        }
        Ok(())
    }

    /// The current version stamp for the heads check -- see `transport::pull_and_merge` and
    /// `spec/10-anti-entropy.md`.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Whether `corroboration_nonce` has been resolved by an `AllClear` -- see `search`'s
    /// `include_resolved` default.
    pub fn is_resolved(&self, corroboration_nonce: &str) -> bool {
        self.resolved.contains(corroboration_nonce)
    }

    /// How many reports share this nonce -- the corroboration count for an anonymous event. Each
    /// one recorded here already paid the escalating proof-of-work cost `record` enforced, so
    /// this count can no longer be inflated for free the way it could before proof-of-work
    /// existed (one actor resubmitting the same event repeatedly).
    pub fn corroboration_for(&self, corroboration_nonce: &str) -> usize {
        self.events.get(corroboration_nonce).map(Vec::len).unwrap_or(0)
    }

    pub fn reports_for(&self, corroboration_nonce: &str) -> &[AnonymousEvent] {
        self.events.get(corroboration_nonce).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Every recorded event matching `filter`, across every nonce -- the one piece of
    /// `spec/03-anonymous-event-rfc.md`'s "Reaching a responder" open question this crate
    /// actually answers: a way for a responder to find events relevant to them (by kind, minimum
    /// severity, coarse location prefix, or recency) without a push/dispatch mechanism of any
    /// kind. See `spec/11-responder-search.md` for exactly what this is, and -- stated as
    /// plainly as that RFC's own "not attempted" framing -- what it is **not**: there is still no
    /// responder identity, no notification/push to anyone, no claim-to-avoid-duplicate-response,
    /// and this searches only this one node's own local log, not the wider mesh.
    pub fn search(&self, filter: &EventFilter) -> Vec<&AnonymousEvent> {
        self.events
            .iter()
            .filter(|(nonce, _)| filter.include_resolved || !self.resolved.contains(nonce.as_str()))
            .flat_map(|(_, events)| events.iter())
            .filter(|event| filter.matches(event))
            .collect()
    }

    /// Merges every event in `other` into `self`, skipping anything already present (exact
    /// `AnonymousEvent` equality -- `event_id` is random per submission, so this only catches a
    /// literal re-pull of the same record, not two independent reports of the same real event;
    /// that distinction is `corroboration_nonce`'s job, unaffected either way). This is
    /// `transport::pull_and_merge`'s building block for pull-based anti-entropy
    /// (`spec/10-anti-entropy.md`) -- unlike `record`, it does **not** re-check proof-of-work or
    /// any validity constraint, because `other` is assumed to already be a verified log from a
    /// trusted peer, not raw untrusted submissions. See that spec file for exactly what trust
    /// this assumption rests on, and why it's weaker than the push path's per-message
    /// verification.
    pub fn merge(&mut self, other: AnonymousEventLog) -> bool {
        let mut changed = false;
        for (nonce, events) in other.events {
            let existing = self.events.entry(nonce).or_default();
            for event in events {
                if !existing.contains(&event) {
                    existing.push(event);
                    changed = true;
                    self.sequence += 1;
                }
            }
        }
        // A resolved nonce resolves here too -- the AllClear is a property of the real event,
        // not of the node that first saw it.
        for nonce in other.resolved {
            if self.resolved.insert(nonce) {
                changed = true;
                self.sequence += 1;
            }
        }
        changed
    }

    /// Removes every event with `observed_at < cutoff`, returning the number of events removed.
    /// Empty nonce entries are removed too, and the store's sequence is bumped if anything was
    /// removed -- so a prune is visible to `pull_and_merge`'s heads check like any other change.
    ///
    /// This is the retention primitive `spec/03-anonymous-event-rfc.md`'s "Retention/expiry" open
    /// question names. The policy -- what cutoff to use, and when to call this -- is deliberately
    /// left to the caller; nothing here prunes automatically.
    pub fn prune_before(&mut self, cutoff: i64) -> usize {
        let mut removed = 0;
        self.events.retain(|_nonce, events| {
            let before = events.len();
            events.retain(|event| event.observed_at >= cutoff);
            removed += before - events.len();
            !events.is_empty()
        });
        if removed > 0 {
            self.sequence += 1;
        }
        removed
    }

    /// `prune_before` with a maximum age in seconds, relative to `now` -- a convenience for the
    /// common "keep the last N seconds" policy. `saturating_sub` avoids underflow on a clock set
    /// before the epoch.
    pub fn prune_expired(&mut self, now: i64, max_age_seconds: i64) -> usize {
        self.prune_before(now.saturating_sub(max_age_seconds))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_event(nonce: &str) -> AnonymousEvent {
        AnonymousEvent {
            event_id: "evt-1".to_string(),
            kind: EventKind::HazardObserved,
            severity: Severity::High,
            observed_at: 1_700_000_400, // divisible by 300
            location: CoarseLocation("9q8yy".to_string()),
            corroboration_nonce: nonce.to_string(),
        }
    }

    /// Solves whatever proof-of-work `log` currently requires for `event`'s nonce, then records
    /// it -- the test-side equivalent of a real client calling `required_difficulty_bits`
    /// before submitting.
    fn record_with_fresh_pow(log: &mut AnonymousEventLog, event: AnonymousEvent) -> Result<(), AnonymousEventError> {
        let required = log.required_difficulty_bits(&event.corroboration_nonce);
        let pow = ProofOfWork::solve(&event, required);
        log.record(event, pow)
    }

    /// Solves for a nonce whose hash has *exactly* `exact_bits` leading zero bits, not merely
    /// at least -- unlike `ProofOfWork::solve`'s `>=` search (which can occasionally overshoot a
    /// higher threshold by chance), this guarantees the result does NOT satisfy any higher
    /// threshold, which is what an escalation-rejection assertion actually needs to be
    /// deterministic rather than flaky.
    fn solve_exact(event: &AnonymousEvent, exact_bits: u32) -> ProofOfWork {
        let mut nonce = 0u64;
        loop {
            let candidate = ProofOfWork { nonce };
            if leading_zero_bits(&proof_of_work_hash(event, &candidate)) == exact_bits {
                return candidate;
            }
            nonce += 1;
        }
    }

    #[test]
    fn a_well_formed_event_validates() {
        assert!(valid_event("nonce-1").validate().is_ok());
    }

    #[test]
    fn a_too_precise_location_is_rejected() {
        let mut event = valid_event("nonce-1");
        event.location = CoarseLocation("9q8yyk8yt0".to_string()); // 10 chars, over the limit
        assert_eq!(
            event.validate(),
            Err(AnonymousEventError::LocationTooPrecise(CoarseLocation::MAX_PRECISION_CHARS))
        );
    }

    #[test]
    fn an_unrounded_timestamp_is_rejected() {
        let mut event = valid_event("nonce-1");
        event.observed_at = 1_700_000_401; // not divisible by 300
        assert_eq!(event.validate(), Err(AnonymousEventError::TimeNotRounded(TIME_ROUNDING_SECONDS)));
    }

    #[test]
    fn the_log_never_records_an_invalid_event() {
        let mut log = AnonymousEventLog::new();
        let mut event = valid_event("nonce-1");
        event.observed_at += 1;
        // Validation runs before the proof-of-work check, so an unsolved (zero) nonce is fine
        // here -- it must never be reached.
        assert!(log.record(event, ProofOfWork { nonce: 0 }).is_err());
        assert_eq!(log.corroboration_for("nonce-1"), 0);
    }

    #[test]
    fn independent_reports_sharing_a_nonce_corroborate_each_other() {
        let mut log = AnonymousEventLog::new();
        record_with_fresh_pow(&mut log, valid_event("wildfire-ridge-rd-2026-10-23t14")).unwrap();
        assert_eq!(log.corroboration_for("wildfire-ridge-rd-2026-10-23t14"), 1);

        let mut second_report = valid_event("wildfire-ridge-rd-2026-10-23t14");
        second_report.event_id = "evt-2".to_string();
        record_with_fresh_pow(&mut log, second_report).unwrap();
        assert_eq!(log.corroboration_for("wildfire-ridge-rd-2026-10-23t14"), 2);

        // An unrelated event (different nonce) must not be conflated with it.
        record_with_fresh_pow(&mut log, valid_event("different-event-entirely")).unwrap();
        assert_eq!(log.corroboration_for("wildfire-ridge-rd-2026-10-23t14"), 2);
        assert_eq!(log.reports_for("wildfire-ridge-rd-2026-10-23t14").len(), 2);
    }

    #[test]
    fn a_heart_issue_medical_emergency_validates_and_carries_no_identifying_detail() {
        let mut event = valid_event("heart-issue-report-1");
        event.kind = EventKind::MedicalEmergency(MedicalEmergencyKind::HeartIssue);
        event.severity = Severity::Critical;
        assert!(event.validate().is_ok());

        let mut log = AnonymousEventLog::new();
        record_with_fresh_pow(&mut log, event).unwrap();
        assert_eq!(log.corroboration_for("heart-issue-report-1"), 1);
        assert!(matches!(
            log.reports_for("heart-issue-report-1")[0].kind,
            EventKind::MedicalEmergency(MedicalEmergencyKind::HeartIssue)
        ));
    }

    #[test]
    fn a_report_with_no_proof_of_work_is_rejected() {
        let mut log = AnonymousEventLog::new();
        let event = valid_event("pow-test-1");
        // Difficulty 0 is never a real solution against BASE_DIFFICULTY_BITS = 16.
        let err = log.record(event, ProofOfWork { nonce: 0 }).unwrap_err();
        assert_eq!(err, AnonymousEventError::InsufficientProofOfWork { required_bits: BASE_DIFFICULTY_BITS });
        assert_eq!(log.corroboration_for("pow-test-1"), 0);
    }

    #[test]
    fn required_difficulty_escalates_with_each_additional_report_under_one_nonce() {
        let mut log = AnonymousEventLog::new();
        let nonce = "escalation-test";
        assert_eq!(log.required_difficulty_bits(nonce), BASE_DIFFICULTY_BITS);

        record_with_fresh_pow(&mut log, valid_event(nonce)).unwrap();
        assert_eq!(log.required_difficulty_bits(nonce), BASE_DIFFICULTY_BITS + DIFFICULTY_STEP_BITS);

        let mut second = valid_event(nonce);
        second.event_id = "evt-2".to_string();
        record_with_fresh_pow(&mut log, second).unwrap();
        assert_eq!(log.required_difficulty_bits(nonce), BASE_DIFFICULTY_BITS + 2 * DIFFICULTY_STEP_BITS);

        // A proof solved for the *first* report's difficulty is no longer enough for a third.
        // Solved to *exactly* the base difficulty (not merely >=) so this assertion is
        // deterministic -- `solve`'s `>=` search can occasionally overshoot a higher threshold
        // by chance.
        let mut third = valid_event(nonce);
        third.event_id = "evt-3".to_string();
        let stale_pow = solve_exact(&third, BASE_DIFFICULTY_BITS);
        let err = log.record(third, stale_pow).unwrap_err();
        assert_eq!(
            err,
            AnonymousEventError::InsufficientProofOfWork { required_bits: BASE_DIFFICULTY_BITS + 2 * DIFFICULTY_STEP_BITS }
        );
    }

    #[test]
    fn prune_before_removes_old_events_and_keeps_recent() {
        let mut log = AnonymousEventLog::new();
        let mut old = valid_event("prune-old");
        old.observed_at = 999_900; // divisible by 300
        record_with_fresh_pow(&mut log, old).unwrap();
        let mut recent = valid_event("prune-recent");
        recent.observed_at = 2_000_100; // divisible by 300
        record_with_fresh_pow(&mut log, recent).unwrap();

        assert_eq!(log.prune_before(1_500_000), 1);
        assert_eq!(log.corroboration_for("prune-old"), 0);
        assert_eq!(log.corroboration_for("prune-recent"), 1);
    }

    #[test]
    fn prune_before_with_no_matches_changes_nothing() {
        let mut log = AnonymousEventLog::new();
        record_with_fresh_pow(&mut log, valid_event("prune-keep")).unwrap();
        let sequence = log.sequence();

        assert_eq!(log.prune_before(1), 0);
        assert_eq!(log.corroboration_for("prune-keep"), 1);
        assert_eq!(log.sequence(), sequence);
    }

    #[test]
    fn prune_expired_uses_now_and_max_age() {
        let mut log = AnonymousEventLog::new();
        let mut old = valid_event("prune-expired-old");
        old.observed_at = 999_900; // divisible by 300
        record_with_fresh_pow(&mut log, old).unwrap();
        let mut recent = valid_event("prune-expired-recent");
        recent.observed_at = 2_000_100; // divisible by 300
        record_with_fresh_pow(&mut log, recent).unwrap();

        assert_eq!(log.prune_expired(2_000_100, 1_000_000), 1);
        assert_eq!(log.corroboration_for("prune-expired-old"), 0);
        assert_eq!(log.corroboration_for("prune-expired-recent"), 1);
    }

    #[test]
    fn merge_adds_new_events_and_skips_exact_duplicates() {
        let mut local = AnonymousEventLog::new();
        record_with_fresh_pow(&mut local, valid_event("merge-test")).unwrap();

        let mut remote = AnonymousEventLog::new();
        // The same event local already has (by full equality) -- must not be double-counted.
        let duplicate = local.reports_for("merge-test")[0].clone();
        remote.events.entry("merge-test".to_string()).or_default().push(duplicate);
        // A genuinely new, independent report of the same real event.
        let mut new_report = valid_event("merge-test");
        new_report.event_id = "evt-from-remote".to_string();
        remote.events.entry("merge-test".to_string()).or_default().push(new_report);
        // An event under an entirely different nonce local has never seen.
        remote.events.entry("remote-only-nonce".to_string()).or_default().push(valid_event("remote-only-nonce"));

        local.merge(remote);

        assert_eq!(local.corroboration_for("merge-test"), 2);
        assert_eq!(local.corroboration_for("remote-only-nonce"), 1);
    }

    #[test]
    fn all_clear_resolves_a_nonce_and_hides_it_from_search() {
        let mut log = AnonymousEventLog::new();
        record_with_fresh_pow(&mut log, valid_event("resolve-nonce")).unwrap();
        let mut all_clear = valid_event("resolve-nonce");
        all_clear.kind = EventKind::AllClear;
        all_clear.event_id = "evt-all-clear".to_string();
        record_with_fresh_pow(&mut log, all_clear).unwrap();

        assert!(log.is_resolved("resolve-nonce"));
        assert_eq!(log.search(&EventFilter::default()).len(), 0);
        assert_eq!(
            log.search(&EventFilter { include_resolved: true, ..Default::default() }).len(),
            2
        );
    }

    #[test]
    fn all_clear_under_one_nonce_does_not_resolve_another() {
        let mut log = AnonymousEventLog::new();
        record_with_fresh_pow(&mut log, valid_event("nonce-a")).unwrap();
        let mut all_clear = valid_event("nonce-b");
        all_clear.kind = EventKind::AllClear;
        record_with_fresh_pow(&mut log, all_clear).unwrap();

        assert!(log.is_resolved("nonce-b"));
        assert!(!log.is_resolved("nonce-a"));
        assert_eq!(log.search(&EventFilter::default()).len(), 1);
    }

    #[test]
    fn merge_carries_the_resolved_set() {
        let mut local = AnonymousEventLog::new();
        record_with_fresh_pow(&mut local, valid_event("merge-resolve")).unwrap();

        let mut remote = AnonymousEventLog::new();
        let mut all_clear = valid_event("merge-resolve");
        all_clear.kind = EventKind::AllClear;
        record_with_fresh_pow(&mut remote, all_clear).unwrap();

        local.merge(remote);
        assert!(local.is_resolved("merge-resolve"));
        assert_eq!(local.search(&EventFilter::default()).len(), 0);
    }

    #[test]
    fn search_with_no_filter_fields_set_returns_every_event() {
        let mut log = AnonymousEventLog::new();
        record_with_fresh_pow(&mut log, valid_event("search-test-1")).unwrap();
        record_with_fresh_pow(&mut log, valid_event("search-test-2")).unwrap();
        assert_eq!(log.search(&EventFilter::default()).len(), 2);
    }

    #[test]
    fn search_by_kind_category_matches_regardless_of_sub_kind_payload() {
        let mut log = AnonymousEventLog::new();
        let mut medical = valid_event("search-medical");
        medical.kind = EventKind::MedicalEmergency(MedicalEmergencyKind::HeartIssue);
        record_with_fresh_pow(&mut log, medical).unwrap();
        record_with_fresh_pow(&mut log, valid_event("search-hazard")).unwrap(); // HazardObserved

        let filter = EventFilter { kind: Some(EventKindCategory::MedicalEmergency), ..Default::default() };
        let results = log.search(&filter);
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0].kind, EventKind::MedicalEmergency(_)));
    }

    #[test]
    fn search_by_min_severity_matches_at_least_as_urgent() {
        let mut log = AnonymousEventLog::new();
        let mut low = valid_event("search-low");
        low.severity = Severity::Low;
        record_with_fresh_pow(&mut log, low).unwrap();
        let mut critical = valid_event("search-critical");
        critical.severity = Severity::Critical;
        record_with_fresh_pow(&mut log, critical).unwrap();

        let filter = EventFilter { min_severity: Some(Severity::High), ..Default::default() };
        let results = log.search(&filter);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].severity, Severity::Critical);
    }

    #[test]
    fn search_by_location_prefix_and_since_narrow_results() {
        let mut log = AnonymousEventLog::new();
        let mut nearby = valid_event("search-nearby");
        nearby.location = CoarseLocation("9q8yy".to_string());
        nearby.observed_at = 1_700_001_000; // divisible by 300, later than valid_event's default
        record_with_fresh_pow(&mut log, nearby).unwrap();
        let mut far = valid_event("search-far");
        far.location = CoarseLocation("abcde".to_string());
        record_with_fresh_pow(&mut log, far).unwrap();

        let by_location = log.search(&EventFilter { location_prefix: Some("9q8".to_string()), ..Default::default() });
        assert_eq!(by_location.len(), 1);
        assert_eq!(by_location[0].location.0, "9q8yy");

        let by_recency = log.search(&EventFilter { since: Some(1_700_000_900), ..Default::default() });
        assert_eq!(by_recency.len(), 1);
        assert_eq!(by_recency[0].location.0, "9q8yy");
    }

    #[test]
    fn a_proof_of_work_is_bound_to_its_own_event_and_cannot_be_reused_for_another() {
        let event_a = valid_event("pow-binding-test-a");
        let event_b = valid_event("pow-binding-test-b");
        let pow_for_a = ProofOfWork::solve(&event_a, BASE_DIFFICULTY_BITS);

        let mut log = AnonymousEventLog::new();
        // Reusing event_a's proof for event_b's (different nonce/content) must not satisfy it.
        let err = log.record(event_b, pow_for_a).unwrap_err();
        assert_eq!(err, AnonymousEventError::InsufficientProofOfWork { required_bits: BASE_DIFFICULTY_BITS });
    }
}
