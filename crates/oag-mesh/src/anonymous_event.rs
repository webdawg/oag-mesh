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
/// is no identifying detail in the rest of the payload to go on.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
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
#[derive(Debug, Default)]
pub struct AnonymousEventLog {
    events: std::collections::HashMap<String, Vec<AnonymousEvent>>,
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
        self.events.entry(event.corroboration_nonce.clone()).or_default().push(event);
        Ok(())
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
        let mut third = valid_event(nonce);
        third.event_id = "evt-3".to_string();
        let stale_pow = ProofOfWork::solve(&third, BASE_DIFFICULTY_BITS);
        let err = log.record(third, stale_pow).unwrap_err();
        assert_eq!(
            err,
            AnonymousEventError::InsufficientProofOfWork { required_bits: BASE_DIFFICULTY_BITS + 2 * DIFFICULTY_STEP_BITS }
        );
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
