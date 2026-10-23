//! Strictly-defined, identity-stripped event reports for life-saving actions ("SAW THIS EVENT")
//! -- a deliberately different trust/privacy model from `bridge.rs`'s signed
//! `BridgeDeclaration`s. A `BridgeDeclaration` is signed by a real `PeerIdentity` because it's
//! making a durable claim about network topology that benefits from accountability; an
//! `AnonymousEvent` is the opposite on purpose: no signature by a persistent identity, no
//! precise location or time, and a closed set of event kinds that structurally cannot carry an
//! identifying description of a specific person. This file defines the strict schema and local
//! corroboration bookkeeping only -- it does not define a transport, and does not solve the
//! anonymous-reporting spam/sybil problem (how do you rate-limit a report with no identity to
//! rate-limit against?). Both are explicitly open -- see `spec/03-anonymous-event-rfc.md`'s
//! "Open questions."

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
    /// A hazard was observed (fire, flood, structural collapse, downed power line, ...).
    HazardObserved,
    MedicalEmergency,
    /// A need for a resource at a location (water, shelter, medical supplies) during a
    /// disaster/emergency response.
    ResourceNeed,
    /// The situation this event's `corroboration_nonce` refers to has resolved or ended.
    AllClear,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
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
}

impl AnonymousEvent {
    /// Checks the two structural anonymity constraints this schema can actually enforce by
    /// itself: location coarseness and time rounding. This does **not**, and cannot, check
    /// "does this payload contain identifying information" in general -- that depends on what a
    /// caller puts in `corroboration_nonce`, not on anything a type system alone can guarantee.
    /// See `spec/03-anonymous-event-rfc.md`'s open questions for what's still unresolved
    /// (anti-spam/sybil resistance, transport-level anonymity).
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

    /// Rejects (and never records) an event that fails `AnonymousEvent::validate`.
    pub fn record(&mut self, event: AnonymousEvent) -> Result<(), AnonymousEventError> {
        event.validate()?;
        self.events.entry(event.corroboration_nonce.clone()).or_default().push(event);
        Ok(())
    }

    /// How many reports share this nonce -- the corroboration count for an anonymous event.
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
        assert!(log.record(event).is_err());
        assert_eq!(log.corroboration_for("nonce-1"), 0);
    }

    #[test]
    fn independent_reports_sharing_a_nonce_corroborate_each_other() {
        let mut log = AnonymousEventLog::new();
        log.record(valid_event("wildfire-ridge-rd-2026-10-23t14")).unwrap();
        assert_eq!(log.corroboration_for("wildfire-ridge-rd-2026-10-23t14"), 1);

        let mut second_report = valid_event("wildfire-ridge-rd-2026-10-23t14");
        second_report.event_id = "evt-2".to_string();
        log.record(second_report).unwrap();
        assert_eq!(log.corroboration_for("wildfire-ridge-rd-2026-10-23t14"), 2);

        // An unrelated event (different nonce) must not be conflated with it.
        log.record(valid_event("different-event-entirely")).unwrap();
        assert_eq!(log.corroboration_for("wildfire-ridge-rd-2026-10-23t14"), 2);
        assert_eq!(log.reports_for("wildfire-ridge-rd-2026-10-23t14").len(), 2);
    }
}
