//! Per-peer link quality, learned from observed delivery outcomes.
//!
//! Every other mechanism in this crate treats the configured peer list as an unordered set of
//! equally-good addresses: route search asks them in configuration order, and anti-entropy pulls
//! each in turn. That is simple and it works, but it spends real fan-out budget on peers that
//! have been dead for hours, and it never learns that one peer is reliably reachable while
//! another is not.
//!
//! This module adds the missing feedback path: a node observes whether each interaction with a
//! peer actually delivered, and uses that history to **order** which peers it asks first. It is
//! the same shape as the base project's tensor pad -- a small persistent-in-memory value nudged
//! by an exponential moving average after every observation -- applied to connectivity instead of
//! to routing weights.
//!
//! **It orders; it never excludes.** A peer at score `0.0` is asked last, not dropped. This is
//! the standing "degrade, don't drop" decision (`OPEN_QUESTIONS.md`) applied to connectivity:
//! a peer that is down today may be the only path tomorrow, and nothing here gives this node a
//! reason to forget it. The fan-out budget is the only thing reordering spends better.
//!
//! **In-memory only.** A restart forgets every peer's quality and re-learns it within a few
//! rounds. That is deliberate and consistent with this crate's posture on its other limiter
//! state (`route_search_limiter`, `responder_ack_limiter`): losing it costs a little wasted
//! fan-out, not anything irrecoverable. It also avoids adding an eighth persisted store, which
//! would change the commit-marker set (`spec/08-persistence.md`) for a value that is by nature
//! ephemeral.
//!
//! **Not a reputation system.** Quality here measures whether a request got an answer, not
//! whether the answer was honest. A peer that replies with garbage scores exactly as well as one
//! that replies correctly; honesty is `spec/05`'s corroboration layer's job, and this module must
//! not be read as a trust signal. It is a liveness signal only.

use std::collections::HashMap;
use std::sync::RwLock;

/// Exponential-moving-average smoothing factor. The same value as the base project's tensor-pad
/// learning rate (`spec/23-tensor-pad-and-evolution-layer.md`), deliberately: both are
/// "nudge a persistent scalar toward the latest observation" and there is no reason for them to
/// disagree.
pub const QUALITY_LEARNING_RATE: f64 = 0.1;

/// The score assigned to a peer this node has never interacted with.
///
/// Neutral rather than optimistic: an unknown peer is not assumed to be good, but it is also not
/// penalized for being unobserved. It sits between a demonstrably-dead peer (`0.0`) and a
/// demonstrably-healthy one (`1.0`), so a node with no history yet spreads its fan-out across
/// everyone instead of preferring whichever address happened to be configured first.
pub const UNKNOWN_PEER_SCORE: f64 = 0.5;

/// What this node has observed about one peer address.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LinkQuality {
    /// How many interactions were recorded.
    pub attempts: u64,
    /// How many of those got a usable answer.
    pub successes: u64,
    /// Exponential moving average of the outcome (`1.0` = delivered, `0.0` = failed).
    pub score: f64,
    /// Wall-clock seconds of the most recent observation, for reporting and freshness.
    pub updated_at: u64,
}

impl LinkQuality {
    fn new(now: u64) -> Self {
        Self { attempts: 0, successes: 0, score: UNKNOWN_PEER_SCORE, updated_at: now }
    }

    fn record(&mut self, delivered: bool, now: u64, alpha: f64) {
        self.attempts += 1;
        if delivered {
            self.successes += 1;
        }
        let observation = if delivered { 1.0 } else { 0.0 };
        self.score = (1.0 - alpha) * self.score + alpha * observation;
        self.updated_at = now;
    }

    /// Fraction of recorded interactions that delivered, or `None` when nothing has been recorded.
    /// Reported separately from `score` because the two answer different questions: the ratio is
    /// the raw evidence, the score is the smoothed estimate a single recent failure cannot swing.
    pub fn success_ratio(&self) -> Option<f64> {
        if self.attempts == 0 {
            None
        } else {
            Some(self.successes as f64 / self.attempts as f64)
        }
    }
}

/// The ledger: one [`LinkQuality`] per peer address this node has interacted with.
#[derive(Debug)]
pub struct LinkQualityLedger {
    inner: RwLock<HashMap<String, LinkQuality>>,
    alpha: f64,
}

impl Default for LinkQualityLedger {
    fn default() -> Self {
        Self::new(QUALITY_LEARNING_RATE)
    }
}

impl LinkQualityLedger {
    pub fn new(alpha: f64) -> Self {
        Self { inner: RwLock::new(HashMap::new()), alpha }
    }

    /// Records one observed outcome for `peer`. `delivered` means the interaction produced a
    /// usable answer -- for a route search, a reply; for a pull, a completed merge.
    pub fn record(&self, peer: &str, delivered: bool, now: u64) {
        let mut inner = self.inner.write().unwrap();
        inner.entry(peer.to_string()).or_insert_with(|| LinkQuality::new(now)).record(delivered, now, self.alpha);
    }

    /// This node's current quality for `peer`, if it has interacted with it.
    pub fn quality(&self, peer: &str) -> Option<LinkQuality> {
        self.inner.read().unwrap().get(peer).copied()
    }

    /// Every recorded peer and its quality.
    pub fn snapshot(&self) -> HashMap<String, LinkQuality> {
        self.inner.read().unwrap().clone()
    }

    /// Orders `peers` by observed quality, best first.
    ///
    /// Stable, so peers with equal scores keep their relative configuration order -- a node with
    /// no history yet asks its configured peers in the order its operator wrote them. Peers
    /// absent from the ledger get [`UNKNOWN_PEER_SCORE`] and therefore sit between the proven
    /// and the disproven.
    ///
    /// **Never drops anything.** Every input address appears exactly once in the output, which
    /// is what makes this safe to use as a fan-out ordering under "degrade, don't drop".
    pub fn ordered(&self, peers: &[String]) -> Vec<String> {
        let inner = self.inner.read().unwrap();
        let mut scored: Vec<(String, f64)> = peers
            .iter()
            .map(|peer| {
                let score = inner.get(peer).map(|q| q.score).unwrap_or(UNKNOWN_PEER_SCORE);
                (peer.clone(), score)
            })
            .collect();
        // `sort_by` is stable, so equal scores preserve configuration order.
        scored.sort_by(|a, b| b.1.total_cmp(&a.1));
        scored.into_iter().map(|(peer, _)| peer).collect()
    }
}

/// Wall-clock seconds from the Unix epoch, the same clock the rest of this crate stamps events
/// with. Kept as a free function so the ledger has no opinion about where time comes from.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ledger_with(observations: &[(&str, bool)]) -> LinkQualityLedger {
        let ledger = LinkQualityLedger::default();
        let mut now = 1_000;
        for (peer, delivered) in observations {
            ledger.record(peer, *delivered, now);
            now += 1;
        }
        ledger
    }

    #[test]
    fn an_unseen_peer_is_neutral_not_zero() {
        // A node with no history must not penalize its peers for being unobserved: every address
        // is asked, just in configuration order.
        let ledger = LinkQualityLedger::default();
        assert_eq!(ledger.quality("never-seen"), None);
        let ordered = ledger.ordered(&["a".into(), "b".into(), "c".into()]);
        assert_eq!(ordered, vec!["a", "b", "c"], "equal scores must preserve configuration order");
    }

    #[test]
    fn a_dead_peer_sorts_last_and_a_healthy_peer_first() {
        let mut observations = Vec::new();
        for _ in 0..20 {
            observations.push(("dead", false));
            observations.push(("live", true));
        }
        let ledger = ledger_with(&observations);

        let ordered = ledger.ordered(&["dead".into(), "live".into()]);
        assert_eq!(ordered, vec!["live", "dead"]);

        // The EMA never quite reaches 0 or 1 -- it converges geometrically. After 20 failures
        // from a neutral 0.5 with alpha 0.1 the score is 0.5 * 0.9^20 ~ 0.061, and after 20
        // successes ~ 0.939. Asserting the exact asymptote would be asserting a limit the
        // mechanism deliberately does not reach.
        let dead = ledger.quality("dead").unwrap();
        let live = ledger.quality("live").unwrap();
        assert!(dead.score < 0.1, "20 consecutive failures should drive the score near 0, got {}", dead.score);
        assert!(live.score > 0.9, "20 consecutive successes should drive the score near 1, got {}", live.score);
        assert_eq!(dead.successes, 0);
        assert_eq!(live.successes, 20);
        assert_eq!(dead.success_ratio(), Some(0.0));
        assert_eq!(live.success_ratio(), Some(1.0));
    }

    #[test]
    fn ordering_never_drops_a_peer() {
        // The "degrade, don't drop" guarantee, as a property rather than a comment: whatever the
        // scores, every configured address is still in the output exactly once.
        let mut observations = Vec::new();
        for _ in 0..50 {
            observations.push(("terrible", false));
        }
        let ledger = ledger_with(&observations);
        let configured: Vec<String> = ["terrible", "good", "also-good", "unseen"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let ordered = ledger.ordered(&configured);
        assert_eq!(ordered.len(), configured.len(), "ordering must be a permutation");
        let mut sorted = ordered.clone();
        sorted.sort();
        let mut configured_sorted = configured.clone();
        configured_sorted.sort();
        assert_eq!(sorted, configured_sorted);
    }

    #[test]
    fn the_score_is_smoothed_not_a_raw_ratio() {
        // One recent failure must not erase a long healthy history -- otherwise a single dropped
        // packet would reshuffle fan-out and make routing oscillate.
        let mut observations = Vec::new();
        for _ in 0..99 {
            observations.push(("flaky", true));
        }
        observations.push(("flaky", false));
        let ledger = ledger_with(&observations);

        let q = ledger.quality("flaky").unwrap();
        assert_eq!(q.attempts, 100);
        assert_eq!(q.successes, 99);
        assert_eq!(q.success_ratio(), Some(0.99));
        assert!(
            q.score > 0.85,
            "after 99 successes and 1 failure the smoothed score should stay high, got {}",
            q.score
        );

        // A healthy-but-unseen peer must still outrank a peer with one recorded failure.
        // The smoothed score must still outrank a peer this node has never tried, which is the
        // property that keeps a single dropped packet from demoting a healthy peer below an
        // unknown one.
        let ordered = ledger.ordered(&["flaky".into(), "unseen".into()]);
        assert_eq!(ordered, vec!["flaky", "unseen"]);
    }

    #[test]
    fn a_peer_recovers_after_its_next_successes() {
        // Ordering must be able to change its mind: a peer that comes back should climb back up
        // rather than being pinned at the bottom forever.
        let mut observations = Vec::new();
        for _ in 0..30 {
            observations.push(("down", false));
        }
        let ledger = ledger_with(&observations);
        assert!(ledger.quality("down").unwrap().score < 0.05, "got {}", ledger.quality("down").unwrap().score);

        for i in 0..30 {
            ledger.record("down", true, 2_000 + i);
        }
        assert!(
            ledger.quality("down").unwrap().score > 0.9,
            "a recovered peer should climb back toward 1.0, got {}",
            ledger.quality("down").unwrap().score
        );
        // And it must climb back *above* a peer this node has never tried.
        assert_eq!(
            ledger.ordered(&["down".into(), "unseen".into()]),
            vec!["down", "unseen"]
        );
    }

    /// The modelled half of the experiment: given a fan-out budget of one, which peer gets asked?
    /// This is a model of the fan-out policy, not a network measurement -- see `EXPERIMENTS.md`.
    #[test]
    fn a_budget_of_one_is_spent_on_the_proven_peer_first() {
        let mut observations = Vec::new();
        for _ in 0..20 {
            observations.push(("dead", false));
            observations.push(("live", true));
        }
        let ledger = ledger_with(&observations);
        let configured = vec!["dead".to_string(), "live".to_string()];
        let ordered = ledger.ordered(&configured);

        // With `fanout_budget == 1`, route search asks only the first address.
        assert_eq!(ordered.first().map(String::as_str), Some("live"));
        assert_ne!(ordered.first().map(String::as_str), Some("dead"));
    }
}
