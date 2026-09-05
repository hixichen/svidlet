//! The set of volumes this node has published, and when each is next due.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use svidlet_issue::SpiffeId;

use crate::rand;

/// Which pod a volume belongs to. Carried for logs and metrics only — the
/// identity itself is namespace and ServiceAccount.
#[derive(Debug, Clone)]
pub struct PodRef {
    pub name: String,
    pub namespace: String,
    pub uid: String,
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub volume_id: String,
    pub target_path: PathBuf,
    pub spiffe_id: SpiffeId,
    pub pod: PodRef,
    pub not_before: i64,
    pub not_after: i64,
    /// Wall-clock second at which renewal should be attempted.
    pub renew_at: i64,
    /// Consecutive renewal failures; drives the backoff.
    pub failures: u32,
}

impl Entry {
    pub fn is_due(&self, now: i64) -> bool {
        now >= self.renew_at
    }
}

/// Pick a renewal instant uniformly in `[min, max]` of the certificate's
/// lifetime.
///
/// Each round of renewals widens the spread by the width of this window, so a
/// fleet issued in one rollout converges to a uniform load after about five
/// lifetimes. Narrowing the window slows that convergence proportionally.
pub fn jittered_renew_at(not_before: i64, not_after: i64, fraction: (f64, f64)) -> i64 {
    let lifetime = (not_after - not_before).max(1) as f64;
    let (min, max) = fraction;
    let point = min + (max - min) * rand::unit();
    not_before + (lifetime * point) as i64
}

#[derive(Default)]
pub struct Store {
    inner: Mutex<HashMap<PathBuf, Entry>>,
}

impl Store {
    pub fn new() -> Self {
        Store::default()
    }

    pub fn insert(&self, entry: Entry) {
        self.lock().insert(entry.target_path.clone(), entry);
    }

    pub fn remove(&self, target_path: &Path) -> Option<Entry> {
        self.lock().remove(target_path)
    }

    pub fn get(&self, target_path: &Path) -> Option<Entry> {
        self.lock().get(target_path).cloned()
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Entries due for renewal at `now`, oldest deadline first so a backlog
    /// drains in the order it built up.
    pub fn due(&self, now: i64) -> Vec<Entry> {
        let mut due: Vec<Entry> = self
            .lock()
            .values()
            .filter(|e| e.is_due(now))
            .cloned()
            .collect();
        due.sort_by_key(|e| e.renew_at);
        due
    }

    pub fn all(&self) -> Vec<Entry> {
        self.lock().values().cloned().collect()
    }

    /// Earliest expiry across all published certificates, for the metrics
    /// endpoint and for alerting on a stuck renewal loop.
    pub fn earliest_expiry(&self) -> Option<i64> {
        self.lock().values().map(|e| e.not_after).min()
    }

    /// Record a successful renewal. Does nothing if the volume was unpublished
    /// while the renewal was in flight.
    pub fn record_renewal(
        &self,
        target_path: &Path,
        not_before: i64,
        not_after: i64,
        renew_at: i64,
    ) {
        if let Some(entry) = self.lock().get_mut(target_path) {
            entry.not_before = not_before;
            entry.not_after = not_after;
            entry.renew_at = renew_at;
            entry.failures = 0;
        }
    }

    /// Record a failed renewal and push the next attempt out with exponential
    /// backoff and jitter, capped so a long Vault outage still retries often
    /// enough to recover quickly once it ends.
    ///
    /// The existing certificate is never removed on failure: with a 24 h
    /// lifetime and renewal starting at 12 h, running pods keep working through
    /// a half-day outage.
    pub fn record_failure(&self, target_path: &Path, now: i64) -> u32 {
        let mut guard = self.lock();
        let Some(entry) = guard.get_mut(target_path) else {
            return 0;
        };
        entry.failures = entry.failures.saturating_add(1);
        let backoff = backoff_secs(entry.failures);
        entry.renew_at = now + backoff;
        entry.failures
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<PathBuf, Entry>> {
        self.inner.lock().expect("store mutex poisoned")
    }
}

/// 30 s, 60 s, 120 s … capped at 10 min, then ±25 % jitter so retries after an
/// outage do not arrive as one wave.
pub fn backoff_secs(failures: u32) -> i64 {
    const BASE: i64 = 30;
    const CAP: i64 = 600;
    let exp = BASE.saturating_mul(1i64 << failures.min(5));
    let capped = exp.min(CAP);
    let spread = capped / 4;
    rand::range_i64(capped - spread, capped + spread)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spiffe_id() -> SpiffeId {
        SpiffeId::parse("spiffe://example.org/cluster/a/ns/default/sa/web").unwrap()
    }

    fn entry(path: &str, not_before: i64, not_after: i64) -> Entry {
        Entry {
            volume_id: format!("csi-{path}"),
            target_path: PathBuf::from(path),
            spiffe_id: spiffe_id(),
            pod: PodRef {
                name: "web-0".into(),
                namespace: "default".into(),
                uid: "uid".into(),
            },
            not_before,
            not_after,
            renew_at: jittered_renew_at(not_before, not_after, (0.5, 0.7)),
            failures: 0,
        }
    }

    #[test]
    fn renewal_lands_inside_the_jitter_window() {
        rand::seed();
        let lifetime = 86_400;
        let mut seen_low = false;
        let mut seen_high = false;
        for _ in 0..500 {
            let at = jittered_renew_at(0, lifetime, (0.5, 0.7));
            assert!(
                (43_200..=60_480).contains(&at),
                "renew_at {at} out of window"
            );
            seen_low |= at < 47_000;
            seen_high |= at > 56_000;
        }
        // The whole window is used, not just its middle.
        assert!(seen_low && seen_high);
    }

    #[test]
    fn due_returns_only_expired_deadlines_oldest_first() {
        rand::seed();
        let store = Store::new();
        let mut early = entry("/a", 0, 100);
        early.renew_at = 50;
        let mut late = entry("/b", 0, 100);
        late.renew_at = 60;
        let mut future = entry("/c", 0, 100);
        future.renew_at = 500;
        store.insert(late);
        store.insert(early);
        store.insert(future);

        let due = store.due(70);
        assert_eq!(due.len(), 2);
        assert_eq!(due[0].target_path, PathBuf::from("/a"));
        assert_eq!(due[1].target_path, PathBuf::from("/b"));
        assert_eq!(store.earliest_expiry(), Some(100));
    }

    #[test]
    fn failures_back_off_and_success_resets() {
        rand::seed();
        let store = Store::new();
        store.insert(entry("/a", 0, 86_400));
        let path = PathBuf::from("/a");

        assert_eq!(store.record_failure(&path, 1_000), 1);
        let after_first = store.get(&path).unwrap();
        assert!(after_first.renew_at > 1_000);
        assert_eq!(store.record_failure(&path, 1_000), 2);
        let after_second = store.get(&path).unwrap();
        assert!(after_second.renew_at >= after_first.renew_at);

        store.record_renewal(&path, 2_000, 88_400, 45_000);
        let renewed = store.get(&path).unwrap();
        assert_eq!(renewed.failures, 0);
        assert_eq!(renewed.renew_at, 45_000);
        assert_eq!(renewed.not_after, 88_400);
    }

    #[test]
    fn backoff_is_capped() {
        rand::seed();
        for failures in 1..20 {
            let b = backoff_secs(failures);
            assert!(
                (20..=750).contains(&b),
                "backoff {b} for {failures} failures"
            );
        }
    }

    #[test]
    fn renewal_of_an_unpublished_volume_is_ignored() {
        rand::seed();
        let store = Store::new();
        store.record_renewal(Path::new("/gone"), 0, 1, 2);
        assert_eq!(store.record_failure(Path::new("/gone"), 0), 0);
        assert_eq!(store.len(), 0);
    }
}
