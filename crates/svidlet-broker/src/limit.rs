//! Rate limits: I10 (per node) and T7 (per identity).

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;

/// A sliding-window counter per key: at most `limit` events in any `window`
/// seconds. Simple and exact, and the key sets are small (nodes, identities).
pub struct Window {
    limit: u32,
    window: i64,
    events: Mutex<HashMap<String, VecDeque<i64>>>,
}

impl Window {
    pub fn new(limit: u32, window_secs: i64) -> Window {
        Window {
            limit,
            window: window_secs,
            events: Mutex::new(HashMap::new()),
        }
    }

    /// Record an event for `key` at `now` if it fits; `false` if it does not.
    /// A limit of zero disables the check.
    pub fn allow(&self, key: &str, now: i64) -> bool {
        if self.limit == 0 {
            return true;
        }
        let mut map = self.events.lock().expect("rate limiter poisoned");
        let q = map.entry(key.to_string()).or_default();
        while q.front().is_some_and(|&t| t <= now - self.window) {
            q.pop_front();
        }
        if q.len() as u32 >= self.limit {
            return false;
        }
        q.push_back(now);
        true
    }

    /// Drop keys with no events in the window, so the map does not grow with
    /// every node that ever existed.
    pub fn sweep(&self, now: i64) {
        let mut map = self.events.lock().expect("rate limiter poisoned");
        map.retain(|_, q| q.back().is_some_and(|&t| t > now - self.window));
    }
}

/// I10's second half: how many distinct identities one node asked for in the
/// last hour. A node asking for many identities is a node acting on pods that
/// churn unusually fast — or a compromised node walking the cluster.
pub struct Distinct {
    limit: u32,
    window: i64,
    seen: Mutex<HashMap<String, (i64, HashSet<String>)>>,
}

impl Distinct {
    pub fn new(limit: u32, window_secs: i64) -> Distinct {
        Distinct {
            limit,
            window: window_secs,
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Whether `node` may obtain `identity`. An identity the node already
    /// obtained in this window is always allowed: renewals must not be blocked
    /// by the cap.
    pub fn allow(&self, node: &str, identity: &str, now: i64) -> bool {
        if self.limit == 0 {
            return true;
        }
        let mut map = self.seen.lock().expect("distinct limiter poisoned");
        let (start, set) = map
            .entry(node.to_string())
            .or_insert_with(|| (now, HashSet::new()));
        if now - *start >= self.window {
            *start = now;
            set.clear();
        }
        if set.contains(identity) {
            return true;
        }
        if set.len() as u32 >= self.limit {
            return false;
        }
        set.insert(identity.to_string());
        true
    }

    pub fn sweep(&self, now: i64) {
        let mut map = self.seen.lock().expect("distinct limiter poisoned");
        map.retain(|_, (start, _)| now - *start < self.window);
    }
}
