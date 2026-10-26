//! Prometheus counters for the broker (docs/DESIGN.md §15).

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

#[derive(Default)]
pub struct Metrics {
    /// (path, outcome, rule) → count.
    requests: Mutex<BTreeMap<(String, String, String), u64>>,
    /// (op) → (count, total seconds) of Vault calls.
    vault: Mutex<BTreeMap<String, (u64, f64)>>,
    /// result (hit|mint) → count.
    cache: Mutex<BTreeMap<String, u64>>,
}

impl Metrics {
    pub fn request(&self, path: &str, outcome: &str, rule: &str) {
        *self
            .requests
            .lock()
            .expect("metrics poisoned")
            .entry((path.into(), outcome.into(), rule.into()))
            .or_default() += 1;
    }

    pub fn vault(&self, op: &str, took: Duration) {
        let mut m = self.vault.lock().expect("metrics poisoned");
        let e = m.entry(op.into()).or_default();
        e.0 += 1;
        e.1 += took.as_secs_f64();
    }

    pub fn cache(&self, minted: bool) {
        *self
            .cache
            .lock()
            .expect("metrics poisoned")
            .entry(if minted { "mint" } else { "hit" }.into())
            .or_default() += 1;
    }

    pub fn render(&self, cached_tokens: usize) -> String {
        let mut out = String::new();
        out.push_str("# TYPE svidlet_broker_requests_total counter\n");
        for ((path, outcome, rule), n) in self.requests.lock().expect("metrics poisoned").iter() {
            out.push_str(&format!(
                "svidlet_broker_requests_total{{path=\"{path}\",outcome=\"{outcome}\",rule=\"{rule}\"}} {n}\n"
            ));
        }
        out.push_str("# TYPE svidlet_broker_vault_seconds summary\n");
        for (op, (n, sum)) in self.vault.lock().expect("metrics poisoned").iter() {
            out.push_str(&format!(
                "svidlet_broker_vault_seconds_count{{op=\"{op}\"}} {n}\n"
            ));
            out.push_str(&format!(
                "svidlet_broker_vault_seconds_sum{{op=\"{op}\"}} {sum}\n"
            ));
        }
        out.push_str("# TYPE svidlet_broker_token_cache_total counter\n");
        for (result, n) in self.cache.lock().expect("metrics poisoned").iter() {
            out.push_str(&format!(
                "svidlet_broker_token_cache_total{{result=\"{result}\"}} {n}\n"
            ));
        }
        out.push_str("# TYPE svidlet_broker_token_cache_entries gauge\n");
        out.push_str(&format!(
            "svidlet_broker_token_cache_entries {cached_tokens}\n"
        ));
        out
    }
}
