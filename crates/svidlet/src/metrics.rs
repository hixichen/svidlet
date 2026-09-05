//! Prometheus metrics over a hand-rolled HTTP/1.1 responder.
//!
//! A scrape endpoint is three lines of HTTP; a web framework for it would cost
//! more resident memory than everything else in the process.
//!
//! Two conventions are followed deliberately. Every label combination is
//! exported from process start, including the ones that are still zero, because
//! a counter that only appears after its first failure makes `rate()` alerts
//! silently useless. And failures are labelled with the stable
//! [`ErrorCode`](svidlet_issue::ErrorCode), so a dashboard matches on a code
//! rather than on log text.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use svidlet_issue::ErrorCode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::log::unix_now;
use crate::store::Store;
use crate::{debug, error, info};

/// Upper bounds, in seconds, for the issuance latency histogram. Sized for one
/// HTTPS round trip to a PKI backend plus a P-256 keygen: the interesting
/// region is 10 ms to a few seconds, and the last bucket catches timeouts.
const LATENCY_BUCKETS: [f64; 9] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0];

/// A counter split by [`ErrorCode`], with every series pre-declared.
#[derive(Default)]
struct FailureCounter([AtomicU64; ErrorCode::ALL.len()]);

impl FailureCounter {
    fn inc(&self, code: ErrorCode) {
        self.0[code.index()].fetch_add(1, Ordering::Relaxed);
    }

    fn get(&self, code: ErrorCode) -> u64 {
        self.0[code.index()].load(Ordering::Relaxed)
    }
}

/// A fixed-bucket histogram. Cheap enough to update on every issuance.
#[derive(Default)]
struct Histogram {
    buckets: [AtomicU64; LATENCY_BUCKETS.len()],
    count: AtomicU64,
    /// Sum in microseconds; converted to seconds when rendered, so no float
    /// arithmetic is needed on the hot path.
    sum_micros: AtomicU64,
}

impl Histogram {
    fn observe(&self, elapsed: Duration) {
        let seconds = elapsed.as_secs_f64();
        for (i, bound) in LATENCY_BUCKETS.iter().enumerate() {
            if seconds <= *bound {
                self.buckets[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_micros
            .fetch_add(elapsed.as_micros() as u64, Ordering::Relaxed);
    }

    fn render(&self, out: &mut String, name: &str, help: &str, reason: &str) {
        use std::fmt::Write as _;
        let _ = writeln!(out, "# HELP {name} {help}");
        let _ = writeln!(out, "# TYPE {name} histogram");
        for (i, bound) in LATENCY_BUCKETS.iter().enumerate() {
            let _ = writeln!(
                out,
                "{name}_bucket{{reason=\"{reason}\",le=\"{bound}\"}} {}",
                self.buckets[i].load(Ordering::Relaxed)
            );
        }
        let count = self.count.load(Ordering::Relaxed);
        let _ = writeln!(
            out,
            "{name}_bucket{{reason=\"{reason}\",le=\"+Inf\"}} {count}"
        );
        let _ = writeln!(
            out,
            "{name}_sum{{reason=\"{reason}\"}} {}",
            self.sum_micros.load(Ordering::Relaxed) as f64 / 1e6
        );
        let _ = writeln!(out, "{name}_count{{reason=\"{reason}\"}} {count}");
    }
}

#[derive(Default)]
pub struct Metrics {
    issued_publish: AtomicU64,
    issued_renew: AtomicU64,
    failed_publish: FailureCounter,
    failed_renew: FailureCounter,
    latency_publish: Histogram,
    latency_renew: Histogram,

    pub recovered: AtomicU64,
    pub unpublished: AtomicU64,
    pub ca_refreshes: AtomicU64,
    pub ca_refresh_failures: AtomicU64,
    /// Volumes found on disk that could not be adopted after a restart. A
    /// non-zero value here means certificates are being re-issued that did not
    /// need to be.
    pub adoption_skipped: AtomicU64,

    /// Static identification of the backend in use, for `svidlet_build_info`.
    backend: std::sync::OnceLock<(&'static str, &'static str)>,
}

impl Metrics {
    pub fn inc(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Record which backend and authentication method this node is using.
    pub fn set_backend(&self, issuer: &'static str, auth: &'static str) {
        let _ = self.backend.set((issuer, auth));
    }

    pub fn published(&self) {
        Metrics::inc(&self.issued_publish);
    }

    pub fn renewed(&self) {
        Metrics::inc(&self.issued_renew);
    }

    pub fn publish_failed(&self, code: ErrorCode) {
        self.failed_publish.inc(code);
    }

    pub fn renew_failed(&self, code: ErrorCode) {
        self.failed_renew.inc(code);
    }

    pub fn observe_publish(&self, elapsed: Duration) {
        self.latency_publish.observe(elapsed);
    }

    pub fn observe_renew(&self, elapsed: Duration) {
        self.latency_renew.observe(elapsed);
    }

    pub fn render(&self, store: &Store) -> String {
        let mut out = String::with_capacity(4096);

        let (backend, auth) = self
            .backend
            .get()
            .copied()
            .unwrap_or(("unknown", "unknown"));
        simple(
            &mut out,
            "svidlet_build_info",
            "Always 1. Carries the version and the backend in its labels.",
            "gauge",
            &format!(
                "{{version=\"{}\",backend=\"{backend}\",auth=\"{auth}\"}}",
                env!("CARGO_PKG_VERSION")
            ),
            1.0,
        );

        counter_by_reason(
            &mut out,
            "svidlet_certificates_issued_total",
            "Certificates signed by the PKI backend.",
            &[
                ("publish", self.issued_publish.load(Ordering::Relaxed)),
                ("renew", self.issued_renew.load(Ordering::Relaxed)),
            ],
        );

        {
            use std::fmt::Write as _;
            let name = "svidlet_issue_failures_total";
            let _ = writeln!(
                out,
                "# HELP {name} Failed signing attempts, by stable error code."
            );
            let _ = writeln!(out, "# TYPE {name} counter");
            for (reason, counter) in [
                ("publish", &self.failed_publish),
                ("renew", &self.failed_renew),
            ] {
                for code in ErrorCode::ALL {
                    let _ = writeln!(
                        out,
                        "{name}{{reason=\"{reason}\",code=\"{code}\"}} {}",
                        counter.get(code)
                    );
                }
            }
        }

        self.latency_publish.render(
            &mut out,
            "svidlet_issue_duration_seconds",
            "Time from starting a certificate request to having it on disk.",
            "publish",
        );
        self.latency_renew.render(
            &mut out,
            "svidlet_issue_duration_seconds",
            "Time from starting a certificate request to having it on disk.",
            "renew",
        );

        for (name, help, value) in [
            (
                "svidlet_volumes_recovered_total",
                "Volumes adopted from the kubelet's records after a restart, without re-issuing.",
                self.recovered.load(Ordering::Relaxed),
            ),
            (
                "svidlet_volumes_adoption_skipped_total",
                "Volumes found on disk that could not be adopted, and so will be re-issued.",
                self.adoption_skipped.load(Ordering::Relaxed),
            ),
            (
                "svidlet_volumes_unpublished_total",
                "Volumes torn down on NodeUnpublishVolume.",
                self.unpublished.load(Ordering::Relaxed),
            ),
            (
                "svidlet_ca_refresh_total",
                "Trust bundle refreshes that changed ca.crt.",
                self.ca_refreshes.load(Ordering::Relaxed),
            ),
            (
                "svidlet_ca_refresh_failures_total",
                "Failed trust bundle refreshes.",
                self.ca_refresh_failures.load(Ordering::Relaxed),
            ),
        ] {
            simple(&mut out, name, help, "counter", "", value as f64);
        }

        simple(
            &mut out,
            "svidlet_certificates_active",
            "Certificates this node is currently renewing.",
            "gauge",
            "",
            store.len() as f64,
        );

        let now = unix_now();
        simple(
            &mut out,
            "svidlet_earliest_certificate_expiry_seconds",
            "Seconds until the soonest-expiring certificate on this node expires. \
             Alert on this: renewal starts at half the lifetime, so it only approaches \
             zero after renewal has been failing for a very long time.",
            "gauge",
            "",
            store
                .earliest_expiry()
                .map(|at| (at - now) as f64)
                .unwrap_or(f64::NAN),
        );
        simple(
            &mut out,
            "svidlet_renewals_due",
            "Certificates whose renewal deadline has passed and which have not yet been renewed.",
            "gauge",
            "",
            store.due(now).len() as f64,
        );

        out
    }
}

fn simple(out: &mut String, name: &str, help: &str, kind: &str, labels: &str, value: f64) {
    use std::fmt::Write as _;
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
    if value.is_nan() {
        let _ = writeln!(out, "{name}{labels} NaN");
    } else {
        let _ = writeln!(out, "{name}{labels} {value}");
    }
}

fn counter_by_reason(out: &mut String, name: &str, help: &str, by_reason: &[(&str, u64)]) {
    use std::fmt::Write as _;
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} counter");
    for (reason, value) in by_reason {
        let _ = writeln!(out, "{name}{{reason=\"{reason}\"}} {value}");
    }
}

/// Answer one request. Split out from [`serve`] so it can be tested without a
/// socket.
pub fn respond(request_line: &str, metrics: &Metrics, store: &Store) -> String {
    let path = request_line.split_whitespace().nth(1).unwrap_or("/");
    match path {
        "/metrics" => http(
            200,
            "text/plain; version=0.0.4; charset=utf-8",
            &metrics.render(store),
        ),
        // The DaemonSet's liveness probe: the process answers, so its runtime
        // is alive. Deliberately not gated on the PKI backend — an outage there
        // must not restart nodes whose certificates are still valid for hours.
        "/healthz" => http(200, "text/plain", "ok\n"),
        _ => http(404, "text/plain", "not found\n"),
    }
}

/// Serve `/metrics` and `/healthz` until the process exits.
pub async fn serve(addr: String, metrics: Arc<Metrics>, store: Arc<Store>) {
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            // Losing metrics does not stop certificates being issued, so this
            // is not fatal — but it does blind the operator, so it is an error.
            error!("metrics listener failed to bind", addr = addr, error = e);
            return;
        }
    };
    info!("metrics endpoint listening", addr = addr, path = "/metrics");

    loop {
        let (mut socket, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                debug!("metrics accept failed", error = e);
                continue;
            }
        };
        let metrics = metrics.clone();
        let store = store.clone();
        tokio::spawn(async move {
            // Read just enough to see the request line; a scrape has no body,
            // and anything oversized is ignored rather than buffered.
            let mut buf = [0u8; 1024];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..n]);
            let response = respond(head.lines().next().unwrap_or(""), &metrics, &store);
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.shutdown().await;
        });
    }
}

fn http(status: u16, content_type: &str, body: &str) -> String {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        _ => "Error",
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Every non-comment line must be `name{labels} value`, with a value
    /// Prometheus can parse.
    fn assert_parses(text: &str) {
        for line in text.lines() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let (series, value) = line
                .rsplit_once(' ')
                .unwrap_or_else(|| panic!("no value: {line}"));
            assert!(!series.is_empty(), "no series name: {line}");
            assert!(
                value == "NaN" || value.parse::<f64>().is_ok(),
                "unparsable value in: {line}"
            );
            if let Some(open) = series.find('{') {
                assert!(series.ends_with('}'), "unterminated labels: {line}");
                assert!(open > 0, "missing metric name: {line}");
            }
        }
    }

    #[test]
    fn render_is_valid_prometheus_text() {
        let metrics = Metrics::default();
        metrics.set_backend("vault", "approle");
        metrics.published();
        metrics.renewed();
        metrics.renewed();
        let out = metrics.render(&Store::new());

        assert_parses(&out);
        assert!(out.contains("svidlet_certificates_issued_total{reason=\"publish\"} 1"));
        assert!(out.contains("svidlet_certificates_issued_total{reason=\"renew\"} 2"));
        assert!(out.contains("svidlet_certificates_active 0"));
        assert!(out.contains(&format!(
            "svidlet_build_info{{version=\"{}\",backend=\"vault\",auth=\"approle\"}} 1",
            env!("CARGO_PKG_VERSION")
        )));
        // No certificates yet, so the expiry gauge has nothing to report.
        assert!(out.contains("svidlet_earliest_certificate_expiry_seconds NaN"));
    }

    #[test]
    fn every_error_code_series_exists_before_its_first_failure() {
        let metrics = Metrics::default();
        let out = metrics.render(&Store::new());
        for code in ErrorCode::ALL {
            for reason in ["publish", "renew"] {
                assert!(
                    out.contains(&format!(
                        "svidlet_issue_failures_total{{reason=\"{reason}\",code=\"{code}\"}} 0"
                    )),
                    "missing zero series for {reason}/{code}"
                );
            }
        }
    }

    #[test]
    fn failures_are_counted_against_their_code() {
        let metrics = Metrics::default();
        metrics.publish_failed(ErrorCode::Policy);
        metrics.renew_failed(ErrorCode::Transport);
        metrics.renew_failed(ErrorCode::Transport);
        let out = metrics.render(&Store::new());

        assert!(out.contains("svidlet_issue_failures_total{reason=\"publish\",code=\"policy\"} 1"));
        assert!(out.contains("svidlet_issue_failures_total{reason=\"renew\",code=\"transport\"} 2"));
        assert!(
            out.contains("svidlet_issue_failures_total{reason=\"publish\",code=\"transport\"} 0")
        );
        assert_parses(&out);
    }

    #[test]
    fn the_latency_histogram_is_cumulative_and_consistent() {
        let metrics = Metrics::default();
        metrics.observe_publish(Duration::from_millis(20));
        metrics.observe_publish(Duration::from_millis(200));
        // Beyond the last bucket: counted in _count but in no bucket but +Inf.
        metrics.observe_publish(Duration::from_secs(9));
        let out = metrics.render(&Store::new());
        assert_parses(&out);

        let value = |needle: &str| -> f64 {
            out.lines()
                .find(|l| l.starts_with(needle))
                .unwrap_or_else(|| panic!("missing {needle}"))
                .rsplit(' ')
                .next()
                .unwrap()
                .parse()
                .unwrap()
        };

        // Buckets are cumulative: 20 ms is in every bucket from 0.025 up.
        assert_eq!(
            value("svidlet_issue_duration_seconds_bucket{reason=\"publish\",le=\"0.01\"}"),
            0.0
        );
        assert_eq!(
            value("svidlet_issue_duration_seconds_bucket{reason=\"publish\",le=\"0.025\"}"),
            1.0
        );
        assert_eq!(
            value("svidlet_issue_duration_seconds_bucket{reason=\"publish\",le=\"0.25\"}"),
            2.0
        );
        assert_eq!(
            value("svidlet_issue_duration_seconds_bucket{reason=\"publish\",le=\"5\"}"),
            2.0
        );
        assert_eq!(
            value("svidlet_issue_duration_seconds_bucket{reason=\"publish\",le=\"+Inf\"}"),
            3.0
        );
        assert_eq!(
            value("svidlet_issue_duration_seconds_count{reason=\"publish\"}"),
            3.0
        );
        assert!(
            (value("svidlet_issue_duration_seconds_sum{reason=\"publish\"}") - 9.22).abs() < 0.01
        );

        // The renew series exists and is empty.
        assert_eq!(
            value("svidlet_issue_duration_seconds_count{reason=\"renew\"}"),
            0.0
        );
    }

    #[test]
    fn gauges_follow_the_store() {
        use crate::store::{Entry, PodRef};
        use std::path::PathBuf;

        let store = Store::new();
        let now = unix_now();
        store.insert(Entry {
            volume_id: "v".into(),
            target_path: PathBuf::from("/a"),
            spiffe_id: svidlet_issue::SpiffeId::parse("spiffe://example.org/ns/a/sa/b").unwrap(),
            pod: PodRef {
                name: "p".into(),
                namespace: "a".into(),
                uid: "u".into(),
            },
            not_before: now - 100,
            not_after: now + 900,
            renew_at: now - 1,
            failures: 0,
        });

        let out = Metrics::default().render(&store);
        assert!(out.contains("svidlet_certificates_active 1"));
        assert!(out.contains("svidlet_renewals_due 1"));
        let expiry: f64 = out
            .lines()
            .find(|l| l.starts_with("svidlet_earliest_certificate_expiry_seconds "))
            .unwrap()
            .rsplit(' ')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert!((890.0..=900.0).contains(&expiry), "expiry {expiry}");
        assert_parses(&out);
    }

    #[test]
    fn routes_answer_the_paths_a_daemonset_probes() {
        let metrics = Metrics::default();
        let store = Store::new();

        let ok = respond("GET /metrics HTTP/1.1", &metrics, &store);
        assert!(ok.starts_with("HTTP/1.1 200 OK"));
        assert!(ok.contains("version=0.0.4"));
        assert!(ok.contains("svidlet_certificates_active"));

        let health = respond("GET /healthz HTTP/1.1", &metrics, &store);
        assert!(health.starts_with("HTTP/1.1 200 OK"));
        assert!(health.ends_with("ok\n"));

        for bad in ["GET / HTTP/1.1", "GET /nope HTTP/1.1", "", "garbage"] {
            assert!(
                respond(bad, &metrics, &store).starts_with("HTTP/1.1 404"),
                "{bad:?} should 404"
            );
        }
    }

    #[test]
    fn content_length_matches_the_body() {
        let response = http(200, "text/plain", "hello\n");
        let (head, body) = response.split_once("\r\n\r\n").unwrap();
        assert!(head.contains("Content-Length: 6"));
        assert_eq!(body, "hello\n");
        assert!(head.contains("Connection: close"));
    }
}
