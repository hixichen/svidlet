//! `svidlet-policy`: policy distribution, in its own process.
//!
//! Why this is a separate process from the CSI plugin rather than another
//! thread inside it: identity issuance and authorization configuration would
//! otherwise share a trust root and an address space. A bug anywhere in the
//! policy path — OCI manifests, tar archives, TOML, signature envelopes, a gRPC
//! stream from a backend somebody else runs — would sit in the same process
//! that holds the credential which mints identities. Splitting them means a
//! compromise of the policy path yields a non-root process with a read-only
//! registry token and no way to issue anything.
//!
//! The two processes share **no state and no IPC**. The interface between them
//! is the volume itself, and it runs in one direction:
//!
//! - svidlet publishes `tls.crt`; this daemon reads it to learn what identity
//!   a volume holds. A certificate it did not issue is not one it can forge.
//! - this daemon publishes `policy/` and `policy.revision`; svidlet, if
//!   `SVIDLET_POLICY_REQUIRED` is set, waits for that revision file before
//!   letting a pod start.
//!
//! Each writes its own atomic swap chain in the volume, so neither can disturb
//! the other's files even by accident.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use svidlet_issue::{IdPolicy, SpiffeId};

use crate::config::PolicyConfig;
use crate::policy::oci::BundleSource;
use crate::policy::PolicyManager;
use crate::{debug, error, info, recover, volume, warn};

/// A volume this node hosts, and the identity its certificate carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Volume {
    pub target: PathBuf,
    pub spiffe_id: SpiffeId,
}

#[derive(Default)]
pub struct DaemonMetrics {
    pub scans: AtomicU64,
    pub volumes_written: AtomicU64,
    pub write_failures: AtomicU64,
    pub unreadable_volumes: AtomicU64,
}

/// What the daemon currently believes about this node's volumes.
pub struct Daemon {
    cfg: PolicyConfig,
    id_policy: IdPolicy,
    pub policy: Arc<PolicyManager>,
    pub bundle: Option<Arc<BundleSource>>,
    /// Target path → identity, refreshed by the scan loop.
    volumes: Mutex<BTreeMap<PathBuf, SpiffeId>>,
    pub metrics: DaemonMetrics,
}

impl Daemon {
    pub fn new(
        cfg: PolicyConfig,
        policy: Arc<PolicyManager>,
        bundle: Option<Arc<BundleSource>>,
    ) -> Result<Arc<Daemon>, String> {
        let id_policy = cfg.id_policy().map_err(|e| e.to_string())?;
        Ok(Arc::new(Daemon {
            cfg,
            id_policy,
            policy,
            bundle,
            volumes: Mutex::new(BTreeMap::new()),
            metrics: DaemonMetrics::default(),
        }))
    }

    pub fn volume_count(&self) -> usize {
        self.volumes.lock().expect("volume map poisoned").len()
    }

    pub fn volumes(&self) -> Vec<Volume> {
        self.volumes
            .lock()
            .expect("volume map poisoned")
            .iter()
            .map(|(target, spiffe_id)| Volume {
                target: target.clone(),
                spiffe_id: spiffe_id.clone(),
            })
            .collect()
    }

    /// Walk the kubelet's records and work out which identities this node
    /// currently hosts, by reading the certificates svidlet published.
    ///
    /// Subscriptions are updated here rather than by the caller: a scan that
    /// reported changes and left someone else to act on them is a footgun, and
    /// forgetting to subscribe would silently give a workload the fleet bundle
    /// when a per-identity one was meant for it.
    ///
    /// Returns the identities that appeared and disappeared, for logging.
    pub fn scan(&self) -> (Vec<String>, Vec<String>) {
        self.metrics.scans.fetch_add(1, Ordering::Relaxed);

        let mut found: BTreeMap<PathBuf, SpiffeId> = BTreeMap::new();
        let mut unreadable = 0u64;

        for discovered in recover::discover(&self.cfg.kubelet_root, &self.cfg.driver_name) {
            let chain = match volume::read_cert_chain(&discovered.target_path) {
                Ok(chain) => chain,
                // Normal and transient: svidlet may be mid-publish, or the pod
                // may be going away. Not worth a warning on every scan.
                Err(_) => {
                    unreadable += 1;
                    continue;
                }
            };
            let facts = match svidlet_issue::inspect(&chain) {
                Ok(facts) => facts,
                Err(e) => {
                    debug!(
                        "volume has no readable certificate yet",
                        path = discovered.target_path.display(),
                        error = e,
                    );
                    unreadable += 1;
                    continue;
                }
            };
            // Only write policy for identities this fleet issues. A certificate
            // from another trust domain or cluster is left alone rather than
            // handed a bundle that was meant for somebody else — the same check
            // restart recovery makes before adopting a certificate.
            if let Err(reason) = recover::identity_belongs_here(
                &self.id_policy,
                facts.spiffe_id.as_str(),
                &self.cfg.trust_domain,
                &self.cfg.cluster,
                &self.cfg.node_name,
            ) {
                warn!(
                    "volume holds an identity this fleet does not issue; not publishing policy",
                    path = discovered.target_path.display(),
                    spiffe_id = facts.spiffe_id,
                    reason = reason,
                );
                continue;
            }
            found.insert(discovered.target_path, facts.spiffe_id);
        }

        self.metrics
            .unreadable_volumes
            .store(unreadable, Ordering::Relaxed);

        let mut volumes = self.volumes.lock().expect("volume map poisoned");
        let before: Vec<String> = volumes.values().map(|id| id.to_string()).collect();
        let after: Vec<String> = found.values().map(|id| id.to_string()).collect();
        *volumes = found;
        drop(volumes);

        let appeared: Vec<String> = after
            .iter()
            .filter(|id| !before.contains(id))
            .cloned()
            .collect();
        let gone: Vec<String> = before
            .iter()
            .filter(|id| !after.contains(id))
            .cloned()
            .collect();

        for id in &appeared {
            self.policy.subscribe(id);
        }
        for id in &gone {
            self.policy.unsubscribe(id);
        }
        (appeared, gone)
    }

    /// Write the policy each volume should hold, skipping the ones already
    /// current. Returns how many were rewritten.
    pub fn apply(&self) -> usize {
        let mut written = 0;
        for volume in self.volumes() {
            let Some(bundle) = self.policy.bundle(volume.spiffe_id.as_str()) else {
                continue;
            };
            if volume::published_revision(&volume.target).as_deref() == Some(&bundle.revision) {
                continue;
            }
            match volume::publish_policy(&volume.target, &bundle, self.cfg.file_mode) {
                Ok(()) => {
                    written += 1;
                    self.metrics.volumes_written.fetch_add(1, Ordering::Relaxed);
                    info!(
                        "policy published",
                        spiffe_id = volume.spiffe_id,
                        revision = bundle.revision,
                        documents = bundle.documents.len(),
                        target = volume.target.display(),
                    );
                }
                Err(e) => {
                    self.metrics.write_failures.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        "could not publish policy",
                        spiffe_id = volume.spiffe_id,
                        target = volume.target.display(),
                        error = e,
                    );
                }
            }
        }
        written
    }
}

/// Rescan for volumes, keep subscriptions in step, and write what has changed.
pub async fn run_loop(daemon: Arc<Daemon>) {
    let interval = daemon.cfg.scan_interval;
    loop {
        let scanning = daemon.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            let (appeared, gone) = scanning.scan();
            // Applying in the same blocking task keeps file writes off the
            // reactor and makes one pass mean one consistent view.
            let written = scanning.apply();
            (appeared.len(), gone.len(), written)
        })
        .await;

        match outcome {
            Ok((appeared, gone, written)) if appeared + gone + written > 0 => info!(
                "policy pass",
                volumes = daemon.volume_count(),
                appeared = appeared,
                gone = gone,
                written = written,
            ),
            Ok(_) => debug!(
                "policy pass: nothing to do",
                volumes = daemon.volume_count()
            ),
            Err(e) => error!("policy pass panicked", error = e),
        }

        tokio::time::sleep(interval).await;
    }
}

/// Prometheus text for the daemon. Separate from svidlet's endpoint, because
/// they are separate processes with separate failure modes.
pub fn render(daemon: &Daemon) -> String {
    use crate::policy::oci::Error as BundleError;
    use std::fmt::Write as _;

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

    let mut out = String::with_capacity(2048);
    simple(
        &mut out,
        "svidlet_policy_build_info",
        "Always 1. Carries the version in its labels.",
        "gauge",
        &format!("{{version=\"{}\"}}", env!("CARGO_PKG_VERSION")),
        1.0,
    );
    simple(
        &mut out,
        "svidlet_policy_volumes",
        "Volumes on this node that hold an identity this fleet issues.",
        "gauge",
        "",
        daemon.volume_count() as f64,
    );
    simple(
        &mut out,
        "svidlet_policy_volumes_unreadable",
        "Volumes found without a readable certificate. Transient during a publish; \
         persistent means svidlet and this daemon disagree about the layout.",
        "gauge",
        "",
        daemon.metrics.unreadable_volumes.load(Ordering::Relaxed) as f64,
    );

    let p = &daemon.policy.metrics;
    for (name, help, value) in [
        (
            "svidlet_policy_scans_total",
            "Passes over the kubelet's volume directory.",
            daemon.metrics.scans.load(Ordering::Relaxed),
        ),
        (
            "svidlet_policy_volumes_written_total",
            "Policy bundles written into a pod's volume.",
            daemon.metrics.volumes_written.load(Ordering::Relaxed),
        ),
        (
            "svidlet_policy_write_failures_total",
            "Failed attempts to write policy into a volume.",
            daemon.metrics.write_failures.load(Ordering::Relaxed),
        ),
        (
            "svidlet_policy_updates_received_total",
            "Policy updates received from a source, including ones that changed nothing.",
            p.updates_received.load(Ordering::Relaxed),
        ),
        (
            "svidlet_policy_updates_rejected_total",
            "Updates refused as malformed. Non-zero means a backend is sending \
             something svidlet will not publish.",
            p.rejected_updates.load(Ordering::Relaxed),
        ),
        (
            "svidlet_policy_stream_reconnects_total",
            "Times the policy stream dropped and was re-established.",
            p.stream_reconnects.load(Ordering::Relaxed),
        ),
    ] {
        simple(&mut out, name, help, "counter", "", value as f64);
    }

    simple(
        &mut out,
        "svidlet_policy_stream_connected",
        "1 when the policy stream is up. Policy already on disk keeps working when it \
         is 0, but changes stop arriving.",
        "gauge",
        "",
        if daemon.policy.stream_enabled() {
            p.connected.load(Ordering::Relaxed) as u8 as f64
        } else {
            f64::NAN
        },
    );

    // The pull-based rollout.
    let current = daemon
        .bundle
        .as_ref()
        .map(|b| b.current())
        .unwrap_or_default();
    let _ = writeln!(
        out,
        "# HELP svidlet_bundle_version Always 1. The digest and ring this node is running are its labels."
    );
    let _ = writeln!(out, "# TYPE svidlet_bundle_version gauge");
    let _ = writeln!(
        out,
        "svidlet_bundle_version{{digest=\"{}\",ring=\"{}\"}} 1",
        if current.digest.is_empty() {
            "none"
        } else {
            &current.digest
        },
        if current.ring.is_empty() {
            "none"
        } else {
            &current.ring
        },
    );
    simple(
        &mut out,
        "svidlet_bundle_age_seconds",
        "Seconds since this node last verified a rollout manifest. Alert on this: a node \
         that cannot reach the registry keeps serving the bundle it has, so age is the \
         only signal that policy has stopped moving.",
        "gauge",
        "",
        daemon
            .bundle
            .as_ref()
            .and_then(|b| b.age_seconds())
            .map(|s| s as f64)
            .unwrap_or(f64::NAN),
    );

    let bundle_metrics = daemon.bundle.as_ref().map(|b| &b.metrics);
    let _ = writeln!(
        out,
        "# HELP svidlet_bundle_rejected_total Polls that did not end with a bundle applied, by reason."
    );
    let _ = writeln!(out, "# TYPE svidlet_bundle_rejected_total counter");
    for reason in BundleError::REASONS {
        let value = bundle_metrics.map(|m| m.rejected(reason)).unwrap_or(0);
        let _ = writeln!(
            out,
            "svidlet_bundle_rejected_total{{reason=\"{reason}\"}} {value}"
        );
    }
    for (name, help, value) in [
        (
            "svidlet_bundle_swap_total",
            "Times this node swapped to a different bundle.",
            bundle_metrics
                .map(|m| m.swaps.load(Ordering::Relaxed))
                .unwrap_or(0),
        ),
        (
            "svidlet_bundle_poll_total",
            "Rollout manifest polls attempted.",
            bundle_metrics
                .map(|m| m.polls.load(Ordering::Relaxed))
                .unwrap_or(0),
        ),
        (
            "svidlet_rollout_manifest_invalid_total",
            "Rollout manifests refused as unsigned, mis-signed or unparsable.",
            bundle_metrics
                .map(|m| m.manifest_invalid.load(Ordering::Relaxed))
                .unwrap_or(0),
        ),
        (
            "svidlet_registry_fetch_errors_total",
            "Failed registry requests.",
            bundle_metrics
                .map(|m| m.fetch_errors.load(Ordering::Relaxed))
                .unwrap_or(0),
        ),
    ] {
        simple(&mut out, name, help, "counter", "", value as f64);
    }
    simple(
        &mut out,
        "svidlet_bundle_node_bucket",
        "This node's stable position in 0..100, which decides its rollout ring.",
        "gauge",
        "",
        daemon
            .bundle
            .as_ref()
            .map(|b| b.bucket() as f64)
            .unwrap_or(f64::NAN),
    );
    out
}

/// Answer one HTTP request. Split out so it can be tested without a socket.
pub fn respond(request_line: &str, daemon: &Daemon) -> String {
    let path = request_line.split_whitespace().nth(1).unwrap_or("/");
    let (status, body) = match path {
        "/metrics" => (200, render(daemon)),
        // Liveness is the process answering, nothing more. Tying it to a policy
        // backend would restart this daemon during exactly the outage where the
        // policy already on disk is what matters.
        "/healthz" => (200, "ok\n".to_string()),
        _ => (404, "not found\n".to_string()),
    };
    format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        if status == 200 { "OK" } else { "Not Found" },
        body.len(),
    )
}

pub async fn serve_metrics(addr: String, daemon: Arc<Daemon>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("metrics listener failed to bind", addr = addr, error = e);
            return;
        }
    };
    info!("metrics endpoint listening", addr = addr, path = "/metrics");

    loop {
        let Ok((mut socket, _)) = listener.accept().await else {
            continue;
        };
        let daemon = daemon.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..n]);
            let response = respond(head.lines().next().unwrap_or(""), &daemon);
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.shutdown().await;
        });
    }
}
