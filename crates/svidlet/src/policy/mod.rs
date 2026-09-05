//! Authorization policy bundles.
//!
//! A certificate says who a workload *is*. It says nothing about who it may
//! talk to, and that half has to come from somewhere too. Svidlet subscribes to
//! a policy backend over one long-lived gRPC stream per node, and publishes
//! whatever the backend returns for an identity into that workload's volume,
//! next to its certificate.
//!
//! The properties that matter:
//!
//! - **One stream per node, not per pod.** Fifty workloads on a node share one
//!   connection, and an upstream change is pushed rather than polled for.
//! - **Certificates do not depend on policy.** If the backend is down, the
//!   certificate is still issued; the policy directory is left as it was and
//!   filled in when the stream recovers. `SVIDLET_POLICY_REQUIRED` inverts that
//!   for operators who would rather a pod fail to start than start unpoliced.
//! - **Updates are atomic with everything else.** A bundle is written through
//!   the same versioned-directory swap as `tls.crt`, so a workload reloading on
//!   a change never reads a half-written policy set.

pub mod daemon;
pub mod grpc;
pub mod oci;

pub mod proto {
    tonic::include_proto!("svidlet.policy.v1");
}

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Notify;

use crate::config::PolicyConfig;
use crate::{debug, info, warn};

/// One file inside a policy bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDocument {
    /// A single path segment: the file name inside the policy directory.
    pub name: String,
    pub content: Vec<u8>,
}

/// Everything the backend has for one identity, at one upstream revision.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PolicyBundle {
    /// Opaque upstream revision — a git commit, typically. Compared for
    /// equality only.
    pub revision: String,
    /// Sorted by name, so the same bundle always produces the same directory.
    pub documents: Vec<PolicyDocument>,
}

impl PolicyBundle {
    /// Validate and normalise an update received from the backend.
    ///
    /// A document name is written straight into a directory the workload can
    /// read, so it must be a single, ordinary path segment. Anything else is
    /// rejected outright rather than sanitised: a backend sending `../../etc`
    /// is either broken or hostile, and quietly rewriting the name would hide
    /// both.
    pub fn build(revision: String, documents: Vec<PolicyDocument>) -> Result<PolicyBundle, String> {
        let mut by_name: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for doc in documents {
            check_document_name(&doc.name)?;
            if by_name.insert(doc.name.clone(), doc.content).is_some() {
                return Err(format!("bundle contains {:?} twice", doc.name));
            }
        }
        Ok(PolicyBundle {
            revision,
            documents: by_name
                .into_iter()
                .map(|(name, content)| PolicyDocument { name, content })
                .collect(),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.documents.is_empty()
    }

    pub fn total_bytes(&self) -> usize {
        self.documents.iter().map(|d| d.content.len()).sum()
    }
}

fn check_document_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("policy document has an empty name".into());
    }
    if name == "." || name == ".." {
        return Err(format!("policy document name {name:?} is not a file name"));
    }
    if name.contains('/') || name.contains('\\') || name.contains('\0') {
        return Err(format!(
            "policy document name {name:?} contains a path separator"
        ));
    }
    if name.starts_with('.') {
        // The volume writer uses "..data" and "..svidlet.N" for its own
        // bookkeeping; keeping backend-supplied names out of that namespace
        // means a bundle can never shadow them.
        return Err(format!(
            "policy document name {name:?} may not start with a dot"
        ));
    }
    Ok(())
}

#[derive(Default)]
struct State {
    /// Identities this node currently hosts and wants policy for.
    wanted: BTreeSet<String>,
    /// The most recent bundle received per identity, from the gRPC stream.
    bundles: BTreeMap<String, PolicyBundle>,
    /// The fleet-wide bundle from the OCI rollout, which applies to every
    /// identity that has nothing more specific.
    fleet: Option<PolicyBundle>,
}

/// Metrics owned by the policy subsystem.
#[derive(Default)]
pub struct PolicyMetrics {
    pub updates_received: AtomicU64,
    pub bundles_applied: AtomicU64,
    pub stream_reconnects: AtomicU64,
    pub rejected_updates: AtomicU64,
    pub wait_timeouts: AtomicU64,
    pub connected: AtomicBool,
}

/// The node's view of policy: what it wants, and what it has.
///
/// Deliberately transport-agnostic. The gRPC client in [`grpc`] is the only
/// thing that knows about streams; tests drive this directly.
pub struct PolicyManager {
    settings: PolicyConfig,
    state: Mutex<State>,
    /// Fires when the wanted set changes, so the stream task re-syncs.
    wanted_changed: Notify,
    /// Fires when any bundle changes, so waiters wake.
    bundle_changed: Notify,
    /// Identities whose published files are now out of date.
    dirty: Mutex<BTreeSet<String>>,
    pub metrics: PolicyMetrics,
}

impl PolicyManager {
    pub fn new(settings: PolicyConfig) -> Arc<PolicyManager> {
        Arc::new(PolicyManager {
            settings,
            state: Mutex::new(State::default()),
            wanted_changed: Notify::new(),
            bundle_changed: Notify::new(),
            dirty: Mutex::new(BTreeSet::new()),
            metrics: PolicyMetrics::default(),
        })
    }

    /// Whether policy distribution is doing anything at all.
    ///
    /// False when the operator switched it off, and false when no endpoint is
    /// configured — there is nothing to connect to either way. Everything else
    /// in this module short-circuits on it, so a disabled manager subscribes to
    /// nothing, writes no policy directory, and never makes publishing wait.
    pub fn enabled(&self) -> bool {
        self.settings.enabled()
    }

    /// Whether the gRPC stream source should run.
    pub fn stream_enabled(&self) -> bool {
        self.settings.stream_enabled()
    }

    /// Whether the OCI rollout source should run.
    pub fn bundle_enabled(&self) -> bool {
        self.settings.bundle_enabled()
    }

    pub fn settings(&self) -> &PolicyConfig {
        &self.settings
    }

    /// Start following an identity. Idempotent.
    pub fn subscribe(&self, spiffe_id: &str) {
        if !self.enabled() {
            return;
        }
        let added = self
            .state
            .lock()
            .expect("policy state poisoned")
            .wanted
            .insert(spiffe_id.to_string());
        if added {
            debug!("subscribing to policy", spiffe_id = spiffe_id);
            self.wanted_changed.notify_waiters();
        }
    }

    /// Stop following an identity and forget its bundle.
    pub fn unsubscribe(&self, spiffe_id: &str) {
        if !self.enabled() {
            return;
        }
        let mut state = self.state.lock().expect("policy state poisoned");
        let removed = state.wanted.remove(spiffe_id);
        state.bundles.remove(spiffe_id);
        drop(state);
        self.dirty
            .lock()
            .expect("policy dirty set poisoned")
            .remove(spiffe_id);
        if removed {
            self.wanted_changed.notify_waiters();
        }
    }

    /// The identities the stream should currently be subscribed to, with the
    /// revision already held for each.
    pub fn wanted(&self) -> Vec<(String, String)> {
        let state = self.state.lock().expect("policy state poisoned");
        state
            .wanted
            .iter()
            .map(|id| {
                let revision = state
                    .bundles
                    .get(id)
                    .map(|b| b.revision.clone())
                    .unwrap_or_default();
                (id.clone(), revision)
            })
            .collect()
    }

    pub fn subscription_count(&self) -> usize {
        self.state
            .lock()
            .expect("policy state poisoned")
            .wanted
            .len()
    }

    /// The bundle to publish for an identity.
    ///
    /// A per-identity bundle from the gRPC stream wins over the fleet-wide one
    /// from the OCI rollout: the more specific source is the more deliberate.
    pub fn bundle(&self, spiffe_id: &str) -> Option<PolicyBundle> {
        let state = self.state.lock().expect("policy state poisoned");
        state
            .bundles
            .get(spiffe_id)
            .cloned()
            .or_else(|| state.fleet.clone())
    }

    /// Record the fleet-wide bundle from the OCI rollout.
    ///
    /// Every subscribed identity without a per-identity bundle is marked dirty,
    /// so the apply loop rewrites their volumes.
    pub fn apply_fleet(&self, bundle: PolicyBundle) -> bool {
        self.metrics
            .updates_received
            .fetch_add(1, Ordering::Relaxed);

        let mut state = self.state.lock().expect("policy state poisoned");
        if state.fleet.as_ref() == Some(&bundle) {
            return false;
        }
        info!(
            "fleet policy updated",
            revision = bundle.revision,
            documents = bundle.documents.len(),
            bytes = bundle.total_bytes(),
        );
        state.fleet = Some(bundle);

        let affected: Vec<String> = state
            .wanted
            .iter()
            .filter(|id| !state.bundles.contains_key(*id))
            .cloned()
            .collect();
        drop(state);

        let mut dirty = self.dirty.lock().expect("policy dirty set poisoned");
        dirty.extend(affected);
        drop(dirty);

        self.bundle_changed.notify_waiters();
        true
    }

    /// The fleet-wide bundle, if one has been applied.
    pub fn fleet_bundle(&self) -> Option<PolicyBundle> {
        self.state
            .lock()
            .expect("policy state poisoned")
            .fleet
            .clone()
    }

    /// Wait until a bundle for `spiffe_id` arrives, or the timeout elapses.
    ///
    /// Used only on the publish path, and only when the operator asked for
    /// policy to be present before a pod starts.
    pub async fn wait_for(&self, spiffe_id: &str, timeout: Duration) -> Option<PolicyBundle> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Some(bundle) = self.bundle(spiffe_id) {
                return Some(bundle);
            }
            // Register before re-checking, so an update that lands between the
            // check and the wait is not missed.
            let notified = self.bundle_changed.notified();
            if let Some(bundle) = self.bundle(spiffe_id) {
                return Some(bundle);
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                self.metrics.wait_timeouts.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        }
    }

    /// Record a bundle received from the backend.
    ///
    /// Returns true when it changed what this node holds, which is what makes
    /// the volume worth rewriting.
    pub fn apply(&self, spiffe_id: &str, bundle: PolicyBundle) -> bool {
        self.metrics
            .updates_received
            .fetch_add(1, Ordering::Relaxed);

        let mut state = self.state.lock().expect("policy state poisoned");
        // An update for something no longer hosted here is not an error: it can
        // arrive between a pod going away and the unsubscribe reaching the
        // backend. Drop it rather than caching it forever.
        if !state.wanted.contains(spiffe_id) {
            debug!(
                "ignoring policy for an identity this node no longer hosts",
                spiffe_id = spiffe_id
            );
            return false;
        }
        if state.bundles.get(spiffe_id) == Some(&bundle) {
            debug!(
                "policy unchanged",
                spiffe_id = spiffe_id,
                revision = bundle.revision
            );
            return false;
        }
        info!(
            "policy updated",
            spiffe_id = spiffe_id,
            revision = bundle.revision,
            documents = bundle.documents.len(),
            bytes = bundle.total_bytes(),
        );
        state.bundles.insert(spiffe_id.to_string(), bundle);
        drop(state);

        self.dirty
            .lock()
            .expect("policy dirty set poisoned")
            .insert(spiffe_id.to_string());
        self.bundle_changed.notify_waiters();
        true
    }

    /// Reject a malformed update without disturbing what is already held.
    pub fn reject(&self, spiffe_id: &str, reason: &str) {
        self.metrics
            .rejected_updates
            .fetch_add(1, Ordering::Relaxed);
        warn!(
            "rejected a policy update from the backend",
            spiffe_id = spiffe_id,
            reason = reason,
        );
    }

    /// Take the set of identities whose volumes need rewriting.
    pub fn take_dirty(&self) -> Vec<String> {
        let mut dirty = self.dirty.lock().expect("policy dirty set poisoned");
        std::mem::take(&mut *dirty).into_iter().collect()
    }

    /// Wait until the wanted set changes. Used by the stream task.
    pub async fn wanted_changed(&self) {
        self.wanted_changed.notified().await;
    }

    pub fn set_connected(&self, connected: bool) {
        let was = self.metrics.connected.swap(connected, Ordering::Relaxed);
        if was != connected {
            if connected {
                info!("policy stream connected");
            } else {
                warn!("policy stream disconnected; existing policy stays in place");
            }
        }
    }
}

/// Fixtures shared by the unit tests and the integration suites.
pub mod testkit {
    use crate::config::{PolicyConfig, PolicySettings};
    use std::time::Duration;

    /// A daemon configuration with only the policy stream turned on.
    pub fn test_config(endpoint: Option<&str>) -> PolicyConfig {
        PolicyConfig {
            node_name: "node-1".into(),
            cluster: "a".into(),
            trust_domain: "example.org".into(),
            driver_name: "csi.svidlet.io".into(),
            kubelet_root: "/var/lib/kubelet".into(),
            spiffe_id_template: svidlet_issue::IdTemplate::DEFAULT.into(),
            spiffe_id_pattern: None,
            stream: PolicySettings {
                enabled: true,
                endpoint: endpoint.map(str::to_string),
                ca_cert_path: None,
                token_path: None,
                reconnect_backoff: Duration::from_millis(10),
            },
            bundle: None,
            scan_interval: Duration::from_millis(50),
            file_mode: 0o644,
            metrics_addr: String::new(),
            log_level: crate::log::Level::Warn,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::test_config;
    use super::*;

    fn settings(enabled: bool) -> PolicyConfig {
        test_config(enabled.then_some("http://policy.invalid:9000"))
    }

    fn doc(name: &str, content: &str) -> PolicyDocument {
        PolicyDocument {
            name: name.into(),
            content: content.as_bytes().to_vec(),
        }
    }

    fn bundle(revision: &str, docs: &[(&str, &str)]) -> PolicyBundle {
        PolicyBundle::build(
            revision.into(),
            docs.iter().map(|(n, c)| doc(n, c)).collect(),
        )
        .unwrap()
    }

    #[test]
    fn documents_are_sorted_so_a_bundle_is_deterministic() {
        let b = bundle("r1", &[("z.rego", "z"), ("a.rego", "a")]);
        let names: Vec<_> = b.documents.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["a.rego", "z.rego"]);
        assert_eq!(b.total_bytes(), 2);
        assert!(!b.is_empty());
        assert!(PolicyBundle::default().is_empty());
    }

    #[test]
    fn document_names_that_could_escape_the_directory_are_refused() {
        for bad in [
            "../etc/passwd",
            "a/b",
            "a\\b",
            "",
            ".",
            "..",
            "..data",
            ".hidden",
        ] {
            let err = PolicyBundle::build("r".into(), vec![doc(bad, "x")]).unwrap_err();
            assert!(!err.is_empty(), "{bad:?} should be rejected");
        }
        for ok in ["authz.rego", "peers.json", "a-b_c.1"] {
            assert!(
                PolicyBundle::build("r".into(), vec![doc(ok, "x")]).is_ok(),
                "{ok}"
            );
        }
    }

    #[test]
    fn a_duplicate_document_name_is_refused() {
        let err = PolicyBundle::build("r".into(), vec![doc("a", "1"), doc("a", "2")]).unwrap_err();
        assert!(err.contains("twice"));
    }

    #[test]
    fn the_flag_switches_off_a_configured_endpoint() {
        // An endpoint is present, but the operator turned the feature off.
        let mut off = settings(true);
        off.stream.enabled = false;
        let m = PolicyManager::new(off);

        assert!(!m.enabled());
        m.subscribe("spiffe://example.org/a");
        assert_eq!(m.subscription_count(), 0);
        assert!(m.bundle("spiffe://example.org/a").is_none());
    }

    #[test]
    fn a_disabled_manager_ignores_everything() {
        let m = PolicyManager::new(settings(false));
        assert!(!m.enabled());
        m.subscribe("spiffe://example.org/a");
        assert_eq!(m.subscription_count(), 0);
        assert!(m.wanted().is_empty());
        // An update for something never subscribed is dropped.
        assert!(!m.apply("spiffe://example.org/a", bundle("r1", &[])));
    }

    #[test]
    fn subscriptions_carry_the_revision_already_held() {
        let m = PolicyManager::new(settings(true));
        let id = "spiffe://example.org/ns/a/sa/b";
        m.subscribe(id);
        assert_eq!(m.wanted(), vec![(id.to_string(), String::new())]);

        assert!(m.apply(id, bundle("r1", &[("authz.rego", "allow")])));
        assert_eq!(m.wanted(), vec![(id.to_string(), "r1".to_string())]);
        assert_eq!(m.bundle(id).unwrap().revision, "r1");
    }

    #[test]
    fn re_applying_the_same_bundle_does_not_dirty_the_volume() {
        let m = PolicyManager::new(settings(true));
        let id = "spiffe://example.org/ns/a/sa/b";
        m.subscribe(id);

        assert!(m.apply(id, bundle("r1", &[("a", "1")])));
        assert_eq!(m.take_dirty(), vec![id.to_string()]);

        // Same revision, same content: nothing to rewrite.
        assert!(!m.apply(id, bundle("r1", &[("a", "1")])));
        assert!(m.take_dirty().is_empty());

        // Changed content: rewrite.
        assert!(m.apply(id, bundle("r2", &[("a", "2")])));
        assert_eq!(m.take_dirty(), vec![id.to_string()]);
        assert_eq!(m.metrics.updates_received.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn unsubscribing_forgets_the_bundle_and_clears_the_dirty_flag() {
        let m = PolicyManager::new(settings(true));
        let id = "spiffe://example.org/ns/a/sa/b";
        m.subscribe(id);
        m.apply(id, bundle("r1", &[("a", "1")]));

        m.unsubscribe(id);
        assert_eq!(m.subscription_count(), 0);
        assert!(m.bundle(id).is_none());
        assert!(m.take_dirty().is_empty());

        // A late update for it is dropped rather than resurrecting it.
        assert!(!m.apply(id, bundle("r2", &[("a", "2")])));
    }

    #[test]
    fn subscribing_twice_is_idempotent() {
        let m = PolicyManager::new(settings(true));
        m.subscribe("spiffe://example.org/a");
        m.subscribe("spiffe://example.org/a");
        assert_eq!(m.subscription_count(), 1);
    }

    #[tokio::test]
    async fn wait_for_returns_as_soon_as_the_bundle_lands() {
        let m = PolicyManager::new(settings(true));
        let id = "spiffe://example.org/ns/a/sa/b";
        m.subscribe(id);

        let waiter = m.clone();
        let handle = tokio::spawn(async move {
            waiter
                .wait_for("spiffe://example.org/ns/a/sa/b", Duration::from_secs(5))
                .await
        });

        // Give the waiter a moment to park, then deliver.
        tokio::time::sleep(Duration::from_millis(20)).await;
        m.apply(id, bundle("r1", &[("a", "1")]));

        let got = handle.await.unwrap().expect("bundle arrives");
        assert_eq!(got.revision, "r1");
        assert_eq!(m.metrics.wait_timeouts.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn wait_for_gives_up_and_counts_the_timeout() {
        let m = PolicyManager::new(settings(true));
        m.subscribe("spiffe://example.org/a");
        assert!(m
            .wait_for("spiffe://example.org/a", Duration::from_millis(30))
            .await
            .is_none());
        assert_eq!(m.metrics.wait_timeouts.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn wait_for_returns_immediately_when_the_bundle_is_already_held() {
        let m = PolicyManager::new(settings(true));
        let id = "spiffe://example.org/a";
        m.subscribe(id);
        m.apply(id, bundle("r1", &[]));
        assert_eq!(
            m.wait_for(id, Duration::from_secs(30))
                .await
                .unwrap()
                .revision,
            "r1"
        );
    }

    #[test]
    fn connection_state_only_logs_on_a_change() {
        let m = PolicyManager::new(settings(true));
        m.set_connected(true);
        m.set_connected(true);
        assert!(m.metrics.connected.load(Ordering::Relaxed));
        m.set_connected(false);
        assert!(!m.metrics.connected.load(Ordering::Relaxed));
    }

    #[test]
    fn rejecting_an_update_counts_it_and_keeps_what_is_held() {
        let m = PolicyManager::new(settings(true));
        let id = "spiffe://example.org/a";
        m.subscribe(id);
        m.apply(id, bundle("r1", &[("a", "1")]));

        m.reject(id, "document name contains a path separator");
        assert_eq!(m.metrics.rejected_updates.load(Ordering::Relaxed), 1);
        assert_eq!(m.bundle(id).unwrap().revision, "r1");
    }
}
