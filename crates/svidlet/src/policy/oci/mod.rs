//! Pull-based policy distribution: signed OCI bundles with a staged rollout.
//!
//! See docs/POLICY.md. The shape of one poll:
//!
//! 1. fetch the rollout manifest by tag, with an ETag so an unchanged one is a 304;
//! 2. verify its Ed25519 signature against the fleet's public key;
//! 3. work out this node's ring and the digest it should be running;
//! 4. pull that bundle by digest and check the bytes against it;
//! 5. unpack it strictly into `versions/<digest>/`;
//! 6. swap `current` and republish into every pod on the node.
//!
//! Every failure path keeps the bundle already on disk. A node fails **stale**:
//! not open, not closed. That is the property that stops a bad bundle, an
//! unreachable registry or an expired credential from taking a fleet down —
//! the worst case is that policy stops moving, and `bundle_age_seconds` says so.

pub mod registry;
pub mod rollout;
pub mod store;
pub mod tarball;
pub mod verify;

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::config::BundleSettings;
use crate::log::unix_now;
use crate::policy::PolicyManager;
use crate::{debug, error, info, rand, warn};

pub use registry::{Reference, Registry};
pub use rollout::Rollout;
pub use store::{State, Store};
pub use verify::PublicKey;

/// Why a poll did not end with a new bundle in place.
///
/// The variants are the reasons an operator needs to tell apart, and they are
/// the `reason` label on `svidlet_bundle_rejected_total`.
#[derive(Debug)]
pub enum Error {
    /// Bad configuration: an unparsable reference, a key that is not a key.
    Config(String),
    /// The registry could not be reached, or answered non-2xx.
    Fetch(String),
    /// A signature did not verify, or content did not match its digest.
    Signature(String),
    /// Well-formed transport, unusable content.
    Malformed(String),
    /// Understood and deliberately refused: too large, escapes its directory,
    /// an unsupported schema.
    Rejected(String),
    /// A local filesystem operation failed.
    Io(String),
}

impl Error {
    /// The stable metric label.
    pub fn reason(&self) -> &'static str {
        match self {
            Error::Config(_) => "config",
            Error::Fetch(_) => "fetch",
            Error::Signature(_) => "signature",
            Error::Malformed(_) => "malformed",
            Error::Rejected(_) => "rejected",
            Error::Io(_) => "io",
        }
    }

    /// Every reason, so the metric can pre-declare its label set.
    pub const REASONS: [&'static str; 6] = [
        "config",
        "fetch",
        "signature",
        "malformed",
        "rejected",
        "io",
    ];
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Config(m) => write!(f, "bundle configuration is invalid: {m}"),
            Error::Fetch(m) => write!(f, "registry fetch failed: {m}"),
            Error::Signature(m) => write!(f, "signature verification failed: {m}"),
            Error::Malformed(m) => write!(f, "unusable content: {m}"),
            Error::Rejected(m) => write!(f, "refused: {m}"),
            Error::Io(m) => write!(f, "io error: {m}"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Default)]
pub struct BundleMetrics {
    pub polls: AtomicU64,
    pub swaps: AtomicU64,
    pub manifest_invalid: AtomicU64,
    pub fetch_errors: AtomicU64,
    /// Indexed by [`Error::REASONS`].
    pub rejected: [AtomicU64; 6],
    /// Unix seconds of the last poll that reached a verified manifest.
    pub last_success: AtomicU64,
}

impl BundleMetrics {
    fn reject(&self, error: &Error) {
        let index = Error::REASONS
            .iter()
            .position(|r| *r == error.reason())
            .unwrap_or(0);
        self.rejected[index].fetch_add(1, Ordering::Relaxed);
        if matches!(error, Error::Fetch(_)) {
            self.fetch_errors.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn rejected(&self, reason: &str) -> u64 {
        Error::REASONS
            .iter()
            .position(|r| *r == reason)
            .map(|i| self.rejected[i].load(Ordering::Relaxed))
            .unwrap_or(0)
    }
}

/// What the node is currently running, for metrics and logs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Current {
    pub ring: String,
    pub digest: String,
    /// Unix seconds of the last poll that reached a verified manifest.
    pub last_success: i64,
}

/// The pull-based policy source.
pub struct BundleSource {
    settings: BundleSettings,
    cluster: String,
    node: String,
    registry: Registry,
    rollout_ref: Reference,
    bundle_ref: Reference,
    key: PublicKey,
    store: Store,
    state: Mutex<State>,
    pub metrics: BundleMetrics,
}

impl BundleSource {
    pub fn new(
        settings: BundleSettings,
        cluster: String,
        node: String,
    ) -> Result<BundleSource, Error> {
        let rollout_ref = Reference::parse(
            settings
                .rollout_ref
                .as_deref()
                .ok_or_else(|| Error::Config("no rollout reference configured".into()))?,
        )?;
        // Bundles usually live in a sibling repository; default to the rollout
        // manifest's own so a single-repository setup needs no second variable.
        let bundle_ref = match &settings.bundle_repo {
            Some(repo) => Reference::parse(repo)?,
            None => rollout_ref.clone(),
        };

        let key_text = match (&settings.public_key, &settings.public_key_path) {
            (Some(text), _) => text.clone(),
            (None, Some(path)) => std::fs::read_to_string(path).map_err(|e| {
                Error::Config(format!(
                    "cannot read the public key from {}: {e}",
                    path.display()
                ))
            })?,
            (None, None) => {
                return Err(Error::Config(
                    "a trusted public key is required: set SVIDLET_BUNDLE_PUBLIC_KEY \
                     or SVIDLET_BUNDLE_PUBLIC_KEY_FILE"
                        .into(),
                ))
            }
        };
        let key = PublicKey::parse(&key_text)?;

        let ca_cert_pem = match &settings.ca_cert_path {
            Some(path) => Some(
                std::fs::read_to_string(path)
                    .map_err(|e| Error::Config(format!("cannot read {}: {e}", path.display())))?,
            ),
            None => None,
        };
        let registry = Registry::new(
            ca_cert_pem,
            settings.token_path.clone(),
            settings.timeout,
            settings.max_bytes,
        )?;

        let store = Store::new(settings.directory.clone(), settings.keep_versions);
        store.prepare()?;
        let state = store.load_state();

        Ok(BundleSource {
            settings,
            cluster,
            node,
            registry,
            rollout_ref,
            bundle_ref,
            key,
            store,
            state: Mutex::new(state),
            metrics: BundleMetrics::default(),
        })
    }

    pub fn current(&self) -> Current {
        let state = self.state.lock().expect("bundle state poisoned");
        Current {
            ring: state.ring.clone(),
            digest: state.digest.clone(),
            last_success: state.last_success,
        }
    }

    /// Seconds since the last poll that reached a verified manifest, or `None`
    /// if none ever has.
    pub fn age_seconds(&self) -> Option<i64> {
        let last = self.current().last_success;
        (last > 0).then(|| (unix_now() - last).max(0))
    }

    /// This node's bucket, exposed so an operator can predict its ring.
    pub fn bucket(&self) -> u32 {
        rollout::node_bucket(&self.cluster, &self.node)
    }

    /// Read whatever is currently published, without touching the network.
    ///
    /// Used at start-up so a node that already has a bundle serves it to pods
    /// immediately rather than waiting for the first poll.
    pub fn load_current(&self) -> Option<crate::policy::PolicyBundle> {
        let digest = self.current().digest;
        if digest.is_empty() || !self.store.has(&digest) {
            return None;
        }
        self.store.read(&digest).ok()
    }

    /// One full poll. Returns the bundle to publish when it changed.
    ///
    /// Blocking: the registry client blocks, so callers run this off the reactor.
    pub fn poll(&self) -> Result<Option<crate::policy::PolicyBundle>, Error> {
        self.metrics.polls.fetch_add(1, Ordering::Relaxed);

        let etag = self.current_etag();
        let fetched = self.registry.manifest(&self.rollout_ref, etag.as_deref())?;
        let (manifest, new_etag) = match fetched {
            registry::Fetched::Unchanged => {
                debug!("rollout manifest unchanged");
                self.record_success(None);
                return Ok(None);
            }
            registry::Fetched::Changed { manifest, etag } => (manifest, etag),
        };

        let envelope = self.registry.single_layer(&self.rollout_ref, &manifest)?;
        let toml = verify::open(&envelope, &self.key)?;
        let rollout = Rollout::parse(&toml)?;
        let _ = self.store.save_manifest(&toml);
        self.record_success(new_etag);

        if rollout.freeze {
            // The kill switch. Deliberately blocks rollbacks too: a human
            // looking at a live incident should not be racing an automated
            // promotion, in either direction.
            warn!("rollout is frozen; no bundle change will be applied");
            return Ok(None);
        }

        let Some(ring) = rollout.target(&self.cluster, &self.node) else {
            warn!(
                "no ring in the rollout manifest matches this node",
                cluster = self.cluster,
                node = self.node,
                bucket = self.bucket(),
            );
            return Ok(None);
        };

        let current = self.current();
        if current.digest == ring.bundle && self.store.has(&ring.bundle) {
            if current.ring != ring.name {
                info!(
                    "ring changed but the bundle did not",
                    from = current.ring,
                    to = ring.name,
                );
                self.set_current(&ring.name, &ring.bundle);
            }
            return Ok(None);
        }

        info!(
            "rolling out a new bundle",
            ring = ring.name,
            from = if current.digest.is_empty() {
                "<none>"
            } else {
                &current.digest
            },
            to = ring.bundle,
            bucket = self.bucket(),
        );

        // Already unpacked? A rollback to the previous version needs no network.
        if !self.store.has(&ring.bundle) {
            let blob = self.registry.blob(&self.bundle_ref, &ring.bundle)?;
            // This is the link in the chain that makes the manifest's signature
            // cover the bundle: the signed manifest named this digest, and
            // these are the bytes that hash to it.
            verify::check_digest(&blob, &ring.bundle)?;
            let entries = tarball::extract(&blob, self.settings.max_bytes)?;
            validate(&entries)?;
            self.store.write_version(&ring.bundle, &entries)?;
        } else {
            debug!("bundle already on disk", digest = ring.bundle);
        }

        self.store.set_current(&ring.bundle)?;
        let bundle = self.store.read(&ring.bundle)?;
        self.set_current(&ring.name, &ring.bundle);
        self.metrics.swaps.fetch_add(1, Ordering::Relaxed);

        let previous = current.digest.clone();
        let keep: Vec<&str> = [ring.bundle.as_str(), previous.as_str()]
            .into_iter()
            .filter(|d| !d.is_empty())
            .collect();
        self.store.prune(&keep);

        info!(
            "bundle applied",
            ring = ring.name,
            digest = ring.bundle,
            documents = bundle.documents.len(),
            bytes = bundle.total_bytes(),
        );
        Ok(Some(bundle))
    }

    fn current_etag(&self) -> Option<String> {
        let state = self.state.lock().expect("bundle state poisoned");
        // An ETag is only usable while the bundle it went with is still on
        // disk; otherwise a 304 would leave the node with nothing to publish.
        if state.digest.is_empty() || self.store.has(&state.digest) {
            Some(state.manifest_etag.clone()).filter(|e| !e.is_empty())
        } else {
            None
        }
    }

    fn record_success(&self, etag: Option<String>) {
        let now = unix_now();
        self.metrics
            .last_success
            .store(now as u64, Ordering::Relaxed);
        let mut state = self.state.lock().expect("bundle state poisoned");
        state.last_success = now;
        state.last_error.clear();
        if let Some(etag) = etag {
            state.manifest_etag = etag;
        }
        let snapshot = state.clone();
        drop(state);
        let _ = self.store.save_state(&snapshot);
    }

    fn set_current(&self, ring: &str, digest: &str) {
        let mut state = self.state.lock().expect("bundle state poisoned");
        state.ring = ring.to_string();
        state.digest = digest.to_string();
        state.applied_at = unix_now();
        let snapshot = state.clone();
        drop(state);
        let _ = self.store.save_state(&snapshot);
    }

    fn record_error(&self, error: &Error) {
        self.metrics.reject(error);
        if matches!(error, Error::Signature(_) | Error::Malformed(_)) {
            self.metrics
                .manifest_invalid
                .fetch_add(1, Ordering::Relaxed);
        }
        let mut state = self.state.lock().expect("bundle state poisoned");
        state.last_error = error.to_string();
        let snapshot = state.clone();
        drop(state);
        let _ = self.store.save_state(&snapshot);
    }
}

/// Node-side validation, before anything reaches a version directory.
///
/// The design's `selftest/` cases are deliberately not run: executing code from
/// a downloaded artifact on every node in a fleet is a large thing to add for a
/// benefit the design does not specify. What is checked is the rest — that the
/// bundle declares a schema this build understands.
fn validate(entries: &[tarball::Entry]) -> Result<(), Error> {
    let Some(manifest) = entries.iter().find(|e| e.path == "bundle.toml") else {
        // Not fatal by itself, but worth being strict about: a bundle with no
        // manifest is almost always a packaging mistake, and accepting it means
        // the schema check never runs again.
        return Err(Error::Rejected(
            "bundle has no bundle.toml at its root".into(),
        ));
    };

    #[derive(serde::Deserialize)]
    struct BundleManifest {
        schema: u32,
    }

    let text = std::str::from_utf8(&manifest.content)
        .map_err(|e| Error::Malformed(format!("bundle.toml is not UTF-8: {e}")))?;
    let parsed: BundleManifest = basic_toml::from_str(text)
        .map_err(|e| Error::Malformed(format!("bundle.toml is not valid TOML: {e}")))?;

    if parsed.schema != rollout::SUPPORTED_SCHEMA {
        return Err(Error::Rejected(format!(
            "bundle.toml declares schema {}, and this build understands {}",
            parsed.schema,
            rollout::SUPPORTED_SCHEMA
        )));
    }
    Ok(())
}

/// Poll forever, feeding whatever changes into the policy manager.
pub async fn poll_loop(source: Arc<BundleSource>, policy: Arc<PolicyManager>) {
    // Publish what is already on disk before the first poll, so a restarted
    // node serves policy to pods immediately rather than after an interval.
    if let Some(bundle) = source.load_current() {
        info!(
            "resuming the bundle this node already had",
            digest = bundle.revision,
            documents = bundle.documents.len(),
        );
        policy.apply_fleet(bundle);
    }

    loop {
        let interval = jittered(source.settings.poll_interval, source.settings.poll_jitter);
        tokio::time::sleep(interval).await;

        let polling = source.clone();
        let outcome = tokio::task::spawn_blocking(move || polling.poll()).await;

        match outcome {
            Ok(Ok(Some(bundle))) => {
                policy.apply_fleet(bundle);
            }
            Ok(Ok(None)) => {}
            Ok(Err(e)) => {
                source.record_error(&e);
                // Never an error-level event on its own: the node keeps the
                // bundle it has, and traffic is unaffected. What deserves an
                // alert is age, not any single failed poll.
                warn!(
                    "bundle poll failed; keeping the current bundle",
                    reason = e.reason(),
                    error = e,
                    current = source.current().digest,
                    age_secs = source.age_seconds().unwrap_or(-1),
                );
            }
            Err(e) => error!("bundle poll task panicked", error = e),
        }
    }
}

/// `interval ± jitter`, so a fleet does not poll the registry in lockstep.
fn jittered(interval: std::time::Duration, jitter: std::time::Duration) -> std::time::Duration {
    let base = interval.as_secs_f64();
    let spread = jitter.as_secs_f64().min(base);
    let offset = (rand::unit() * 2.0 - 1.0) * spread;
    std::time::Duration::from_secs_f64((base + offset).max(1.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn entry(path: &str, content: &str) -> tarball::Entry {
        tarball::Entry {
            path: path.into(),
            content: content.as_bytes().to_vec(),
        }
    }

    #[test]
    fn error_reasons_are_stable_label_values_and_all_reachable() {
        let samples = [
            Error::Config("x".into()),
            Error::Fetch("x".into()),
            Error::Signature("x".into()),
            Error::Malformed("x".into()),
            Error::Rejected("x".into()),
            Error::Io("x".into()),
        ];
        let mut seen: Vec<&str> = samples.iter().map(Error::reason).collect();
        seen.sort_unstable();
        let mut all = Error::REASONS.to_vec();
        all.sort_unstable();
        assert_eq!(seen, all);

        for reason in Error::REASONS {
            assert!(reason.bytes().all(|b| b.is_ascii_lowercase()), "{reason}");
        }
    }

    #[test]
    fn rejections_are_counted_against_their_reason() {
        let metrics = BundleMetrics::default();
        metrics.reject(&Error::Fetch("down".into()));
        metrics.reject(&Error::Fetch("down".into()));
        metrics.reject(&Error::Signature("bad".into()));

        assert_eq!(metrics.rejected("fetch"), 2);
        assert_eq!(metrics.rejected("signature"), 1);
        assert_eq!(metrics.rejected("io"), 0);
        // A fetch failure is also counted on its own series, because "can we
        // reach the registry" is the first question during an incident.
        assert_eq!(metrics.fetch_errors.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.rejected("nonsense"), 0);
    }

    #[test]
    fn a_bundle_must_declare_a_schema_this_build_understands() {
        assert!(validate(&[entry("bundle.toml", "schema = 1\nenforce = true\n")]).is_ok());

        let err = validate(&[entry("rules/a.rego", "x")]).unwrap_err();
        assert!(matches!(err, Error::Rejected(_)));
        assert!(err.to_string().contains("no bundle.toml"));

        let err = validate(&[entry("bundle.toml", "schema = 99\n")]).unwrap_err();
        assert!(matches!(err, Error::Rejected(_)));

        let err = validate(&[entry("bundle.toml", "not toml [[[")]).unwrap_err();
        assert!(matches!(err, Error::Malformed(_)));
    }

    #[test]
    fn poll_jitter_stays_inside_its_window_and_never_hits_zero() {
        rand::seed();
        for _ in 0..500 {
            let d = jittered(Duration::from_secs(60), Duration::from_secs(30));
            assert!(
                (30..=90).contains(&d.as_secs()),
                "{}s is outside 60±30",
                d.as_secs()
            );
        }
        // A jitter wider than the interval must not produce a zero sleep.
        for _ in 0..500 {
            let d = jittered(Duration::from_secs(2), Duration::from_secs(60));
            assert!(d.as_secs_f64() >= 1.0);
        }
    }
}
