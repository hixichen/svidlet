//! Turning a workload identity into files on a pod's tmpfs.
//!
//! One code path serves both the first issuance (`NodePublishVolume`) and every
//! renewal, so a renewed certificate is written exactly the way the first one
//! was.

use std::path::Path;
use std::sync::{Arc, Mutex};

use svidlet_issue::{
    BrokerClient, Error, IdPolicy, IssuedBundle, Issuer, PodContext, Result, SignRequest, SpiffeId,
    WorkloadAttributes,
};

use crate::config::Config;
use crate::metrics::Metrics;
use crate::store::{PodRef, PodToken, Store};
use crate::volume::{self, Identity, Modes};
use crate::{debug, info};

pub struct Publisher {
    pub cfg: Arc<Config>,
    pub issuer: Arc<dyn Issuer>,
    /// The SPIFFE ID shape this node issues, compiled once at start-up.
    pub policy: Arc<IdPolicy>,
    pub store: Arc<Store>,
    pub metrics: Arc<Metrics>,
    /// The broker, when this node uses one. Also `issuer`; held separately
    /// for the token path, which is not part of the `Issuer` seam.
    pub broker: Option<Arc<BrokerClient>>,
    /// Trust bundle fetched from the backend's CA endpoint. Preferred over the
    /// chain returned alongside a signature, because it also carries a new root
    /// during a CA rotation, before any leaf has been signed by it.
    ca: Mutex<String>,
}

impl Publisher {
    pub fn new(
        cfg: Arc<Config>,
        policy: Arc<IdPolicy>,
        issuer: Arc<dyn Issuer>,
        store: Arc<Store>,
        metrics: Arc<Metrics>,
    ) -> Self {
        Publisher {
            cfg,
            issuer,
            policy,
            store,
            metrics,
            broker: None,
            ca: Mutex::new(String::new()),
        }
    }

    /// Fetch tokens from this broker as well as certificates.
    pub fn with_broker(mut self, broker: Arc<BrokerClient>) -> Self {
        self.broker = Some(broker);
        self
    }

    fn modes(&self) -> Modes {
        Modes {
            key: self.cfg.key_mode,
            cert: self.cfg.cert_mode,
            key_gid: self.cfg.key_gid,
        }
    }

    fn cached_ca(&self) -> String {
        self.ca.lock().expect("ca mutex poisoned").clone()
    }

    /// Render the SPIFFE ID for a workload, applying the operator's pattern.
    pub fn spiffe_id(&self, attrs: &WorkloadAttributes) -> Result<SpiffeId> {
        self.policy.render(attrs)
    }

    /// Generate a key, get it signed, and publish all three files atomically.
    ///
    /// Blocking: the PKI backend is a blocking HTTP client, so callers run this
    /// on a blocking thread.
    pub fn issue(
        &self,
        spiffe_id: &SpiffeId,
        target: &Path,
        pod: &PodRef,
        pod_token: Option<&PodToken>,
    ) -> Result<IssuedBundle> {
        let generated = svidlet_issue::generate(spiffe_id)?;
        let bundle = self.issuer.sign(&SignRequest {
            spiffe_id,
            csr_pem: &generated.csr_pem,
            ttl: self.cfg.cert_ttl,
            node_name: &self.cfg.node_name,
            pod: Some(PodContext {
                namespace: &pod.namespace,
                name: &pod.name,
                uid: &pod.uid,
                service_account: &pod.service_account,
                token: pod_token.map(|t| t.0.as_str()),
            }),
        })?;

        // §5.2: the leaf must be for the key this node just generated. A
        // certificate for any other key would be useless to the workload, and
        // one the backend should never have returned.
        if svidlet_issue::leaf_public_key(&bundle.cert_chain_pem)? != generated.public_key {
            return Err(Error::Certificate(
                "the signed certificate is not for the key this node generated".into(),
            ));
        }

        let cached = self.cached_ca();
        let ca_pem = if cached.is_empty() {
            bundle.ca_pem.clone()
        } else {
            cached
        };

        volume::publish_identity(
            target,
            &Identity {
                key_pem: generated.key_pem,
                cert_chain_pem: bundle.cert_chain_pem.clone(),
                ca_pem,
            },
            self.modes(),
        )?;
        Ok(bundle)
    }

    /// Check in with the broker for this volume's tokens and rewrite `jwt/`
    /// if any changed (§6.2). Returns whether anything was written.
    ///
    /// Does nothing without a broker or with tokens switched off. On failure
    /// the files already published stay until they expire: fail stale.
    pub fn refresh_tokens(&self, target: &Path) -> Result<bool> {
        let Some(broker) = &self.broker else {
            return Ok(false);
        };
        if !self.cfg.broker.as_ref().is_some_and(|b| b.jwt_enabled) {
            return Ok(false);
        }
        let identity = volume::read_identity(target)?;
        let grants = broker.fetch_tokens(&identity.cert_chain_pem, &identity.key_pem)?;
        let fresh: std::collections::BTreeMap<String, String> =
            grants.into_iter().map(|g| (g.alias, g.token)).collect();
        if fresh == volume::read_tokens(target) {
            return Ok(false);
        }
        volume::publish_tokens(target, &fresh, self.modes())?;
        Ok(true)
    }

    /// Fetch the trust bundle and, if it changed, rewrite `ca.crt` in every
    /// published volume without re-issuing anything.
    ///
    /// Returns the number of volumes updated.
    pub fn refresh_ca(&self) -> Result<usize> {
        let fetched = self.issuer.ca_chain()?;
        {
            let mut cached = self.ca.lock().expect("ca mutex poisoned");
            if *cached == fetched {
                return Ok(0);
            }
            *cached = fetched.clone();
        }
        info!(
            "trust bundle changed; rewriting ca.crt",
            volumes = self.store.len()
        );

        let mut updated = 0;
        for entry in self.store.all() {
            let current = match volume::read_identity(&entry.target_path) {
                Ok(m) => m,
                Err(e) => {
                    debug!(
                        "skipping ca.crt refresh for unreadable volume",
                        path = entry.target_path.display(),
                        error = e
                    );
                    continue;
                }
            };
            if current.ca_pem == fetched {
                continue;
            }
            let refreshed = Identity {
                ca_pem: fetched.clone(),
                ..current
            };
            match volume::publish_identity(&entry.target_path, &refreshed, self.modes()) {
                Ok(()) => updated += 1,
                Err(e) => {
                    debug!(
                        "ca.crt refresh failed",
                        path = entry.target_path.display(),
                        error = e
                    );
                }
            }
        }
        Ok(updated)
    }

    /// Seed the trust bundle cache at start-up.
    ///
    /// A failure here is not fatal: the CA chain returned with the first
    /// signature is a usable substitute, and the periodic refresh will retry.
    pub fn prime_ca(&self) -> Result<()> {
        let fetched = self.issuer.ca_chain()?;
        if !fetched.contains("-----BEGIN CERTIFICATE-----") {
            return Err(Error::Protocol("trust bundle is not PEM".into()));
        }
        *self.ca.lock().expect("ca mutex poisoned") = fetched;
        Ok(())
    }
}
