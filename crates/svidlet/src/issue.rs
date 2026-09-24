//! Turning a workload identity into files on a pod's tmpfs.
//!
//! One code path serves both the first issuance (`NodePublishVolume`) and every
//! renewal, so a renewed certificate is written exactly the way the first one
//! was.

use std::path::Path;
use std::sync::{Arc, Mutex};

use svidlet_issue::{
    Error, IdPolicy, IssuedBundle, Issuer, Result, SignRequest, SpiffeId, WorkloadAttributes,
};

use crate::config::Config;
use crate::metrics::Metrics;
use crate::store::Store;
use crate::volume::{self, Identity, Modes};
use crate::{debug, info, warn};

pub struct Publisher {
    pub cfg: Arc<Config>,
    pub issuer: Arc<dyn Issuer>,
    /// The SPIFFE ID shape this node issues, compiled once at start-up.
    pub policy: Arc<IdPolicy>,
    pub store: Arc<Store>,
    pub metrics: Arc<Metrics>,
    /// Trust bundle fetched from the backend's CA endpoint. Preferred over the
    /// chain returned alongside a signature, because it also carries a new root
    /// during a CA rotation, before any leaf has been signed by it.
    ca: Mutex<String>,
}

impl std::fmt::Debug for Publisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The issuer is a trait object; its names are what identify it.
        f.debug_struct("Publisher")
            .field("issuer", &self.issuer.name())
            .field("auth", &self.issuer.auth_name())
            .field("policy", &self.policy)
            .field("volumes", &self.store.len())
            .finish_non_exhaustive()
    }
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
            ca: Mutex::new(String::new()),
        }
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

    /// The Subject Common Name for a workload, per `SVIDLET_CERT_SUBJECT`.
    pub fn common_name(&self, attrs: &WorkloadAttributes) -> Option<String> {
        self.cfg.cert_subject.common_name(attrs)
    }

    /// Generate a key, get it signed, and publish all three files atomically.
    ///
    /// Blocking: the PKI backend is a blocking HTTP client, so callers run this
    /// on a blocking thread.
    pub fn issue(
        &self,
        spiffe_id: &SpiffeId,
        common_name: Option<&str>,
        target: &Path,
    ) -> Result<IssuedBundle> {
        let generated = svidlet_issue::generate(spiffe_id, common_name)?;
        let bundle = self.issuer.sign(&SignRequest {
            spiffe_id,
            csr_pem: &generated.csr_pem,
            common_name,
            ttl: self.cfg.cert_ttl,
            node_name: &self.cfg.node_name,
        })?;
        self.check_cloud_profile(spiffe_id, &bundle.cert_chain_pem);

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

    /// Report anything a configured cloud would refuse about a certificate.
    ///
    /// Never fails issuance: the certificate is a valid SVID for mTLS whatever
    /// a cloud thinks of it, and fail-stale says a cloud-only defect must not
    /// cost a pod its identity. The metric is what to alert on; the log says
    /// which rule and why.
    fn check_cloud_profile(&self, spiffe_id: &SpiffeId, chain: &str) {
        if self.cfg.cloud_profile.is_empty() {
            return;
        }
        match svidlet_issue::profile::check(chain, &self.cfg.cloud_profile) {
            Ok(findings) => {
                for finding in findings {
                    self.metrics.cloud_finding(finding.cloud, finding.rule);
                    warn!(
                        "issued certificate would be refused by a cloud",
                        spiffe_id = spiffe_id,
                        cloud = finding.cloud.as_str(),
                        rule = finding.rule.as_str(),
                        detail = finding.detail,
                    );
                }
            }
            // Unreachable in practice — the chain was parsed moments ago to
            // check its identity — but not worth failing issuance over.
            Err(e) => debug!("cloud profile check could not parse the chain", error = e),
        }
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
            cached.clone_from(&fetched);
        };
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
