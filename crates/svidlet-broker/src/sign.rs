//! The certificate path (docs/DESIGN.md §5): attest the caller and the pod,
//! enforce I1–I11, and ask Vault PKI to sign.

use std::sync::Arc;

use svidlet_issue::broker::SignBody;
use svidlet_issue::{IdPolicy, IssuedBundle, Issuer, SignRequest, SpiffeId, WorkloadAttributes};

use crate::catalog::CatalogHandle;
use crate::config::Config;
use crate::csr;
use crate::kube::{Kube, Pod};
use crate::limit::{Distinct, Window};
use crate::refusal::{from_vault, Refusal};

/// Who asked, and for what — the audit record of a successful issuance.
#[derive(Debug, Clone)]
pub struct Signed {
    pub spiffe_id: SpiffeId,
    pub node: String,
    pub namespace: String,
    pub pod: String,
    pub pod_uid: String,
    pub bundle: IssuedBundle,
}

pub struct Signer {
    pub cfg: Arc<Config>,
    pub policy: Arc<IdPolicy>,
    pub kube: Arc<dyn Kube>,
    pub issuer: Arc<dyn Issuer>,
    pub catalog: CatalogHandle,
    node_rate: Window,
    node_identities: Distinct,
}

impl Signer {
    pub fn new(
        cfg: Arc<Config>,
        policy: Arc<IdPolicy>,
        kube: Arc<dyn Kube>,
        issuer: Arc<dyn Issuer>,
        catalog: CatalogHandle,
    ) -> Signer {
        Signer {
            node_rate: Window::new(cfg.node_rate_per_minute, 60),
            node_identities: Distinct::new(cfg.node_identities_per_hour, 3600),
            cfg,
            policy,
            kube,
            issuer,
            catalog,
        }
    }

    pub fn sweep(&self, now: i64) {
        self.node_rate.sweep(now);
        self.node_identities.sweep(now);
    }

    /// Authenticate the caller as `svidlet-node` on some node, and return
    /// that node's name.
    pub fn attest_node(&self, node_token: &str) -> Result<String, Refusal> {
        if node_token.is_empty() {
            return Err(Refusal::unauthenticated("I1", "no node token"));
        }
        let review = self
            .kube
            .token_review(node_token, &self.cfg.audience)?
            .ok_or_else(|| Refusal::unauthenticated("I1", "the node token did not authenticate"))?;
        if review.username != self.cfg.node_username() {
            return Err(Refusal::forbidden(
                "I1",
                format!("{} is not {}", review.username, self.cfg.node_username()),
            ));
        }
        let (Some(pod_name), Some(pod_uid)) = (&review.pod_name, &review.pod_uid) else {
            return Err(Refusal::forbidden(
                "I1",
                "the node token is not bound to a pod",
            ));
        };
        let pod = self
            .kube
            .pod(&self.cfg.node_namespace, pod_name)?
            .ok_or_else(|| {
                Refusal::forbidden("I1", format!("node pod {pod_name} does not exist"))
            })?;
        if pod.uid != *pod_uid || pod.terminating {
            return Err(Refusal::forbidden(
                "I1",
                format!("node pod {pod_name} is not live"),
            ));
        }
        if !pod
            .owners
            .iter()
            .any(|(kind, name)| kind == "DaemonSet" && *name == self.cfg.node_daemonset)
        {
            return Err(Refusal::forbidden(
                "I1",
                format!(
                    "{pod_name} is not a {} DaemonSet pod",
                    self.cfg.node_daemonset
                ),
            ));
        }
        if pod.node_name.is_empty() {
            return Err(Refusal::forbidden(
                "I1",
                format!("{pod_name} is not scheduled"),
            ));
        }
        // The token's own node claim, where the API server provides one, must
        // agree with where the pod actually runs.
        if let Some(n) = &review.node_name {
            if *n != pod.node_name {
                return Err(Refusal::forbidden(
                    "I3",
                    "node token and node pod disagree on the node",
                ));
            }
        }
        Ok(pod.node_name)
    }

    /// Authenticate the pod token and check the pod it is bound to (I1, I3,
    /// I4, I5). Returns the live pod.
    pub fn attest_pod(&self, pod_token: &str, node: &str) -> Result<Pod, Refusal> {
        if pod_token.is_empty() {
            return Err(Refusal::unauthenticated("I5", "no pod token"));
        }
        let review = self
            .kube
            .token_review(pod_token, &self.cfg.audience)?
            .ok_or_else(|| Refusal::unauthenticated("I5", "the pod token did not authenticate"))?;
        let Some((ns, sa)) = review.service_account() else {
            return Err(Refusal::forbidden(
                "I1",
                format!("{} is not a ServiceAccount", review.username),
            ));
        };
        let (Some(pod_name), Some(pod_uid)) = (&review.pod_name, &review.pod_uid) else {
            return Err(Refusal::forbidden(
                "I1",
                "the pod token is not bound to a pod",
            ));
        };
        let pod = self.kube.pod(ns, pod_name)?.ok_or_else(|| {
            Refusal::forbidden("I4", format!("pod {ns}/{pod_name} does not exist"))
        })?;
        if pod.uid != *pod_uid {
            return Err(Refusal::forbidden(
                "I4",
                "the pod was replaced; its UID changed",
            ));
        }
        if pod.terminating {
            return Err(Refusal::forbidden("I4", "the pod is terminating"));
        }
        if pod.service_account != sa {
            return Err(Refusal::forbidden(
                "I4",
                "the pod's ServiceAccount does not match its token",
            ));
        }
        if pod.node_name != node {
            return Err(Refusal::forbidden(
                "I3",
                format!(
                    "pod {ns}/{pod_name} runs on {:?}, not on the calling node {node}",
                    pod.node_name
                ),
            ));
        }
        if let Some(n) = &review.node_name {
            if n != node {
                return Err(Refusal::forbidden(
                    "I3",
                    "the pod token was minted for another node",
                ));
            }
        }
        Ok(pod)
    }

    /// I8 and I9 for one pod.
    pub fn admit(&self, pod: &Pod) -> Result<(), Refusal> {
        if self.cfg.denied_namespaces.contains(&pod.namespace) {
            return Err(Refusal::forbidden(
                "I8",
                format!("namespace {} receives no identity", pod.namespace),
            ));
        }
        if pod.service_account == "default" {
            return Err(Refusal::forbidden(
                "I8",
                "the default ServiceAccount receives no identity",
            ));
        }
        let catalog = self.catalog.current();
        let entry = catalog.lookup(&self.cfg.cluster, &pod.namespace, &pod.service_account);
        if catalog.mode.allowlist && entry.is_none() {
            return Err(Refusal::forbidden(
                "I8",
                format!(
                    "{}/{} is not in the catalog",
                    pod.namespace, pod.service_account
                ),
            ));
        }
        if entry.is_some_and(|e| e.sensitive) {
            for image in &pod.images {
                if !image.contains("@sha256:") {
                    return Err(Refusal::forbidden(
                        "I9",
                        format!("image {image} is not pinned by digest"),
                    ));
                }
                if !catalog
                    .sensitive
                    .registries
                    .iter()
                    .any(|r| image.starts_with(r.as_str()))
                {
                    return Err(Refusal::forbidden(
                        "I9",
                        format!("image {image} is not from an approved registry"),
                    ));
                }
            }
        }
        Ok(())
    }

    /// The whole certificate path. Blocking: Kubernetes and Vault are both
    /// blocking HTTP clients.
    pub fn sign(&self, node_token: &str, body: &SignBody, now: i64) -> Result<Signed, Refusal> {
        let node = self.attest_node(node_token)?;
        let pod = self.attest_pod(&body.pod_token, &node)?;

        // I1: the request's names are hints. Disagreeing with the attested pod
        // is not an attack vector — they are never used — but it is a bug
        // worth surfacing rather than signing past.
        for (hint, actual, what) in [
            (&body.namespace, &pod.namespace, "namespace"),
            (&body.pod_name, &pod.name, "pod name"),
            (&body.pod_uid, &pod.uid, "pod UID"),
            (
                &body.service_account,
                &pod.service_account,
                "ServiceAccount",
            ),
        ] {
            if !hint.is_empty() && hint != actual {
                return Err(Refusal::bad(
                    "I1",
                    format!("{what} {hint:?} does not match the pod token ({actual:?})"),
                ));
            }
        }

        self.admit(&pod)?;
        csr::check(&body.csr).map_err(|m| Refusal::bad("I6", m))?;

        // I7: render the ID from attested attributes and the configured
        // cluster only (I2), then check it against the pattern.
        let attrs = WorkloadAttributes {
            trust_domain: self.cfg.trust_domain.clone(),
            cluster: self.cfg.cluster.clone(),
            namespace: pod.namespace.clone(),
            service_account: pod.service_account.clone(),
            pod_name: pod.name.clone(),
            pod_uid: pod.uid.clone(),
            node_name: node.clone(),
        };
        let spiffe_id = self
            .policy
            .render(&attrs)
            .map_err(|e| Refusal::forbidden("I7", e.to_string()))?;
        if !body.spiffe_id.is_empty() && body.spiffe_id != spiffe_id.as_str() {
            return Err(Refusal::bad(
                "I7",
                format!("the node expects {} but the broker issues {spiffe_id}; check both SPIFFE ID templates", body.spiffe_id),
            ));
        }

        // I10, counted only for requests that passed every other check, so a
        // flood of garbage cannot lock a node out of renewals.
        if !self.node_rate.allow(&node, now) {
            return Err(Refusal::too_many(
                "I10",
                format!("node {node} is over its issuance rate"),
            ));
        }
        if !self.node_identities.allow(&node, spiffe_id.as_str(), now) {
            return Err(Refusal::too_many(
                "I10",
                format!("node {node} asked for too many distinct identities this hour"),
            ));
        }

        let bundle = self
            .issuer
            .sign(&SignRequest {
                spiffe_id: &spiffe_id,
                csr_pem: &body.csr,
                ttl: self.cfg.effective_ttl(), // I11
                node_name: &node,
                pod: None,
            })
            .map_err(from_vault)?;

        Ok(Signed {
            spiffe_id,
            node,
            namespace: pod.namespace,
            pod: pod.name,
            pod_uid: pod.uid,
            bundle,
        })
    }
}
