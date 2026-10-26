//! The two Kubernetes calls the broker makes: TokenReview, and reading a Pod.
//!
//! Both sit behind [`Kube`] so the attestation rules can be tested without an
//! API server. The production client re-reads its own ServiceAccount token on
//! every call, because the kubelet rotates it.
//!
//! Pods are read with a direct `GET` per request rather than an informer cache
//! (open question 3 in docs/DESIGN.md): liveness (I4) is then as fresh as it
//! can be, and the issuance rate is far below what the API server serves.

use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;
use ureq::tls::{Certificate, RootCerts, TlsConfig};
use ureq::Agent;

use crate::config::KubeSettings;

/// A Kubernetes failure, split by what the broker should answer.
#[derive(Debug)]
pub enum KubeError {
    /// The API server could not be reached or answered 5xx: `503`.
    Unavailable(String),
    /// Anything else unexpected: `500`.
    Other(String),
}

impl std::fmt::Display for KubeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KubeError::Unavailable(m) => write!(f, "API server unavailable: {m}"),
            KubeError::Other(m) => write!(f, "API server: {m}"),
        }
    }
}

/// What a successful TokenReview says about a token.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Review {
    pub username: String,
    /// From `authentication.kubernetes.io/pod-name` and `…/pod-uid`: set for
    /// pod-bound tokens only.
    pub pod_name: Option<String>,
    pub pod_uid: Option<String>,
    /// From `authentication.kubernetes.io/node-name` (Kubernetes 1.30+).
    pub node_name: Option<String>,
}

impl Review {
    /// Split `system:serviceaccount:<ns>:<name>`.
    pub fn service_account(&self) -> Option<(&str, &str)> {
        let rest = self.username.strip_prefix("system:serviceaccount:")?;
        let (ns, name) = rest.split_once(':')?;
        (!ns.is_empty() && !name.is_empty() && !name.contains(':')).then_some((ns, name))
    }
}

/// The parts of a Pod the rules read.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Pod {
    pub namespace: String,
    pub name: String,
    pub uid: String,
    pub node_name: String,
    pub service_account: String,
    pub terminating: bool,
    /// Every container's image: init, regular and ephemeral.
    pub images: Vec<String>,
    /// `(kind, name)` of each owner reference.
    pub owners: Vec<(String, String)>,
}

pub trait Kube: Send + Sync {
    /// `None` when the API server says the token is not authenticated for
    /// `audience`.
    fn token_review(&self, token: &str, audience: &str) -> Result<Option<Review>, KubeError>;

    /// `None` when the pod does not exist.
    fn pod(&self, namespace: &str, name: &str) -> Result<Option<Pod>, KubeError>;
}

pub struct HttpKube {
    base: String,
    token_path: PathBuf,
    agent: Agent,
}

impl HttpKube {
    pub fn new(settings: &KubeSettings) -> Result<HttpKube, String> {
        let pem = std::fs::read(&settings.ca_cert_path).map_err(|e| {
            format!(
                "cannot read the API server CA {}: {e}",
                settings.ca_cert_path.display()
            )
        })?;
        let mut roots = Vec::new();
        for item in ureq::tls::parse_pem(&pem) {
            if let Ok(ureq::tls::PemItem::Certificate(c)) = item {
                roots.push(c);
            }
        }
        if roots.is_empty() {
            return Err("the API server CA file holds no certificate".into());
        }
        Ok(HttpKube {
            base: settings.api_url.trim_end_matches('/').to_string(),
            token_path: settings.token_path.clone(),
            agent: agent(&roots, settings.timeout),
        })
    }

    fn bearer(&self) -> Result<String, KubeError> {
        std::fs::read_to_string(&self.token_path)
            .map(|t| t.trim().to_string())
            .map_err(|e| KubeError::Other(format!("cannot read our own token: {e}")))
    }
}

fn agent(roots: &[Certificate<'static>], timeout: Duration) -> Agent {
    Agent::config_builder()
        .timeout_global(Some(timeout))
        .http_status_as_error(false)
        .tls_config(
            TlsConfig::builder()
                .root_certs(RootCerts::new_with_certs(roots))
                .build(),
        )
        .build()
        .into()
}

fn status_error(status: u16, body: &str) -> KubeError {
    let body: String = body.chars().take(300).collect();
    if status >= 500 || status == 429 {
        KubeError::Unavailable(format!("HTTP {status}: {body}"))
    } else {
        KubeError::Other(format!("HTTP {status}: {body}"))
    }
}

impl Kube for HttpKube {
    fn token_review(&self, token: &str, audience: &str) -> Result<Option<Review>, KubeError> {
        let url = format!("{}/apis/authentication.k8s.io/v1/tokenreviews", self.base);
        let body = serde_json::json!({
            "apiVersion": "authentication.k8s.io/v1",
            "kind": "TokenReview",
            "spec": { "token": token, "audiences": [audience] },
        });
        let mut resp = self
            .agent
            .post(&url)
            .header("Authorization", &format!("Bearer {}", self.bearer()?))
            .send_json(&body)
            .map_err(|e| KubeError::Unavailable(format!("POST tokenreviews: {e}")))?;
        let status = resp.status().as_u16();
        let text = resp.body_mut().read_to_string().unwrap_or_default();
        if !(200..300).contains(&status) {
            return Err(status_error(status, &text));
        }
        parse_review(&text, audience).map_err(KubeError::Other)
    }

    fn pod(&self, namespace: &str, name: &str) -> Result<Option<Pod>, KubeError> {
        if !safe_segment(namespace) || !safe_segment(name) {
            return Ok(None);
        }
        let url = format!("{}/api/v1/namespaces/{namespace}/pods/{name}", self.base);
        let mut resp = self
            .agent
            .get(&url)
            .header("Authorization", &format!("Bearer {}", self.bearer()?))
            .call()
            .map_err(|e| KubeError::Unavailable(format!("GET pod: {e}")))?;
        let status = resp.status().as_u16();
        let text = resp.body_mut().read_to_string().unwrap_or_default();
        if status == 404 {
            return Ok(None);
        }
        if !(200..300).contains(&status) {
            return Err(status_error(status, &text));
        }
        parse_pod(&text).map(Some).map_err(KubeError::Other)
    }
}

/// A name that is safe to put in a URL path: Kubernetes names never need more.
fn safe_segment(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
}

#[derive(Deserialize)]
struct RawReview {
    #[serde(default)]
    status: RawReviewStatus,
}

#[derive(Deserialize, Default)]
struct RawReviewStatus {
    #[serde(default)]
    authenticated: bool,
    #[serde(default)]
    user: RawUser,
    #[serde(default)]
    audiences: Vec<String>,
}

#[derive(Deserialize, Default)]
struct RawUser {
    #[serde(default)]
    username: String,
    #[serde(default)]
    extra: std::collections::HashMap<String, Vec<String>>,
}

/// Parse a TokenReview answer. A review that is not authenticated, or that
/// does not echo the audience we asked for, is `None`.
pub fn parse_review(json: &str, audience: &str) -> Result<Option<Review>, String> {
    let raw: RawReview =
        serde_json::from_str(json).map_err(|e| format!("TokenReview is not JSON: {e}"))?;
    let st = raw.status;
    if !st.authenticated || st.user.username.is_empty() {
        return Ok(None);
    }
    // The API server returns the intersection of the requested audiences and
    // the token's. An empty list means the token is valid for the server's
    // default audience only — not for ours.
    if !st.audiences.iter().any(|a| a == audience) {
        return Ok(None);
    }
    let one = |key: &str| {
        st.user
            .extra
            .get(key)
            .and_then(|v| v.first())
            .filter(|s| !s.is_empty())
            .cloned()
    };
    Ok(Some(Review {
        pod_name: one("authentication.kubernetes.io/pod-name"),
        pod_uid: one("authentication.kubernetes.io/pod-uid"),
        node_name: one("authentication.kubernetes.io/node-name"),
        username: st.user.username,
    }))
}

#[derive(Deserialize)]
struct RawPod {
    metadata: RawMeta,
    #[serde(default)]
    spec: RawSpec,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawMeta {
    #[serde(default)]
    name: String,
    #[serde(default)]
    namespace: String,
    #[serde(default)]
    uid: String,
    #[serde(default)]
    deletion_timestamp: Option<String>,
    #[serde(default)]
    owner_references: Vec<RawOwner>,
}

#[derive(Deserialize)]
struct RawOwner {
    #[serde(default)]
    kind: String,
    #[serde(default)]
    name: String,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct RawSpec {
    #[serde(default)]
    node_name: String,
    #[serde(default)]
    service_account_name: String,
    #[serde(default)]
    containers: Vec<RawContainer>,
    #[serde(default)]
    init_containers: Vec<RawContainer>,
    #[serde(default)]
    ephemeral_containers: Vec<RawContainer>,
}

#[derive(Deserialize)]
struct RawContainer {
    #[serde(default)]
    image: String,
}

pub fn parse_pod(json: &str) -> Result<Pod, String> {
    let raw: RawPod = serde_json::from_str(json).map_err(|e| format!("Pod is not JSON: {e}"))?;
    let images = raw
        .spec
        .init_containers
        .iter()
        .chain(&raw.spec.containers)
        .chain(&raw.spec.ephemeral_containers)
        .map(|c| c.image.clone())
        .collect();
    Ok(Pod {
        namespace: raw.metadata.namespace,
        name: raw.metadata.name,
        uid: raw.metadata.uid,
        node_name: raw.spec.node_name,
        // An unset serviceAccountName means `default`.
        service_account: if raw.spec.service_account_name.is_empty() {
            "default".into()
        } else {
            raw.spec.service_account_name
        },
        terminating: raw.metadata.deletion_timestamp.is_some(),
        images,
        owners: raw
            .metadata
            .owner_references
            .into_iter()
            .map(|o| (o.kind, o.name))
            .collect(),
    })
}
