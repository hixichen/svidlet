//! The node's client for `svidlet-broker`.
//!
//! With a broker, the node holds nothing that can sign and nothing that can
//! talk to Vault. It proves two things on every certificate request — that it
//! is `svidlet-node` on this node (its own projected token) and that the
//! kubelet on this node asked for this pod (the pod token the kubelet handed
//! to the CSI driver) — and the broker does the rest. See docs/DESIGN.md §5.
//!
//! Tokens are fetched over mTLS with the pod's own certificate and key, so the
//! broker derives the token subject from the certificate and never from
//! anything the node says (§6).

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use ureq::tls::{Certificate, ClientCert, PemItem, PrivateKey, RootCerts, TlsConfig};
use ureq::Agent;

use crate::bundle::{assert_identity, IssuedBundle};
use crate::error::{Error, Result};
use crate::issuer::{Issuer, SignRequest};

/// Where the broker is and how to trust it.
#[derive(Debug, Clone)]
pub struct BrokerEndpoint {
    /// Certificate port, e.g. `https://svidlet-broker.svidlet-system.svc:8443`.
    pub sign_url: String,
    /// Token port, e.g. `https://svidlet-broker.svidlet-system.svc:8444`.
    pub token_url: String,
    /// PEM bundle that signed the broker's serving certificate. For the token
    /// port this is normally the trust domain's own `ca.crt`.
    pub ca_cert_pem: String,
    /// The node's own projected token, audience `svidlet-broker`. Re-read on
    /// every request because the kubelet rotates it.
    pub node_token_path: PathBuf,
    pub timeout: Duration,
}

/// `POST /v1/sign`.
#[derive(Debug, Serialize, Deserialize)]
pub struct SignBody {
    pub pod_token: String,
    pub namespace: String,
    pub pod_name: String,
    pub pod_uid: String,
    pub service_account: String,
    pub csr: String,
    /// What the node expects the ID to be. The broker renders its own and
    /// refuses a mismatch, so a template drift between node and broker is an
    /// error message rather than a surprising certificate.
    pub spiffe_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignReply {
    pub spiffe_id: String,
    pub cert_chain: String,
    pub ca: String,
    pub not_after: i64,
}

/// One token in `POST /v1/tokens`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenGrant {
    pub alias: String,
    pub audience: String,
    pub token: String,
    pub exp: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokensReply {
    pub tokens: Vec<TokenGrant>,
}

/// The broker's error body.
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorReply {
    pub error: String,
    /// The invariant or rule that refused the request, e.g. `I3`.
    #[serde(default)]
    pub rule: String,
}

/// Turn a broker status into the error taxonomy the CSI plugin already maps
/// onto gRPC codes and retry decisions.
pub fn classify(status: u16, body: &str) -> Error {
    let detail = serde_json::from_str::<ErrorReply>(body)
        .map(|e| {
            if e.rule.is_empty() {
                e.error
            } else {
                format!("{} ({})", e.error, e.rule)
            }
        })
        .unwrap_or_else(|_| body.chars().take(512).collect());
    match status {
        400 => Error::Identity(format!("broker: {detail}")),
        401 => Error::Auth(format!("broker: {detail}")),
        403 => Error::Policy(format!("broker refused: {detail}")),
        _ => Error::Backend {
            status,
            body: format!("broker: {detail}"),
        },
    }
}

pub struct BrokerClient {
    endpoint: BrokerEndpoint,
    roots: Vec<Certificate<'static>>,
    agent: Agent,
}

impl BrokerClient {
    pub fn new(endpoint: BrokerEndpoint) -> Result<BrokerClient> {
        let roots = certificates(&endpoint.ca_cert_pem)
            .map_err(|e| Error::Config(format!("broker CA bundle: {e}")))?;
        if roots.is_empty() {
            return Err(Error::Config(
                "broker CA bundle holds no certificate".into(),
            ));
        }
        let agent = agent(&endpoint, &roots, None);
        Ok(BrokerClient {
            endpoint,
            roots,
            agent,
        })
    }

    fn node_token(&self) -> Result<String> {
        let raw = std::fs::read_to_string(&self.endpoint.node_token_path).map_err(|e| {
            Error::Auth(format!(
                "cannot read the node token from {}: {e}",
                self.endpoint.node_token_path.display()
            ))
        })?;
        let token = raw.trim();
        if token.is_empty() {
            return Err(Error::Auth("the node token file is empty".into()));
        }
        Ok(token.to_string())
    }

    /// Fetch every approved token for the identity in `cert_chain_pem`.
    ///
    /// Called with the pod's own certificate and key: that pair *is* the
    /// authentication, and the broker answers only for the identity in it.
    pub fn fetch_tokens(&self, cert_chain_pem: &str, key_pem: &str) -> Result<Vec<TokenGrant>> {
        let chain = certificates(cert_chain_pem)
            .map_err(|e| Error::Certificate(format!("pod certificate: {e}")))?;
        let key = PrivateKey::from_pem(key_pem.as_bytes())
            .map_err(|e| Error::Crypto(format!("pod key: {e}")))?;
        // One agent per call: the client certificate differs per pod, and a
        // check-in every fifteen minutes does not need connection reuse.
        let agent = agent(
            &self.endpoint,
            &self.roots,
            Some(ClientCert::new_with_certs(&chain, key)),
        );
        let url = format!(
            "{}/v1/tokens",
            self.endpoint.token_url.trim_end_matches('/')
        );
        let reply: TokensReply = post(&agent, &url, None, &serde_json::json!({}))?;
        Ok(reply.tokens)
    }
}

fn agent(
    endpoint: &BrokerEndpoint,
    roots: &[Certificate<'static>],
    client: Option<ClientCert>,
) -> Agent {
    let tls = TlsConfig::builder()
        .root_certs(RootCerts::new_with_certs(roots))
        .client_cert(client)
        .build();
    Agent::config_builder()
        .timeout_global(Some(endpoint.timeout))
        .http_status_as_error(false)
        .tls_config(tls)
        .build()
        .into()
}

fn certificates(pem: &str) -> std::result::Result<Vec<Certificate<'static>>, String> {
    let mut out = Vec::new();
    for item in ureq::tls::parse_pem(pem.as_bytes()) {
        match item.map_err(|e| e.to_string())? {
            PemItem::Certificate(c) => out.push(c),
            _ => continue,
        }
    }
    Ok(out)
}

fn post<T: serde::de::DeserializeOwned>(
    agent: &Agent,
    url: &str,
    bearer: Option<&str>,
    body: &serde_json::Value,
) -> Result<T> {
    let mut req = agent.post(url);
    if let Some(token) = bearer {
        req = req.header("Authorization", &format!("Bearer {token}"));
    }
    let mut resp = req
        .send_json(body)
        .map_err(|e| Error::Transport(format!("POST {url}: {e}")))?;
    let status = resp.status().as_u16();
    if !(200..300).contains(&status) {
        let body = resp.body_mut().read_to_string().unwrap_or_default();
        return Err(classify(status, &body));
    }
    resp.body_mut()
        .read_json::<T>()
        .map_err(|e| Error::Protocol(format!("POST {url}: {e}")))
}

impl Issuer for BrokerClient {
    fn sign(&self, request: &SignRequest<'_>) -> Result<IssuedBundle> {
        let pod = request
            .pod
            .ok_or_else(|| Error::Config("the broker needs the pod's context".into()))?;
        // After a restart the kubelet has not republished yet; the renewal
        // backs off and the next republish (about a minute) supplies a token.
        let pod_token = pod
            .token
            .ok_or_else(|| Error::Auth("no pod token from the kubelet yet".into()))?;
        let node_token = self.node_token()?;
        let body = serde_json::to_value(SignBody {
            pod_token: pod_token.to_string(),
            namespace: pod.namespace.to_string(),
            pod_name: pod.name.to_string(),
            pod_uid: pod.uid.to_string(),
            service_account: pod.service_account.to_string(),
            csr: request.csr_pem.to_string(),
            spiffe_id: request.spiffe_id.as_str().to_string(),
        })
        .map_err(|e| Error::Protocol(e.to_string()))?;
        let url = format!("{}/v1/sign", self.endpoint.sign_url.trim_end_matches('/'));
        let reply: SignReply = post(&self.agent, &url, Some(&node_token), &body)?;

        // The broker is trusted to ask Vault, not to be right: check the leaf
        // carries the identity this node expects before a workload holds it.
        let facts = assert_identity(&reply.cert_chain, request.spiffe_id)?;
        Ok(IssuedBundle {
            cert_chain_pem: reply.cert_chain,
            ca_pem: reply.ca,
            not_after: facts.not_after,
            not_before: facts.not_before,
        })
    }

    fn ca_chain(&self) -> Result<String> {
        let url = format!("{}/v1/bundle", self.endpoint.sign_url.trim_end_matches('/'));
        let mut resp = self
            .agent
            .get(&url)
            .call()
            .map_err(|e| Error::Transport(format!("GET {url}: {e}")))?;
        let status = resp.status().as_u16();
        let body = resp
            .body_mut()
            .read_to_string()
            .map_err(|e| Error::Transport(format!("GET {url}: {e}")))?;
        if !(200..300).contains(&status) {
            return Err(classify(status, &body));
        }
        if !body.contains("-----BEGIN CERTIFICATE-----") {
            return Err(Error::Protocol(format!(
                "{url} did not return a PEM bundle"
            )));
        }
        Ok(body)
    }

    fn name(&self) -> &'static str {
        "broker"
    }

    fn auth_name(&self) -> &'static str {
        "node-token"
    }
}
