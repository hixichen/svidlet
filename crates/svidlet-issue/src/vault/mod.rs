//! HashiCorp Vault PKI backend.
//!
//! The plugin logs in once through whichever [`TokenSource`] is configured and
//! keeps a periodic, renewable token; it does not log in per certificate.
//!
//! [`TokenSource`]: crate::auth::TokenSource

pub mod auth;
pub mod http;

use std::sync::Arc;

use serde::Deserialize;

use crate::auth::{TokenCache, TokenSource};
use crate::bundle::{assert_identity, IssuedBundle};
use crate::error::{Error, Result};
use crate::issuer::{Issuer, SignRequest};

pub use auth::{AppRoleAuth, KubernetesAuth, StaticTokenAuth};
pub use http::{VaultEndpoint, VaultHttp};

/// Where and how to sign.
#[derive(Debug, Clone)]
pub struct VaultPkiConfig {
    /// Mount path of the PKI secrets engine, e.g. `pki`.
    pub mount: String,
    /// Role to sign with, e.g. `spiffe-cluster-a`. The role's
    /// `allowed_uri_sans` is what pins this cluster's SPIFFE prefix.
    pub role: String,
}

pub struct VaultIssuer<S: TokenSource> {
    http: Arc<VaultHttp>,
    pki: VaultPkiConfig,
    tokens: TokenCache<S>,
    auth_name: &'static str,
}

impl<S: TokenSource> VaultIssuer<S> {
    pub fn new(http: Arc<VaultHttp>, pki: VaultPkiConfig, source: S) -> VaultIssuer<S> {
        let auth_name = source.name();
        VaultIssuer {
            http,
            pki,
            tokens: TokenCache::new(source),
            auth_name,
        }
    }

    fn sign_path(&self) -> String {
        format!(
            "{}/sign/{}",
            self.pki.mount.trim_matches('/'),
            self.pki.role
        )
    }

    fn ca_chain_path(&self) -> String {
        format!("{}/ca_chain", self.pki.mount.trim_matches('/'))
    }
}

impl<S: TokenSource> Issuer for VaultIssuer<S> {
    fn sign(&self, request: &SignRequest<'_>) -> Result<IssuedBundle> {
        let body = serde_json::json!({
            "csr": request.csr_pem,
            "uri_sans": request.spiffe_id.as_str(),
            // Vault takes durations as a string; seconds are unambiguous.
            "ttl": format!("{}s", request.ttl.as_secs()),
            "format": "pem",
            "exclude_cn_from_sans": true,
        });
        // Vault records request headers in its audit log when configured to,
        // which is what makes an issuance attributable to a node.
        let headers = [("X-Svidlet-Node", request.node_name)];
        let path = self.sign_path();

        let mut attempt = 0;
        let signed: SignEnvelope = loop {
            attempt += 1;
            let token = self.tokens.token()?;
            match self
                .http
                .post_json::<SignEnvelope>(&path, Some(&token), &headers, &body)
            {
                Ok(v) => break v,
                // Vault answers 403 for a token it no longer knows. Log in
                // again once — this is what makes credential rotation and Vault
                // restarts survivable without restarting the DaemonSet.
                Err(Error::Backend { status: 403, .. }) if attempt == 1 => {
                    self.tokens.invalidate();
                }
                Err(e) => return Err(e),
            }
        };

        let chain = signed.data.chain_pem();
        // Defence in depth: the per-cluster role already pins allowed_uri_sans,
        // so this only fires if the role is misconfigured — and then it fires
        // on the node, before a workload ever holds the certificate.
        let facts = assert_identity(&chain, request.spiffe_id)?;

        Ok(IssuedBundle {
            cert_chain_pem: chain,
            ca_pem: signed.data.ca_bundle_pem(),
            not_after: facts.not_after,
            not_before: facts.not_before,
        })
    }

    fn ca_chain(&self) -> Result<String> {
        let path = self.ca_chain_path();
        let body = self.http.get_text(&path)?;
        if !body.contains("-----BEGIN CERTIFICATE-----") {
            return Err(Error::Protocol(format!(
                "{path} did not return a PEM chain"
            )));
        }
        Ok(body)
    }

    fn name(&self) -> &'static str {
        "vault"
    }

    fn auth_name(&self) -> &'static str {
        self.auth_name
    }
}

#[derive(Deserialize)]
struct SignEnvelope {
    data: SignData,
}

#[derive(Deserialize)]
struct SignData {
    certificate: String,
    #[serde(default)]
    ca_chain: Vec<String>,
    #[serde(default)]
    issuing_ca: String,
}

impl SignData {
    /// Leaf first, then any intermediates — the order a TLS server must present.
    fn chain_pem(&self) -> String {
        let mut out = normalize(&self.certificate);
        for ca in &self.ca_chain {
            // ca_chain holds the issuing CA and its parents; the leaf is never
            // in it, but guard anyway so it is not duplicated.
            let ca = normalize(ca);
            if ca != out {
                out.push_str(&ca);
            }
        }
        out
    }

    /// Trust bundle written to `ca.crt`.
    fn ca_bundle_pem(&self) -> String {
        if self.ca_chain.is_empty() {
            normalize(&self.issuing_ca)
        } else {
            self.ca_chain.iter().map(|c| normalize(c)).collect()
        }
    }
}

fn normalize(pem: &str) -> String {
    let trimmed = pem.trim();
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("{trimmed}\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(certificate: &str, chain: &[&str], issuing: &str) -> SignData {
        SignData {
            certificate: certificate.into(),
            ca_chain: chain.iter().map(|s| s.to_string()).collect(),
            issuing_ca: issuing.into(),
        }
    }

    #[test]
    fn chain_is_leaf_first_and_newline_terminated() {
        let d = data("LEAF", &["INT", "ROOT"], "INT");
        assert_eq!(d.chain_pem(), "LEAF\nINT\nROOT\n");
        assert_eq!(d.ca_bundle_pem(), "INT\nROOT\n");
    }

    #[test]
    fn ca_bundle_falls_back_to_issuing_ca() {
        let d = data("LEAF", &[], "INT");
        assert_eq!(d.chain_pem(), "LEAF\n");
        assert_eq!(d.ca_bundle_pem(), "INT\n");
    }

    #[test]
    fn a_duplicated_issuing_ca_is_not_written_twice() {
        let d = data("LEAF", &["LEAF"], "");
        assert_eq!(d.chain_pem(), "LEAF\n");
    }

    #[test]
    fn paths_are_built_from_the_mount_and_role() {
        let http = Arc::new(
            VaultHttp::new(VaultEndpoint {
                address: "https://vault.example:8200".into(),
                namespace: None,
                ca_cert_pem: None,
                timeout: std::time::Duration::from_secs(1),
            })
            .unwrap(),
        );
        let issuer = VaultIssuer::new(
            http,
            VaultPkiConfig {
                mount: "/pki/".into(),
                role: "spiffe-cluster-a".into(),
            },
            StaticTokenAuth::new("/dev/null".into()),
        );
        assert_eq!(issuer.sign_path(), "pki/sign/spiffe-cluster-a");
        assert_eq!(issuer.ca_chain_path(), "pki/ca_chain");
        assert_eq!(issuer.name(), "vault");
        assert_eq!(issuer.auth_name(), "token");
    }
}
