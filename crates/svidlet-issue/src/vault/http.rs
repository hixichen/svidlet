//! The HTTP client shared by Vault's auth methods and its PKI engine.

use std::time::Duration;

use ureq::tls::{Certificate, RootCerts, TlsConfig};
use ureq::Agent;

use crate::error::{Error, Result};

/// Connection settings for one Vault cluster.
#[derive(Debug, Clone)]
pub struct VaultEndpoint {
    /// e.g. `https://vault.example.internal:8200`
    pub address: String,
    /// Vault Enterprise namespace, if any.
    pub namespace: Option<String>,
    /// PEM bundle used to verify Vault's server certificate. When absent, the
    /// compiled-in Mozilla root store is used.
    pub ca_cert_pem: Option<String>,
    pub timeout: Duration,
}

/// The `Debug` impl deliberately omits the agent: it is only here so callers
/// can `unwrap()` a `Result<VaultHttp, _>`.
pub struct VaultHttp {
    endpoint: VaultEndpoint,
    agent: Agent,
}

impl std::fmt::Debug for VaultHttp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultHttp")
            .field("address", &self.endpoint.address)
            .field("namespace", &self.endpoint.namespace)
            .finish_non_exhaustive()
    }
}

impl VaultHttp {
    pub fn new(endpoint: VaultEndpoint) -> Result<VaultHttp> {
        let mut tls = TlsConfig::builder();
        if let Some(pem) = &endpoint.ca_cert_pem {
            let cert = Certificate::from_pem(pem.as_bytes()).map_err(|e| {
                Error::Config(format!("the Vault CA certificate is not valid PEM: {e}"))
            })?;
            tls = tls.root_certs(RootCerts::new_with_certs(&[cert]));
        }
        let config = Agent::config_builder()
            .timeout_global(Some(endpoint.timeout))
            // Handle non-2xx ourselves so Vault's `errors` array reaches the
            // log instead of being collapsed into a bare status code.
            .http_status_as_error(false)
            .tls_config(tls.build())
            .build();

        Ok(VaultHttp {
            endpoint,
            agent: config.into(),
        })
    }

    pub fn url(&self, path: &str) -> String {
        format!(
            "{}/v1/{}",
            self.endpoint.address.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }

    /// POST JSON and decode a JSON answer.
    pub fn post_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        token: Option<&str>,
        extra_headers: &[(&str, &str)],
        body: &serde_json::Value,
    ) -> Result<T> {
        let url = self.url(path);
        let mut req = self.agent.post(&url);
        if let Some(token) = token {
            req = req.header("X-Vault-Token", token);
        }
        if let Some(ns) = &self.endpoint.namespace {
            req = req.header("X-Vault-Namespace", ns);
        }
        for (name, value) in extra_headers {
            req = req.header(*name, *value);
        }

        let mut resp = req
            .send_json(body)
            .map_err(|e| Error::Transport(format!("POST {url}: {e}")))?;

        let status = resp.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(Error::Backend {
                status,
                body: truncate(&resp.body_mut().read_to_string().unwrap_or_default()),
            });
        }
        resp.body_mut()
            .read_json::<T>()
            .map_err(|e| Error::Protocol(format!("POST {url}: {e}")))
    }

    /// GET a plain-text body. Vault's `ca_chain` endpoint returns PEM, not JSON.
    pub fn get_text(&self, path: &str) -> Result<String> {
        let url = self.url(path);
        let mut req = self.agent.get(&url);
        if let Some(ns) = &self.endpoint.namespace {
            req = req.header("X-Vault-Namespace", ns);
        }
        let mut resp = req
            .call()
            .map_err(|e| Error::Transport(format!("GET {url}: {e}")))?;

        let status = resp.status().as_u16();
        let body = resp
            .body_mut()
            .read_to_string()
            .map_err(|e| Error::Transport(format!("GET {url}: {e}")))?;
        if !(200..300).contains(&status) {
            return Err(Error::Backend {
                status,
                body: truncate(&body),
            });
        }
        Ok(body)
    }
}

/// Keep a failing response readable in a log line without pasting a whole page
/// of HTML into it.
fn truncate(body: &str) -> String {
    const LIMIT: usize = 512;
    if body.len() <= LIMIT {
        return body.to_string();
    }
    let mut cut = LIMIT;
    while cut > 0 && !body.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}…", &body[..cut])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(address: &str) -> VaultEndpoint {
        VaultEndpoint {
            address: address.into(),
            namespace: None,
            ca_cert_pem: None,
            timeout: Duration::from_secs(1),
        }
    }

    #[test]
    fn urls_join_without_doubling_slashes() {
        let http = VaultHttp::new(endpoint("https://vault.example:8200/")).unwrap();
        assert_eq!(
            http.url("pki/ca_chain"),
            "https://vault.example:8200/v1/pki/ca_chain"
        );
        assert_eq!(
            http.url("/pki/ca_chain"),
            "https://vault.example:8200/v1/pki/ca_chain"
        );
    }

    #[test]
    fn a_bad_ca_certificate_is_a_configuration_error() {
        let mut ep = endpoint("https://vault.example:8200");
        ep.ca_cert_pem = Some("not a certificate".into());
        let err = VaultHttp::new(ep).unwrap_err();
        assert_eq!(err.code(), crate::error::ErrorCode::Config);
        assert!(!err.is_retryable());
    }

    #[test]
    fn truncation_keeps_the_head_and_never_splits_a_character() {
        assert_eq!(truncate("short"), "short");
        let long = "é".repeat(400);
        let cut = truncate(&long);
        assert!(cut.ends_with('…'));
        assert!(cut.len() <= 512 + '…'.len_utf8());
    }

    #[test]
    fn an_unreachable_vault_is_a_retryable_transport_error() {
        // Port 1 is reserved and refuses immediately.
        let http = VaultHttp::new(endpoint("http://127.0.0.1:1")).unwrap();
        let err = http.get_text("pki/ca_chain").unwrap_err();
        assert_eq!(err.code(), crate::error::ErrorCode::Transport);
        assert!(err.is_retryable());

        let err = http
            .post_json::<serde_json::Value>("auth/approle/login", None, &[], &serde_json::json!({}))
            .unwrap_err();
        assert_eq!(err.code(), crate::error::ErrorCode::Transport);
    }
}
