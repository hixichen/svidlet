//! Vault authentication methods.
//!
//! Each implements [`TokenSource`], so adding one does not touch issuance.
//! AppRole is the default because it works everywhere, including bare metal.
//!
//! **AppRole is the weakest part of this design.** It is a bearer secret sitting
//! in a Kubernetes Secret: whoever can read that Secret in the plugin's
//! namespace can mint any identity in the cluster, from anywhere, until the
//! secret ID is rotated. Every other method here is stronger — Kubernetes auth
//! and cloud IAM prove node or workload identity to Vault instead of presenting
//! a shared secret — but they need Vault to reach an API server or a cloud
//! metadata service, which is not always true. AppRole is the option that always
//! works, and it is simple enough to reason about; prefer one of the others
//! where the environment allows it.

use std::path::PathBuf;
use std::sync::Arc;

use serde::Deserialize;

use crate::auth::{Token, TokenSource};
use crate::error::{Error, Result};

use super::http::VaultHttp;

/// Vault's answer to any successful login or renewal.
#[derive(Deserialize)]
struct AuthEnvelope {
    auth: AuthData,
}

#[derive(Deserialize)]
struct AuthData {
    client_token: String,
    #[serde(default)]
    lease_duration: u64,
    #[serde(default)]
    renewable: bool,
}

/// Turn a login rejection into an auth error rather than a generic backend one,
/// so it is classified and logged as a credential problem.
fn classify(e: Error, method: &str) -> Error {
    match e {
        Error::Backend { status, body } if status == 400 || status == 403 => {
            Error::Auth(format!("{method} login rejected (HTTP {status}): {body}"))
        }
        other => other,
    }
}

fn renew_self(http: &VaultHttp, token: &str) -> Result<Token> {
    let envelope: AuthEnvelope = http.post_json(
        "auth/token/renew-self",
        Some(token),
        &[],
        &serde_json::json!({}),
    )?;
    Ok(Token::new(
        envelope.auth.client_token,
        envelope.auth.lease_duration,
        envelope.auth.renewable,
    ))
}

/// Read a credential from a mounted file, trimming whitespace.
///
/// Re-read on every login rather than cached, which is what makes rotating the
/// mounted Secret take effect without restarting the DaemonSet.
fn read_file(path: &PathBuf, what: &str) -> Result<String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| Error::Auth(format!("cannot read {what} from {}: {e}", path.display())))?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(Error::Auth(format!(
            "{what} at {} is empty",
            path.display()
        )));
    }
    Ok(trimmed.to_string())
}

// ------------------------------------------------------------------- approle

/// One AppRole per cluster: the role ID ships in the DaemonSet's config, the
/// secret ID is a mounted Kubernetes Secret rotated on a fixed cadence.
pub struct AppRoleAuth {
    http: Arc<VaultHttp>,
    mount: String,
    role_id: String,
    secret_id_path: PathBuf,
}

impl AppRoleAuth {
    pub fn new(
        http: Arc<VaultHttp>,
        mount: impl Into<String>,
        role_id: impl Into<String>,
        secret_id_path: PathBuf,
    ) -> AppRoleAuth {
        AppRoleAuth {
            http,
            mount: mount.into(),
            role_id: role_id.into(),
            secret_id_path,
        }
    }
}

impl TokenSource for AppRoleAuth {
    fn login(&self) -> Result<Token> {
        let secret_id = read_file(&self.secret_id_path, "the AppRole secret ID")?;
        let body = serde_json::json!({
            "role_id": self.role_id,
            "secret_id": secret_id,
        });
        let envelope: AuthEnvelope = self
            .http
            .post_json(&format!("auth/{}/login", self.mount), None, &[], &body)
            .map_err(|e| classify(e, "AppRole"))?;
        Ok(Token::new(
            envelope.auth.client_token,
            envelope.auth.lease_duration,
            envelope.auth.renewable,
        ))
    }

    fn renew(&self, token: &str) -> Result<Token> {
        renew_self(&self.http, token)
    }

    fn name(&self) -> &'static str {
        "approle"
    }
}

// ---------------------------------------------------------------- kubernetes

/// Vault's Kubernetes auth method: present the plugin's own projected
/// ServiceAccount token and let Vault verify it.
///
/// Stronger than AppRole — there is no shared secret to leak or rotate — but it
/// requires Vault to be able to validate the token, either by reaching the
/// cluster's API server or through an aggregated JWKS endpoint.
pub struct KubernetesAuth {
    http: Arc<VaultHttp>,
    mount: String,
    role: String,
    token_path: PathBuf,
}

impl KubernetesAuth {
    pub const DEFAULT_TOKEN_PATH: &'static str =
        "/var/run/secrets/kubernetes.io/serviceaccount/token";

    pub fn new(
        http: Arc<VaultHttp>,
        mount: impl Into<String>,
        role: impl Into<String>,
        token_path: PathBuf,
    ) -> KubernetesAuth {
        KubernetesAuth {
            http,
            mount: mount.into(),
            role: role.into(),
            token_path,
        }
    }
}

impl TokenSource for KubernetesAuth {
    fn login(&self) -> Result<Token> {
        // Projected tokens are rotated by the kubelet, so this must be read
        // fresh on every login.
        let jwt = read_file(&self.token_path, "the ServiceAccount token")?;
        let body = serde_json::json!({ "role": self.role, "jwt": jwt });
        let envelope: AuthEnvelope = self
            .http
            .post_json(&format!("auth/{}/login", self.mount), None, &[], &body)
            .map_err(|e| classify(e, "Kubernetes"))?;
        Ok(Token::new(
            envelope.auth.client_token,
            envelope.auth.lease_duration,
            envelope.auth.renewable,
        ))
    }

    fn renew(&self, token: &str) -> Result<Token> {
        renew_self(&self.http, token)
    }

    fn name(&self) -> &'static str {
        "kubernetes"
    }
}

// -------------------------------------------------------------- static token

/// A token read from a file. Intended for local development against a dev-mode
/// Vault, and as an escape hatch where a token is injected by something else.
pub struct StaticTokenAuth {
    path: PathBuf,
}

impl StaticTokenAuth {
    pub fn new(path: PathBuf) -> StaticTokenAuth {
        StaticTokenAuth { path }
    }
}

impl TokenSource for StaticTokenAuth {
    fn login(&self) -> Result<Token> {
        // Re-read rather than cached, so replacing the file is enough.
        Ok(Token::permanent(read_file(&self.path, "the Vault token")?))
    }

    fn name(&self) -> &'static str {
        "token"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCode;

    fn scratch_file(name: &str, contents: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "svidlet-auth-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, contents).unwrap();
        path
    }

    fn http() -> Arc<VaultHttp> {
        Arc::new(
            VaultHttp::new(super::super::http::VaultEndpoint {
                address: "http://127.0.0.1:1".into(),
                namespace: None,
                ca_cert_pem: None,
                timeout: std::time::Duration::from_millis(500),
            })
            .unwrap(),
        )
    }

    #[test]
    fn method_names_are_stable_label_values() {
        let h = http();
        assert_eq!(
            AppRoleAuth::new(h.clone(), "approle", "r", "/dev/null".into()).name(),
            "approle"
        );
        assert_eq!(
            KubernetesAuth::new(h, "kubernetes", "svidlet", "/dev/null".into()).name(),
            "kubernetes"
        );
        assert_eq!(StaticTokenAuth::new("/dev/null".into()).name(), "token");
    }

    #[test]
    fn a_static_token_is_read_fresh_from_disk_every_time() {
        let path = scratch_file("static", "  s.first\n");
        let auth = StaticTokenAuth::new(path.clone());

        let token = auth.login().unwrap();
        assert_eq!(token.value, "s.first");
        assert_eq!(token.lease_secs, 0);
        assert!(!token.renewable);

        // Rotating the file is enough; nothing is cached.
        std::fs::write(&path, "s.second").unwrap();
        assert_eq!(auth.login().unwrap().value, "s.second");

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_missing_or_empty_credential_file_is_an_auth_error() {
        let auth = StaticTokenAuth::new("/nonexistent/svidlet/token".into());
        let err = auth.login().unwrap_err();
        assert_eq!(err.code(), ErrorCode::Auth);
        assert!(err.to_string().contains("cannot read the Vault token"));

        let empty = scratch_file("empty", "   \n");
        let err = StaticTokenAuth::new(empty.clone()).login().unwrap_err();
        assert_eq!(err.code(), ErrorCode::Auth);
        assert!(err.to_string().contains("is empty"));
        std::fs::remove_file(&empty).unwrap();
    }

    #[test]
    fn approle_reads_the_secret_id_before_it_reaches_the_network() {
        // The secret ID file is checked first, so a rotation that empties the
        // file is reported as a credential problem, not a transport one.
        let auth = AppRoleAuth::new(http(), "approle", "role", "/nonexistent/secret-id".into());
        let err = auth.login().unwrap_err();
        assert_eq!(err.code(), ErrorCode::Auth);
        assert!(err.to_string().contains("AppRole secret ID"));
    }

    #[test]
    fn kubernetes_auth_reads_the_projected_token_before_the_network() {
        let auth = KubernetesAuth::new(
            http(),
            "kubernetes",
            "svidlet",
            "/nonexistent/sa-token".into(),
        );
        let err = auth.login().unwrap_err();
        assert_eq!(err.code(), ErrorCode::Auth);
        assert!(err.to_string().contains("ServiceAccount token"));
        assert_eq!(
            KubernetesAuth::DEFAULT_TOKEN_PATH,
            "/var/run/secrets/kubernetes.io/serviceaccount/token"
        );
    }

    #[test]
    fn rejected_logins_are_classified_as_auth_not_backend_failures() {
        for status in [400, 403] {
            let err = classify(
                Error::Backend {
                    status,
                    body: "invalid role or secret ID".into(),
                },
                "AppRole",
            );
            assert_eq!(err.code(), ErrorCode::Auth);
            assert!(err.to_string().contains("AppRole login rejected"));
        }
        // Anything else keeps its own classification: a 503 is an outage, and
        // retrying it is right, whereas retrying a rejected credential is not.
        let err = classify(
            Error::Backend {
                status: 503,
                body: "sealed".into(),
            },
            "AppRole",
        );
        assert_eq!(err.code(), ErrorCode::BackendStatus);
        assert!(err.is_retryable());
    }
}
