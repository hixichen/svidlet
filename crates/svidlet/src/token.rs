//! Asking the token issuer for JWT-SVIDs on a pod's behalf.
//!
//! svidlet holds what the issuer needs: the node certificate to authenticate
//! the connection, and — because it generated it — each pod's private key to
//! prove possession. So the exchange happens here, not in the pod: one HTTP/2
//! connection per node however many pods it hosts, and a pod only ever reads
//! files.
//!
//! The connection is built lazily and rebuilt when the node certificate or the
//! trust bundle changes, so node bootstrap's daily renewal and a CA rotation
//! both reach it without a restart.

use std::path::PathBuf;
use std::sync::Mutex;

use svidlet_issue::{Error, Result};
use svidlet_token::proto::token_issuer_client::TokenIssuerClient;
use svidlet_token::proto::MintRequest;
use svidlet_token::{pop, Audience, Claims};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

use crate::config::TokenSettings;

/// A token as issued: its file name, the compact JWS, and its claims.
#[derive(Debug, Clone)]
pub struct Minted {
    pub name: String,
    pub token: String,
    pub claims: Claims,
}

/// The node's client for the token issuer.
#[derive(Debug)]
pub struct TokenClient {
    settings: TokenSettings,
    node_cert_path: PathBuf,
    node_key_path: PathBuf,
    channel: Mutex<Option<Cached>>,
}

#[derive(Debug)]
struct Cached {
    ca_pem: String,
    node_cert_pem: String,
    channel: Channel,
}

impl TokenClient {
    #[must_use]
    pub fn new(settings: TokenSettings, node_cert_path: PathBuf, node_key_path: PathBuf) -> Self {
        TokenClient {
            settings,
            node_cert_path,
            node_key_path,
            channel: Mutex::new(None),
        }
    }

    /// Mint one token for the pod whose certificate chain and key are given.
    ///
    /// `trust_bundle_pem` verifies the issuer's certificate unless
    /// `SVIDLET_TOKEN_ISSUER_CACERT` names another.
    ///
    /// # Errors
    ///
    /// Classified like the PKI backend's, so the same codes and retry rules
    /// apply: `policy` when the issuer refuses the audience (the pod's
    /// problem), `auth` when it refuses the node, `transport` when it cannot be
    /// reached or fails, `protocol` for a malformed exchange.
    pub async fn mint(
        &self,
        trust_bundle_pem: &str,
        pod_chain_pem: &str,
        pod_key_pem: &str,
        audience: &Audience,
    ) -> Result<Minted> {
        let node_cert = read(&self.node_cert_path, "the node certificate")?;
        let node_key = read(&self.node_key_path, "the node private key")?;
        // The issuer takes the node's identity from the TLS certificate, so the
        // proof must name exactly that identity.
        let node_id = svidlet_issue::inspect(&node_cert)?.spiffe_id;
        let pod_id = svidlet_issue::inspect(pod_chain_pem)?.spiffe_id;

        let time = crate::log::unix_now();
        let message = pop::message(node_id.as_str(), pod_id.as_str(), audience.value(), time);
        let proof = pop::sign(pod_key_pem, &message)
            .map_err(|e| Error::Crypto(format!("cannot prove possession of the pod key: {e}")))?;

        let ca_pem = match &self.settings.ca_cert_path {
            Some(path) => read(path, "the token issuer CA")?,
            None => trust_bundle_pem.to_string(),
        };
        let channel = self.channel(&ca_pem, &node_cert, &node_key)?;
        let mut request = tonic::Request::new(MintRequest {
            pod_cert_chain_pem: pod_chain_pem.to_string(),
            audience: audience.value().to_string(),
            proof_time: time,
            proof,
        });
        request.set_timeout(self.settings.timeout);
        let response = TokenIssuerClient::new(channel)
            .mint(request)
            .await
            .map_err(|status| classify(&status))?
            .into_inner();

        // Read the claims back before trusting the answer: a token for another
        // subject or audience must never reach a pod.
        let claims = Claims::read_unverified(&response.token)
            .map_err(|e| Error::Protocol(format!("the issuer returned no JWT: {e}")))?;
        if claims.sub != pod_id.as_str() || claims.aud != audience.value() {
            return Err(Error::Protocol(format!(
                "the issuer returned a token for {} / {:?}, not {pod_id} / {:?}",
                claims.sub,
                claims.aud,
                audience.value()
            )));
        }
        Ok(Minted {
            name: audience.name().to_string(),
            token: response.token,
            claims,
        })
    }

    fn channel(&self, ca_pem: &str, node_cert: &str, node_key: &str) -> Result<Channel> {
        let mut cached = self.channel.lock().expect("token channel mutex poisoned");
        if let Some(c) = cached.as_ref() {
            if c.ca_pem == ca_pem && c.node_cert_pem == node_cert {
                return Ok(c.channel.clone());
            }
        }
        let tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(ca_pem))
            .identity(Identity::from_pem(node_cert, node_key));
        let channel = Channel::from_shared(self.settings.url.clone())
            .map_err(|e| Error::Config(format!("SVIDLET_TOKEN_ISSUER: {e}")))?
            .tls_config(tls)
            .map_err(|e| Error::Config(format!("token issuer TLS: {e}")))?
            .connect_timeout(self.settings.timeout)
            .connect_lazy();
        *cached = Some(Cached {
            ca_pem: ca_pem.to_string(),
            node_cert_pem: node_cert.to_string(),
            channel: channel.clone(),
        });
        Ok(channel)
    }
}

fn read(path: &std::path::Path, what: &str) -> Result<String> {
    std::fs::read_to_string(path)
        .map_err(|e| Error::Auth(format!("cannot read {what} from {}: {e}", path.display())))
}

/// Map a gRPC status onto svidlet's error codes.
fn classify(status: &tonic::Status) -> Error {
    use tonic::Code;
    let message = format!("token issuer: {}", status.message());
    match status.code() {
        Code::PermissionDenied => Error::Policy(message),
        Code::Unauthenticated => Error::Auth(message),
        Code::InvalidArgument | Code::FailedPrecondition | Code::Unimplemented => {
            Error::Protocol(message)
        }
        _ => Error::Transport(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use svidlet_issue::ErrorCode;

    #[test]
    fn refusals_keep_the_meaning_they_have_for_the_pki_backend() {
        for (code, want, retryable) in [
            (tonic::Code::PermissionDenied, ErrorCode::Policy, false),
            (tonic::Code::Unauthenticated, ErrorCode::Auth, true),
            (tonic::Code::InvalidArgument, ErrorCode::Protocol, false),
            (tonic::Code::Unavailable, ErrorCode::Transport, true),
            (tonic::Code::DeadlineExceeded, ErrorCode::Transport, true),
        ] {
            let err = classify(&tonic::Status::new(code, "x"));
            assert_eq!(err.code(), want, "{code:?}");
            assert_eq!(err.is_retryable(), retryable, "{code:?}");
        }
        // A refused audience is the pod's problem, reported as such.
        assert!(classify(&tonic::Status::permission_denied("no grant")).is_caller_error());
    }

    #[tokio::test]
    async fn a_missing_node_certificate_fails_before_any_network_call() {
        let client = TokenClient::new(
            TokenSettings {
                url: "https://127.0.0.1:1".into(),
                ca_cert_path: None,
                timeout: std::time::Duration::from_millis(200),
            },
            "/nonexistent/node.crt".into(),
            "/nonexistent/node.key".into(),
        );
        let err = client
            .mint("", "", "", &Audience::new("a", "a").unwrap())
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Auth);
        assert!(err.to_string().contains("node certificate"), "{err}");
    }
}
