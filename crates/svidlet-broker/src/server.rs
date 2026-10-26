//! HTTPS on two ports, metrics on a third, and the background loops.
//!
//! - **8443, certificates.** Server TLS only; the caller authenticates with
//!   its node token in `Authorization` and the pod token in the body.
//! - **8444, tokens.** Mutual TLS: the TLS layer chains the client certificate
//!   to the trust bundle, checks its validity and client-auth usage, and only
//!   then does a request reach [`Tokens`].

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use svidlet_issue::broker::{ErrorReply, SignBody, SignReply, TokenGrant, TokensReply};

use crate::metrics::Metrics;
use crate::refusal::Refusal;
use crate::sign::Signer;
use crate::tokens::{Grant, Tokens};

/// Requests are small JSON documents; anything bigger is not one of ours.
const MAX_BODY: usize = 64 * 1024;

/// A client gets this long to send its request headers, so a connection that
/// trickles bytes cannot hold a task and a descriptor forever.
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);

/// Accept the next connection. An accept error — descriptors exhausted, a
/// connection reset before it was accepted — is logged and retried: one bad
/// moment must not take the cluster's only broker down.
async fn accept(listener: &TcpListener) -> (tokio::net::TcpStream, SocketAddr) {
    loop {
        match listener.accept().await {
            Ok(conn) => return conn,
            Err(e) => {
                warn!(error = %e, "accept failed; retrying");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

fn http1() -> hyper::server::conn::http1::Builder {
    let mut b = hyper::server::conn::http1::Builder::new();
    b.timer(TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT);
    b
}

pub struct Broker {
    pub signer: Signer,
    pub tokens: Tokens,
    pub metrics: Metrics,
    /// Trust bundle served at `/v1/bundle` and returned with certificates.
    pub bundle: RwLock<String>,
    pub bundle_path: PathBuf,
}

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

type Body = Full<Bytes>;

fn json<T: serde::Serialize>(status: StatusCode, value: &T) -> Response<Body> {
    let body = serde_json::to_vec(value).unwrap_or_default();
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .expect("static response parts")
}

fn text(status: StatusCode, body: String) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(body)))
        .expect("static response parts")
}

fn refused(r: &Refusal) -> Response<Body> {
    json(
        StatusCode::from_u16(r.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        &ErrorReply {
            error: r.message().to_string(),
            rule: r.rule().to_string(),
        },
    )
}

async fn read_body(req: Request<Incoming>) -> Result<Bytes, Refusal> {
    Limited::new(req.into_body(), MAX_BODY)
        .collect()
        .await
        .map(|c| c.to_bytes())
        .map_err(|e| Refusal::bad("I1", format!("cannot read the request body: {e}")))
}

fn bearer(req: &Request<Incoming>) -> String {
    req.headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default()
        .trim()
        .to_string()
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, Refusal> + Send + 'static,
) -> Result<T, Refusal> {
    tokio::task::spawn_blocking(f).await.unwrap_or_else(|e| {
        Err(Refusal::Internal {
            message: format!("handler panicked: {e}"),
        })
    })
}

/// Port 8443.
pub async fn handle_sign(broker: Arc<Broker>, req: Request<Incoming>) -> Response<Body> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/healthz") => text(StatusCode::OK, "ok\n".into()),
        (&Method::GET, "/v1/bundle") => {
            let bundle = broker.bundle.read().expect("bundle poisoned").clone();
            text(StatusCode::OK, bundle)
        }
        (&Method::POST, "/v1/sign") => {
            let node_token = bearer(&req);
            let outcome = async {
                let body = read_body(req).await?;
                let body: SignBody = serde_json::from_slice(&body)
                    .map_err(|e| Refusal::bad("I1", format!("malformed request: {e}")))?;
                let b = broker.clone();
                blocking(move || b.signer.sign(&node_token, &body, unix_now())).await
            }
            .await;
            match outcome {
                Ok(signed) => {
                    broker.metrics.request("sign", "ok", "");
                    broker.metrics.vault("pki_sign", signed.vault_elapsed);
                    // I12: every decision, never a token.
                    info!(
                        target: "audit",
                        decision = "issue",
                        spiffe_id = %signed.spiffe_id,
                        node = %signed.node,
                        namespace = %signed.namespace,
                        pod = %signed.pod,
                        pod_uid = %signed.pod_uid,
                        not_after = signed.bundle.not_after,
                        "certificate issued"
                    );
                    let bundle = broker.bundle.read().expect("bundle poisoned").clone();
                    json(
                        StatusCode::OK,
                        &SignReply {
                            spiffe_id: signed.spiffe_id.to_string(),
                            cert_chain: signed.bundle.cert_chain_pem,
                            ca: if bundle.is_empty() {
                                signed.bundle.ca_pem
                            } else {
                                bundle
                            },
                            not_after: signed.bundle.not_after,
                        },
                    )
                }
                Err(r) => {
                    broker.metrics.request("sign", r.outcome(), r.rule());
                    warn!(
                        target: "audit",
                        decision = "deny",
                        path = "sign",
                        status = r.status(),
                        rule = r.rule(),
                        reason = r.message(),
                        "certificate refused"
                    );
                    refused(&r)
                }
            }
        }
        _ => text(StatusCode::NOT_FOUND, "not found\n".into()),
    }
}

#[derive(Deserialize)]
struct TokenBody {
    audience: String,
}

/// Port 8444. `leaf` is the client certificate the TLS layer verified.
pub async fn handle_tokens(
    broker: Arc<Broker>,
    leaf: Option<Arc<Vec<u8>>>,
    req: Request<Incoming>,
) -> Response<Body> {
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    if method == Method::GET && path == "/healthz" {
        return text(StatusCode::OK, "ok\n".into());
    }
    let single = match (method, path.as_str()) {
        (Method::POST, "/v1/tokens") => false,
        (Method::POST, "/v1/token") => true,
        _ => return text(StatusCode::NOT_FOUND, "not found\n".into()),
    };
    let label = if single { "token" } else { "tokens" };

    let outcome = async {
        let leaf = leaf.ok_or_else(|| Refusal::unauthenticated("T1", "no client certificate"))?;
        let body = read_body(req).await?;
        let audience = if single {
            let b: TokenBody = serde_json::from_slice(&body)
                .map_err(|e| Refusal::bad("T3", format!("malformed request: {e}")))?;
            Some(b.audience)
        } else {
            None
        };
        let b = broker.clone();
        blocking(move || {
            let now = unix_now();
            let caller = b.tokens.caller(&leaf, now)?;
            let grants = match &audience {
                Some(a) => vec![b.tokens.single(&caller, a, now)?],
                None => b.tokens.all(&caller, now)?,
            };
            Ok((caller, grants))
        })
        .await
    }
    .await;

    match outcome {
        Ok((caller, grants)) => {
            broker.metrics.request(label, "ok", "");
            for g in &grants {
                broker.metrics.cache(g.minted);
                if let Some(took) = g.vault_elapsed {
                    broker.metrics.vault("mintjwt", took);
                }
                // T8: identity, audience, caller serial and jti; never the token.
                info!(
                    target: "audit",
                    decision = "token",
                    spiffe_id = %caller.spiffe_id,
                    audience = %g.audience,
                    serial = %caller.serial,
                    jti = %g.jti,
                    minted = g.minted,
                    exp = g.exp,
                    "token issued"
                );
            }
            let wire = |g: Grant| TokenGrant {
                alias: g.alias,
                audience: g.audience,
                token: g.token,
                exp: g.exp,
            };
            if single {
                let g = grants.into_iter().next().map(wire);
                json(StatusCode::OK, &g)
            } else {
                json(
                    StatusCode::OK,
                    &TokensReply {
                        tokens: grants.into_iter().map(wire).collect(),
                    },
                )
            }
        }
        Err(r) => {
            broker.metrics.request(label, r.outcome(), r.rule());
            warn!(
                target: "audit",
                decision = "deny",
                path = label,
                status = r.status(),
                rule = r.rule(),
                reason = r.message(),
                "token refused"
            );
            refused(&r)
        }
    }
}

// ------------------------------------------------------------------- TLS

/// The broker's serving certificate, re-read from disk so a rotated file
/// (§9: 24 h) takes effect without a restart.
#[derive(Debug)]
pub struct ReloadingCert {
    cert: PathBuf,
    key: PathBuf,
    current: RwLock<Arc<CertifiedKey>>,
}

impl ReloadingCert {
    pub fn load(cert: &Path, key: &Path) -> Result<ReloadingCert, String> {
        Ok(ReloadingCert {
            current: RwLock::new(Arc::new(load_certified(cert, key)?)),
            cert: cert.to_path_buf(),
            key: key.to_path_buf(),
        })
    }

    /// Re-read; a bad pair leaves the current one in place.
    pub fn reload(&self) -> Result<(), String> {
        let fresh = load_certified(&self.cert, &self.key)?;
        *self.current.write().expect("cert poisoned") = Arc::new(fresh);
        Ok(())
    }
}

impl ResolvesServerCert for ReloadingCert {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current.read().expect("cert poisoned").clone())
    }
}

fn load_certified(cert: &Path, key: &Path) -> Result<CertifiedKey, String> {
    let chain = load_certs(cert)?;
    let key = PrivateKeyDer::from_pem_file(key)
        .map_err(|e| format!("cannot read the key {}: {e}", key.display()))?;
    let signing = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| format!("unsupported serving key: {e}"))?;
    Ok(CertifiedKey::new(chain, signing))
}

pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let certs: Result<Vec<_>, _> = CertificateDer::pem_file_iter(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?
        .collect();
    let certs = certs.map_err(|e| format!("{} is not PEM: {e}", path.display()))?;
    if certs.is_empty() {
        return Err(format!("{} holds no certificate", path.display()));
    }
    Ok(certs)
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

pub fn sign_tls(cert: Arc<ReloadingCert>) -> Result<Arc<ServerConfig>, String> {
    let mut cfg = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_cert_resolver(cert);
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// T1's chain, validity and usage checks happen here, in the handshake.
pub fn token_tls(cert: Arc<ReloadingCert>, client_ca: &Path) -> Result<Arc<ServerConfig>, String> {
    let mut roots = RootCertStore::empty();
    for c in load_certs(client_ca)? {
        roots.add(c).map_err(|e| format!("bad client CA: {e}"))?;
    }
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider())
        .build()
        .map_err(|e| e.to_string())?;
    let mut cfg = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(cert);
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

#[derive(Clone, Copy)]
pub enum Port {
    Sign,
    Tokens,
}

/// Accept TLS connections forever and serve HTTP/1.1 on each.
pub async fn serve(
    listener: TcpListener,
    tls: Arc<ServerConfig>,
    broker: Arc<Broker>,
    port: Port,
) -> std::io::Result<()> {
    let acceptor = TlsAcceptor::from(tls);
    loop {
        let (tcp, peer) = accept(&listener).await;
        let acceptor = acceptor.clone();
        let broker = broker.clone();
        tokio::spawn(async move {
            let stream =
                match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        // A failed client-certificate check lands here: T1 refused
                        // in the handshake. Worth seeing, not worth a warning each.
                        tracing::debug!(peer = %peer, error = %e, "TLS handshake failed");
                        return;
                    }
                    Err(_) => return,
                };
            let leaf = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|c| c.first())
                .map(|c| Arc::new(c.as_ref().to_vec()));
            let svc = service_fn(move |req| {
                let broker = broker.clone();
                let leaf = leaf.clone();
                async move {
                    Ok::<_, Infallible>(match port {
                        Port::Sign => handle_sign(broker, req).await,
                        Port::Tokens => handle_tokens(broker, leaf, req).await,
                    })
                }
            });
            if let Err(e) = http1().serve_connection(TokioIo::new(stream), svc).await {
                tracing::debug!(peer = %peer, error = %e, "connection ended with an error");
            }
        });
    }
}

/// Plain HTTP: `/metrics` and `/healthz`. Liveness is process-only (§10): a
/// Vault or API-server outage must never restart the broker.
pub async fn serve_metrics(listener: TcpListener, broker: Arc<Broker>) -> std::io::Result<()> {
    loop {
        let (tcp, _) = accept(&listener).await;
        let broker = broker.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req: Request<Incoming>| {
                let broker = broker.clone();
                async move {
                    Ok::<_, Infallible>(match req.uri().path() {
                        "/metrics" => text(
                            StatusCode::OK,
                            broker.metrics.render(broker.tokens.cached()),
                        ),
                        "/healthz" => text(StatusCode::OK, "ok\n".into()),
                        _ => text(StatusCode::NOT_FOUND, "not found\n".into()),
                    })
                }
            });
            let _ = http1().serve_connection(TokioIo::new(tcp), svc).await;
        });
    }
}

/// Reload files, refresh the JWKS, and sweep caches.
pub async fn housekeeping(broker: Arc<Broker>, cert: Arc<ReloadingCert>, jwks_every: Duration) {
    let mut last_jwks = Instant::now() - jwks_every;
    let mut last_sweep = Instant::now();
    loop {
        if last_jwks.elapsed() >= jwks_every {
            last_jwks = Instant::now();
            let b = broker.clone();
            match tokio::task::spawn_blocking(move || b.tokens.jwks.refresh()).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => warn!(error = %e, "JWKS refresh failed; keeping the last good set"),
                Err(e) => error!(error = %e, "JWKS refresh panicked"),
            }
        }
        if let Err(e) = cert.reload() {
            warn!(error = %e, "serving certificate reload failed; keeping the current one");
        }
        match broker.signer.catalog.reload() {
            Ok(true) => info!("catalog reloaded"),
            Ok(false) => {}
            Err(e) => warn!(error = %e, "catalog reload failed; keeping the current one"),
        }
        if let Ok(b) = std::fs::read_to_string(&broker.bundle_path) {
            if b.contains("-----BEGIN CERTIFICATE-----") {
                *broker.bundle.write().expect("bundle poisoned") = b;
            }
        }
        if last_sweep.elapsed() >= Duration::from_secs(300) {
            last_sweep = Instant::now();
            let now = unix_now();
            broker.signer.sweep(now);
            broker.tokens.sweep(now);
        }
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}
