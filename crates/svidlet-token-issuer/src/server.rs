//! Serving: the gRPC API for svidlet, and HTTP for everyone else.
//!
//! Three listeners, because they face three audiences:
//!
//! - **gRPC, mutual TLS** (`listen`): svidlet on every node. The handshake
//!   requires a client certificate from the node registration CA; anything
//!   else never reaches [`Minter::mint`].
//! - **Public HTTP** (`public_listen`): `/.well-known/openid-configuration`
//!   and `/.well-known/jwks.json`, for relying parties. Plain HTTP, meant to
//!   sit behind the load balancer that terminates TLS for the `issuer` URL.
//!   Relying parties that cannot reach it cannot verify any token, so for the
//!   widest availability publish the same two documents to static hosting
//!   instead — `svidlet-token-issuer discovery` writes them.
//! - **Metrics** (`metrics_listen`): `/metrics` and `/healthz`, internal.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use svidlet_token::proto::token_issuer_server::{TokenIssuer, TokenIssuerServer};
use svidlet_token::proto::{MintRequest, MintResponse};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};

use crate::config::Config;
use crate::grants::Grants;
use crate::keys::{Key, KeyPool};
use crate::mint::{DeniedKind, Minter, DENIAL_LABELS};

/// Counters for `/metrics`, every series present from start.
#[derive(Debug, Default)]
pub struct Metrics {
    minted: AtomicU64,
    denied: [AtomicU64; DENIAL_LABELS.len()],
}

impl Metrics {
    fn deny(&self, label: &str) {
        if let Some(i) = DENIAL_LABELS.iter().position(|l| *l == label) {
            self.denied[i].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Prometheus text.
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        let _ = writeln!(
            out,
            "# HELP svidlet_token_minted_total Tokens issued.\n\
             # TYPE svidlet_token_minted_total counter\n\
             svidlet_token_minted_total {}",
            self.minted.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "# HELP svidlet_token_denied_total Requests refused, by the first check that failed.\n\
             # TYPE svidlet_token_denied_total counter"
        );
        for (label, count) in DENIAL_LABELS.iter().zip(&self.denied) {
            let _ = writeln!(
                out,
                "svidlet_token_denied_total{{reason=\"{label}\"}} {}",
                count.load(Ordering::Relaxed)
            );
        }
        out
    }
}

/// The gRPC service.
#[derive(Debug, Clone)]
pub struct Service {
    minter: Arc<Minter>,
    metrics: Arc<Metrics>,
}

impl Service {
    #[must_use]
    pub fn new(minter: Arc<Minter>, metrics: Arc<Metrics>) -> Service {
        Service { minter, metrics }
    }
}

#[tonic::async_trait]
impl TokenIssuer for Service {
    async fn mint(&self, request: Request<MintRequest>) -> Result<Response<MintResponse>, Status> {
        let Some(peer) = request.peer_certs() else {
            self.metrics.deny("node_identity");
            return Err(Status::unauthenticated("no client certificate"));
        };
        let Some(node_cert) = peer.first() else {
            self.metrics.deny("node_identity");
            return Err(Status::unauthenticated("no client certificate"));
        };
        match self
            .minter
            .mint(node_cert.as_ref(), request.get_ref(), unix_now())
        {
            Ok(minted) => {
                self.metrics.minted.fetch_add(1, Ordering::Relaxed);
                tracing::info!(
                    sub = %minted.claims.sub,
                    aud = %minted.claims.aud,
                    kid = %minted.kid,
                    jti = %minted.claims.jti,
                    exp = minted.claims.exp,
                    "token.mint.success"
                );
                Ok(Response::new(MintResponse {
                    token: minted.token,
                    expires_at: minted.claims.exp,
                }))
            }
            Err(denied) => {
                self.metrics.deny(denied.label());
                tracing::warn!(
                    reason = denied.label(),
                    detail = denied.detail(),
                    audience = %request.get_ref().audience,
                    "token.mint.denied"
                );
                Err(match denied.kind() {
                    DeniedKind::Unauthenticated => Status::unauthenticated(denied.to_string()),
                    DeniedKind::InvalidArgument => Status::invalid_argument(denied.to_string()),
                    DeniedKind::PermissionDenied => Status::permission_denied(denied.to_string()),
                    DeniedKind::Internal => Status::internal(denied.to_string()),
                })
            }
        }
    }
}

/// The `OpenID` Connect discovery document for `minter`'s issuer.
#[must_use]
pub fn discovery(minter: &Minter) -> serde_json::Value {
    serde_json::json!({
        "issuer": minter.issuer(),
        "jwks_uri": format!("{}/.well-known/jwks.json", minter.issuer()),
        "response_types_supported": ["id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256"],
    })
}

/// Build the minter from a configuration, reading every file it names.
///
/// # Errors
///
/// A description naming the file or setting at fault.
pub fn load(cfg: &Config) -> Result<Minter, String> {
    let read = |path: &std::path::Path| {
        std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
    };
    let mut keys = Vec::new();
    for file in &cfg.keys {
        let pem = read(&file.path)?;
        let der = pkcs8_der(&pem).map_err(|e| format!("{}: {e}", file.path.display()))?;
        keys.push(
            Key::from_pkcs8(&der, file.sign)
                .map_err(|e| format!("{}: {e}", file.path.display()))?,
        );
    }
    let pool = KeyPool::new(keys).map_err(|e| e.to_string())?;
    let grants = Grants::new(&cfg.trust_domain, cfg.grants.clone()).map_err(|e| e.to_string())?;
    Minter::new(
        &cfg.issuer,
        &cfg.trust_domain,
        Duration::from_secs(cfg.token_ttl_secs),
        &read(&cfg.pod_ca)?,
        pool,
        grants,
    )
}

fn pkcs8_der(pem: &str) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    let body: String = pem
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN PRIVATE KEY-----"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    if body.is_empty() {
        return Err("no -----BEGIN PRIVATE KEY----- block (PKCS#8 PEM)".into());
    }
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|e| format!("the key is not base64: {e}"))
}

/// Serve the gRPC API on `listener` until it fails.
///
/// # Errors
///
/// When the TLS material is unusable or the server stops.
pub async fn serve_grpc(
    listener: TcpListener,
    server_cert_pem: &str,
    server_key_pem: &str,
    node_ca_pem: &str,
    service: Service,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // A client certificate from the node CA is required: with client_ca_root
    // set, tonic refuses a handshake without one.
    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(server_cert_pem, server_key_pem))
        .client_ca_root(Certificate::from_pem(node_ca_pem));
    Server::builder()
        .tls_config(tls)?
        .add_service(TokenIssuerServer::new(service))
        .serve_with_incoming(tokio_stream_listener(listener))
        .await?;
    Ok(())
}

fn tokio_stream_listener(
    listener: TcpListener,
) -> impl tokio_stream::Stream<Item = std::io::Result<tokio::net::TcpStream>> {
    tokio_stream::wrappers::TcpListenerStream::new(listener)
}

/// The HTTP routes: discovery and JWKS on the public listener, metrics and
/// health on the internal one. Returns status, content type and body.
#[must_use]
pub fn route(
    path: &str,
    public: bool,
    minter: &Minter,
    metrics: &Metrics,
) -> (u16, &'static str, String) {
    match (public, path) {
        (true, "/.well-known/openid-configuration") => {
            (200, "application/json", discovery(minter).to_string())
        }
        (true, "/.well-known/jwks.json") => (200, "application/json", minter.jwks().to_string()),
        (false, "/metrics") => (200, "text/plain; version=0.0.4", metrics.render()),
        (_, "/healthz") => (200, "text/plain", "ok\n".into()),
        _ => (404, "text/plain", "not found\n".into()),
    }
}

/// Serve [`route`] on `listener`: GET only, one request per connection.
pub async fn serve_http(
    listener: TcpListener,
    public: bool,
    minter: Arc<Minter>,
    metrics: Arc<Metrics>,
) {
    loop {
        let Ok((mut conn, _)) = listener.accept().await else {
            continue;
        };
        let minter = Arc::clone(&minter);
        let metrics = Arc::clone(&metrics);
        tokio::spawn(async move {
            // A request line and headers fit easily; nothing here reads a body.
            let mut buf = [0u8; 4096];
            let Ok(n) = conn.read(&mut buf).await else {
                return;
            };
            let head = String::from_utf8_lossy(&buf[..n]);
            let mut parts = head.lines().next().unwrap_or("").split(' ');
            let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
            let (status, content_type, body) = if method == "GET" {
                route(path, public, &minter, &metrics)
            } else {
                (405, "text/plain", "GET only\n".into())
            };
            let reason = match status {
                200 => "OK",
                404 => "Not Found",
                _ => "Method Not Allowed",
            };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\n\
                 Content-Length: {}\r\nCache-Control: max-age=300\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = conn.write_all(response.as_bytes()).await;
        });
    }
}

/// Run everything a configuration describes.
///
/// # Errors
///
/// When a file cannot be read, a listener cannot bind, or the gRPC server
/// stops.
pub async fn run(cfg: Config) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let minter = Arc::new(load(&cfg)?);
    let metrics = Arc::new(Metrics::default());
    let read = |path: &std::path::Path| {
        std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
    };
    let (cert, key, node_ca) = (
        read(&cfg.server_cert)?,
        read(&cfg.server_key)?,
        read(&cfg.node_ca)?,
    );

    for (addr, public) in [(cfg.public_listen, true), (cfg.metrics_listen, false)] {
        if let Some(addr) = addr {
            let listener = bind(addr).await?;
            tokio::spawn(serve_http(
                listener,
                public,
                Arc::clone(&minter),
                Arc::clone(&metrics),
            ));
        }
    }
    tracing::info!(
        issuer = %cfg.issuer,
        listen = %cfg.listen,
        keys = cfg.keys.len(),
        grants = cfg.grants.len(),
        "token.issuer.start"
    );
    let listener = bind(cfg.listen).await?;
    serve_grpc(
        listener,
        &cert,
        &key,
        &node_ca,
        Service::new(minter, metrics),
    )
    .await
}

async fn bind(addr: SocketAddr) -> Result<TcpListener, String> {
    TcpListener::bind(addr)
        .await
        .map_err(|e| format!("cannot listen on {addr}: {e}"))
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}
