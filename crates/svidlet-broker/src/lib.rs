//! `svidlet-broker`: the per-cluster broker of docs/DESIGN.md.
//!
//! It holds the cluster's only Vault credential and never signs anything.
//! Certificates: attest the calling node and the pod with two TokenReviews and
//! a Pod read, enforce I1–I11, and ask Vault PKI to sign. Tokens: take the
//! identity from the caller's mTLS certificate, enforce T1–T7, and ask Vault's
//! SPIFFE engine to mint — or answer from a cache shared by every pod with the
//! same identity.

#![forbid(unsafe_code)]

pub mod catalog;
pub mod config;
pub mod csr;
pub mod kube;
pub mod limit;
pub mod metrics;
pub mod publish;
pub mod refusal;
pub mod server;
pub mod sign;
pub mod tokens;

use std::sync::{Arc, RwLock};

use svidlet_issue::{
    AppRoleAuth, Issuer, JwtAuth, JwtMinter, StaticTokenAuth, VaultEndpoint, VaultHttp,
    VaultIssuer, VaultPkiConfig, VaultSpiffe,
};
use tokio::net::TcpListener;
use tracing::info;

use crate::catalog::CatalogHandle;
use crate::config::{Config, VaultAuth};
use crate::kube::HttpKube;
use crate::server::{Broker, Port, ReloadingCert};
use crate::sign::Signer;
use crate::tokens::{JwksSource, Tokens};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The two Vault engines the broker calls.
pub type VaultBackends = (Arc<dyn Issuer>, Arc<dyn JwtMinter>);

/// Vault PKI signer and SPIFFE minter, each with its own login from the same
/// credential.
pub fn build_vault(cfg: &Config) -> Result<VaultBackends, BoxError> {
    let ca_cert_pem = match &cfg.vault.ca_cert_path {
        Some(p) => Some(
            std::fs::read_to_string(p).map_err(|e| format!("VAULT_CACERT {}: {e}", p.display()))?,
        ),
        None => None,
    };
    let http = Arc::new(VaultHttp::new(VaultEndpoint {
        address: cfg.vault.address.clone(),
        namespace: cfg.vault.namespace.clone(),
        ca_cert_pem,
        timeout: cfg.vault.timeout,
    })?);
    let pki = VaultPkiConfig {
        mount: cfg.vault.pki_mount.clone(),
        role: cfg.vault.pki_role.clone(),
    };
    let mount = cfg.vault.spiffe_mount.clone();
    Ok(match &cfg.vault.auth {
        VaultAuth::Jwt {
            mount: m,
            role,
            token_path,
        } => (
            Arc::new(VaultIssuer::new(
                http.clone(),
                pki,
                JwtAuth::new(http.clone(), m.clone(), role.clone(), token_path.clone()),
            )),
            Arc::new(VaultSpiffe::new(
                http.clone(),
                mount,
                JwtAuth::new(http, m.clone(), role.clone(), token_path.clone()),
            )),
        ),
        VaultAuth::AppRole {
            mount: m,
            role_id,
            secret_id_path,
        } => (
            Arc::new(VaultIssuer::new(
                http.clone(),
                pki,
                AppRoleAuth::new(
                    http.clone(),
                    m.clone(),
                    role_id.clone(),
                    secret_id_path.clone(),
                ),
            )),
            Arc::new(VaultSpiffe::new(
                http.clone(),
                mount,
                AppRoleAuth::new(http, m.clone(), role_id.clone(), secret_id_path.clone()),
            )),
        ),
        VaultAuth::Token { path } => (
            Arc::new(VaultIssuer::new(
                http.clone(),
                pki,
                StaticTokenAuth::new(path.clone()),
            )),
            Arc::new(VaultSpiffe::new(
                http,
                mount,
                StaticTokenAuth::new(path.clone()),
            )),
        ),
    })
}

/// Where T5/T6 read the JWKS: the public URL relying parties use, if set, so
/// "published" means what it says; otherwise Vault's own endpoint.
pub fn jwks_source(cfg: &Config, minter: Arc<dyn JwtMinter>) -> JwksSource {
    match cfg.jwks_url.clone() {
        Some(url) => {
            let agent: ureq::Agent = ureq::Agent::config_builder()
                .timeout_global(Some(std::time::Duration::from_secs(10)))
                .build()
                .into();
            JwksSource::new(Box::new(move || {
                agent
                    .get(&url)
                    .call()
                    .map_err(|e| format!("GET {url}: {e}"))?
                    .body_mut()
                    .read_to_string()
                    .map_err(|e| format!("GET {url}: {e}"))
            }))
        }
        None => JwksSource::new(Box::new(move || minter.jwks().map_err(|e| e.to_string()))),
    }
}

pub async fn run(cfg: Config) -> Result<(), BoxError> {
    info!(cluster = %cfg.cluster, trust_domain = %cfg.trust_domain, vault_auth = cfg.vault.auth.method(), "starting svidlet-broker");
    let cfg = Arc::new(cfg);
    let policy = Arc::new(cfg.id_policy()?);
    let catalog = CatalogHandle::load(cfg.catalog_path.clone())?;
    let kube = Arc::new(HttpKube::new(&cfg.kube)?);
    let (issuer, minter) = build_vault(&cfg)?;
    let jwks = Arc::new(jwks_source(&cfg, minter.clone()));
    {
        let jwks = jwks.clone();
        if let Err(e) = tokio::task::spawn_blocking(move || jwks.refresh()).await? {
            // Not fatal: certificates do not need it, and housekeeping retries.
            tracing::warn!(error = %e, "could not load the JWKS at start-up; tokens wait for it");
        }
    }
    let bundle = std::fs::read_to_string(&cfg.bundle_path).unwrap_or_default();

    let broker = Arc::new(Broker {
        signer: Signer::new(cfg.clone(), policy.clone(), kube, issuer, catalog.clone()),
        tokens: Tokens::new(cfg.clone(), policy, minter, catalog, jwks),
        metrics: Default::default(),
        bundle: RwLock::new(bundle),
        bundle_path: cfg.bundle_path.clone(),
    });

    let cert = Arc::new(ReloadingCert::load(&cfg.tls_cert_path, &cfg.tls_key_path)?);
    let sign_tls = server::sign_tls(cert.clone())?;
    let token_tls = server::token_tls(cert.clone(), &cfg.client_ca_path)?;

    let sign = TcpListener::bind(&cfg.sign_addr).await?;
    let tokens = TcpListener::bind(&cfg.token_addr).await?;
    info!(sign = %cfg.sign_addr, tokens = %cfg.token_addr, "listening");

    tokio::spawn(server::housekeeping(broker.clone(), cert, cfg.jwks_refresh));
    if !cfg.metrics_addr.is_empty() {
        let m = TcpListener::bind(&cfg.metrics_addr).await?;
        tokio::spawn(server::serve_metrics(m, broker.clone()));
    }

    tokio::select! {
        r = server::serve(sign, sign_tls, broker.clone(), Port::Sign) => r?,
        r = server::serve(tokens, token_tls, broker, Port::Tokens) => r?,
        _ = tokio::signal::ctrl_c() => info!("shutting down"),
    }
    Ok(())
}
