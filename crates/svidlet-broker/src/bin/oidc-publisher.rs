//! `oidc-publisher`: every minute, read Vault's SPIFFE discovery document and
//! JWKS, check them, and write them where the public bucket is synced from.
//!
//! Environment: `VAULT_ADDR`, `VAULT_CACERT` (optional), `VAULT_NAMESPACE`
//! (optional), `SVIDLET_SPIFFE_MOUNT` (default `spiffe`), `OIDC_ISSUER` (e.g.
//! `https://oidc.corp.example/v1/spiffe`), `OIDC_OUT_DIR`, `OIDC_INTERVAL`
//! (default `60s`; `0` runs once and exits non-zero if nothing was
//! published). The upload itself (`gsutil rsync`,
//! `aws s3 sync` with `Cache-Control: max-age=300`) is the sidecar's job, so
//! the bucket credential never reaches this process.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use svidlet_issue::{VaultEndpoint, VaultHttp};

fn env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let issuer = env("OIDC_ISSUER").ok_or("OIDC_ISSUER is required")?;
    let out = PathBuf::from(env("OIDC_OUT_DIR").ok_or("OIDC_OUT_DIR is required")?);
    let mount = env("SVIDLET_SPIFFE_MOUNT").unwrap_or_else(|| "spiffe".into());
    let interval = env("OIDC_INTERVAL")
        .map(|v| svidlet_issue::catalog::parse_duration(&v).ok_or(format!("OIDC_INTERVAL {v:?}")))
        .transpose()?
        .unwrap_or(Duration::from_secs(60));
    let http = Arc::new(VaultHttp::new(VaultEndpoint {
        address: env("VAULT_ADDR").ok_or("VAULT_ADDR is required")?,
        namespace: env("VAULT_NAMESPACE"),
        ca_cert_pem: env("VAULT_CACERT")
            .map(std::fs::read_to_string)
            .transpose()?,
        timeout: Duration::from_secs(10),
    })?);

    loop {
        let once = || -> Result<svidlet_broker::publish::Checked, String> {
            let discovery = http
                .get_text(&format!("{mount}/.well-known/openid-configuration"))
                .map_err(|e| e.to_string())?;
            let jwks = http
                .get_text(&format!("{mount}/.well-known/keys"))
                .map_err(|e| e.to_string())?;
            let checked = svidlet_broker::publish::check(&discovery, &jwks, &issuer)?;
            svidlet_broker::publish::write(&out, &issuer, &discovery, &jwks)
                .map_err(|e| format!("cannot write {}: {e}", out.display()))?;
            Ok(checked)
        };
        let outcome = once();
        match &outcome {
            Ok(c) => tracing::info!(issuer = %c.issuer, kids = ?c.kids, "published"),
            // Keep the last good copy; the stale-age alert is on the sidecar.
            Err(e) => tracing::error!(error = %e, "not published; the last good copy stays"),
        }
        if interval.is_zero() {
            // Run once (a CI job, a CronJob): the exit status is the result.
            return outcome.map(|_| ()).map_err(Into::into);
        }
        std::thread::sleep(interval);
    }
}
