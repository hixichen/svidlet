//! The token path (docs/DESIGN.md §6): derive the identity from the caller's
//! certificate, enforce T1–T7, and serve JWT-SVIDs from a shared cache or
//! from Vault's SPIFFE engine.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use svidlet_issue::catalog::{role_name, Identity};
use svidlet_issue::jwt::{decode_unverified, Jwks, Unverified};
use svidlet_issue::{IdPolicy, JwtMinter, SpiffeId};
use x509_parser::prelude::*;

use crate::catalog::CatalogHandle;
use crate::config::Config;
use crate::limit::Window;
use crate::refusal::{from_vault, Refusal};

/// The identity a caller's certificate proves, after T1 and T2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub spiffe_id: SpiffeId,
    pub namespace: String,
    pub service_account: String,
    /// The certificate's `notAfter`, which no token may outlive (T5).
    pub not_after: i64,
    /// For the audit log (T8).
    pub serial: String,
}

/// One token handed out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub alias: String,
    pub audience: String,
    pub token: String,
    pub exp: i64,
    pub jti: String,
    /// Whether this answer cost a Vault mint.
    pub minted: bool,
}

#[derive(Clone)]
struct Cached {
    token: String,
    parsed: Unverified,
}

/// The public JWKS, as relying parties see it (T5, T6).
pub struct JwksSource {
    fetch: Box<dyn Fn() -> Result<String, String> + Send + Sync>,
    state: Mutex<JwksState>,
}

struct JwksState {
    jwks: Option<Jwks>,
    /// When the last forced refresh ran, so a burst of misses costs one fetch.
    forced_at: i64,
}

impl JwksSource {
    pub fn new(fetch: Box<dyn Fn() -> Result<String, String> + Send + Sync>) -> JwksSource {
        JwksSource {
            fetch,
            state: Mutex::new(JwksState {
                jwks: None,
                forced_at: i64::MIN,
            }),
        }
    }

    /// Fetch and replace. On failure the last good set stays: fail stale.
    pub fn refresh(&self) -> Result<usize, String> {
        let text = (self.fetch)()?;
        let jwks = Jwks::parse(&text).map_err(|e| e.to_string())?;
        if jwks.is_empty() {
            return Err("the JWKS holds no keys".into());
        }
        let n = jwks.len();
        self.state.lock().expect("jwks poisoned").jwks = Some(jwks);
        Ok(n)
    }

    /// `Some(true)` if `kid` is published, `None` if no JWKS was ever loaded.
    pub fn has(&self, kid: &str) -> Option<bool> {
        self.state
            .lock()
            .expect("jwks poisoned")
            .jwks
            .as_ref()
            .map(|j| j.contains(kid))
    }

    /// Refresh now unless one ran in the last ten seconds.
    fn refresh_if_stale(&self, now: i64) {
        {
            let mut st = self.state.lock().expect("jwks poisoned");
            if now.saturating_sub(st.forced_at) < 10 {
                return;
            }
            st.forced_at = now;
        }
        let _ = self.refresh();
    }
}

pub struct Tokens {
    pub cfg: Arc<Config>,
    pub policy: Arc<IdPolicy>,
    pub minter: Arc<dyn JwtMinter>,
    pub catalog: CatalogHandle,
    pub jwks: Arc<JwksSource>,
    cache: Mutex<HashMap<(String, String), Cached>>,
    mint_rate: Window,
}

impl Tokens {
    pub fn new(
        cfg: Arc<Config>,
        policy: Arc<IdPolicy>,
        minter: Arc<dyn JwtMinter>,
        catalog: CatalogHandle,
        jwks: Arc<JwksSource>,
    ) -> Tokens {
        Tokens {
            mint_rate: Window::new(cfg.mint_rate_per_minute, 60),
            cfg,
            policy,
            minter,
            catalog,
            jwks,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// T1 and T2 on a certificate the TLS layer already chained to the
    /// pinned root (with client-auth usage and a current validity window).
    pub fn caller(&self, leaf_der: &[u8], now: i64) -> Result<Caller, Refusal> {
        let (_, cert) = X509Certificate::from_der(leaf_der).map_err(|e| {
            Refusal::unauthenticated("T1", format!("unreadable client certificate: {e}"))
        })?;
        if cert.is_ca() {
            return Err(Refusal::unauthenticated(
                "T1",
                "the client certificate is a CA",
            ));
        }
        let validity = cert.validity();
        if now < validity.not_before.timestamp() || now >= validity.not_after.timestamp() {
            return Err(Refusal::unauthenticated(
                "T1",
                "the client certificate is not currently valid",
            ));
        }
        let san = cert
            .subject_alternative_name()
            .map_err(|e| Refusal::unauthenticated("T1", format!("malformed SAN: {e}")))?
            .ok_or_else(|| Refusal::unauthenticated("T1", "the client certificate has no SAN"))?;
        let uris: Vec<&str> = san
            .value
            .general_names
            .iter()
            .filter_map(|n| match n {
                GeneralName::URI(u) => Some(*u),
                _ => None,
            })
            .collect();
        let [uri] = uris.as_slice() else {
            return Err(Refusal::unauthenticated(
                "T1",
                format!("expected exactly one URI SAN, found {}", uris.len()),
            ));
        };
        let spiffe_id = SpiffeId::parse(uri).map_err(|e| {
            Refusal::unauthenticated("T1", format!("the URI SAN is not a SPIFFE ID: {e}"))
        })?;
        self.policy
            .check(spiffe_id.as_str())
            .map_err(|e| Refusal::forbidden("T1", e.to_string()))?;
        let attrs = self
            .policy
            .attributes_of(spiffe_id.as_str())
            .ok_or_else(|| {
                Refusal::forbidden(
                    "T1",
                    format!("{spiffe_id} does not have this cluster's ID shape"),
                )
            })?;
        if attrs.trust_domain != self.cfg.trust_domain && !attrs.trust_domain.is_empty() {
            return Err(Refusal::forbidden(
                "T1",
                format!("{spiffe_id} is in another trust domain"),
            ));
        }
        // T2: the cluster is this broker's, checked before Vault is called.
        if attrs.cluster != self.cfg.cluster {
            return Err(Refusal::forbidden(
                "T2",
                format!(
                    "{spiffe_id} belongs to cluster {:?}, not {:?}",
                    attrs.cluster, self.cfg.cluster
                ),
            ));
        }
        if attrs.namespace.is_empty() || attrs.service_account.is_empty() {
            return Err(Refusal::forbidden(
                "T1",
                format!("{spiffe_id} names no namespace and ServiceAccount"),
            ));
        }
        Ok(Caller {
            spiffe_id,
            namespace: attrs.namespace,
            service_account: attrs.service_account,
            not_after: validity.not_after.timestamp(),
            serial: cert.raw_serial_as_string(),
        })
    }

    fn entry(&self, caller: &Caller) -> Result<Identity, Refusal> {
        let catalog = self.catalog.current();
        catalog
            .lookup(
                &self.cfg.cluster,
                &caller.namespace,
                &caller.service_account,
            )
            .cloned()
            .ok_or_else(|| {
                Refusal::forbidden("T3", format!("{} has no catalog entry", caller.spiffe_id))
            })
    }

    /// File mode: every approved audience. All or nothing for transient
    /// failures, so the node never replaces a good set with a partial one; an
    /// audience Vault refuses outright (a grant the policy does not carry yet)
    /// is left out.
    pub fn all(&self, caller: &Caller, now: i64) -> Result<Vec<Grant>, Refusal> {
        let entry = self.entry(caller)?;
        let mut out = Vec::with_capacity(entry.audiences.len());
        for aud in &entry.audiences {
            match self.one(caller, &entry, &aud.audience, now) {
                Ok(g) => out.push(g),
                Err(Refusal::Forbidden { rule: "vault", .. }) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    /// Direct mode: one audience, which must still be approved (T3).
    pub fn single(&self, caller: &Caller, audience: &str, now: i64) -> Result<Grant, Refusal> {
        let entry = self.entry(caller)?;
        self.one(caller, &entry, audience, now)
    }

    fn one(
        &self,
        caller: &Caller,
        entry: &Identity,
        audience: &str,
        now: i64,
    ) -> Result<Grant, Refusal> {
        let approved = entry.audience(audience).ok_or_else(|| {
            Refusal::forbidden(
                "T3",
                format!(
                    "audience {audience:?} is not approved for {}",
                    caller.spiffe_id
                ),
            )
        })?;
        // T4: the role comes from the SAN, never from the request.
        let role = role_name(
            &self.cfg.cluster,
            &caller.namespace,
            &caller.service_account,
        );
        let key = (role.clone(), audience.to_string());

        let cached = self
            .cache
            .lock()
            .expect("token cache poisoned")
            .get(&key)
            .cloned();
        if let Some(c) = cached {
            if self.servable(&c.parsed, caller, now)? {
                return Ok(grant(approved.alias.clone(), audience, c, false));
            }
        }

        if !self.mint_rate.allow(&role, now) {
            return Err(Refusal::too_many(
                "T7",
                format!("{} is over its mint rate", caller.spiffe_id),
            ));
        }
        let token = self.minter.mint(&role, audience).map_err(from_vault)?;
        let parsed = decode_unverified(&token).map_err(|e| Refusal::Internal {
            message: format!("Vault minted an unreadable token: {e}"),
        })?;
        // The role fixes the subject; check that Vault agrees.
        if parsed.claims.sub != caller.spiffe_id.as_str()
            || !parsed.claims.aud.iter().any(|a| a == audience)
        {
            return Err(Refusal::Internal {
                message: format!(
                    "role {role} minted sub={:?} aud={:?}; the Vault role does not match the catalog",
                    parsed.claims.sub, parsed.claims.aud
                ),
            });
        }
        // T6: only once relying parties can verify it.
        match self.jwks.has(&parsed.header.kid) {
            Some(true) => {}
            _ => {
                self.jwks.refresh_if_stale(now);
                if self.jwks.has(&parsed.header.kid) != Some(true) {
                    return Err(Refusal::unavailable(format!(
                        "signing key {} is not in the public JWKS yet",
                        parsed.header.kid
                    )));
                }
            }
        }
        // T5: a token never outlives the certificate that obtained it.
        if parsed.claims.exp > caller.not_after {
            return Err(Refusal::unavailable(
                "the client certificate expires before a new token would; renew the certificate first",
            ));
        }
        let fresh = Cached { token, parsed };
        self.cache
            .lock()
            .expect("token cache poisoned")
            .insert(key, fresh.clone());
        Ok(grant(approved.alias.clone(), audience, fresh, true))
    }

    /// T5 and T6 for a cached token.
    fn servable(&self, t: &Unverified, caller: &Caller, now: i64) -> Result<bool, Refusal> {
        if t.past_half_life(now) || t.claims.exp > caller.not_after {
            return Ok(false);
        }
        match self.jwks.has(&t.header.kid) {
            Some(true) => Ok(true),
            // Retired key: drop it and mint again (T6).
            Some(false) => Ok(false),
            None => Err(Refusal::unavailable(
                "the public JWKS has not been loaded yet",
            )),
        }
    }

    /// Drop cached tokens past half-life or whose key is retired, so memory
    /// tracks live identities.
    pub fn sweep(&self, now: i64) {
        let mut cache = self.cache.lock().expect("token cache poisoned");
        cache.retain(|_, c| {
            !c.parsed.past_half_life(now) && self.jwks.has(&c.parsed.header.kid) != Some(false)
        });
    }

    pub fn cached(&self) -> usize {
        self.cache.lock().expect("token cache poisoned").len()
    }
}

fn grant(alias: String, audience: &str, c: Cached, minted: bool) -> Grant {
    Grant {
        alias,
        audience: audience.to_string(),
        exp: c.parsed.claims.exp,
        jti: c.parsed.claims.jti.clone(),
        token: c.token,
        minted,
    }
}
