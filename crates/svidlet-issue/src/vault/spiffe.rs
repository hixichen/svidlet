//! Vault's SPIFFE secrets engine: the JWT-SVID minter.
//!
//! The broker never signs a token. It asks Vault to mint one for a role whose
//! subject is fixed, with an audience Vault policy restricts — see
//! docs/DESIGN.md §6.1. That is the whole interface: `mintjwt` takes only an
//! audience, so a compromised broker cannot choose a subject.

use std::sync::Arc;

use serde::Deserialize;

use crate::auth::{TokenCache, TokenSource};
use crate::error::{Error, Result};

use super::http::VaultHttp;

/// Something that mints JWT-SVIDs and publishes the keys to check them.
///
/// Vault's SPIFFE engine is the implementation; the trait exists so the broker
/// can be tested without one.
pub trait JwtMinter: Send + Sync {
    /// Mint a token for `role` with exactly one audience.
    fn mint(&self, role: &str, audience: &str) -> Result<String>;

    /// The engine's current JWKS document, as JSON text.
    fn jwks(&self) -> Result<String>;
}

pub struct VaultSpiffe<S: TokenSource> {
    http: Arc<VaultHttp>,
    mount: String,
    tokens: TokenCache<S>,
}

impl<S: TokenSource> VaultSpiffe<S> {
    pub fn new(http: Arc<VaultHttp>, mount: impl Into<String>, source: S) -> VaultSpiffe<S> {
        VaultSpiffe {
            http,
            mount: mount.into().trim_matches('/').to_string(),
            tokens: TokenCache::new(source),
        }
    }

    pub fn mint_path(&self, role: &str) -> String {
        format!("{}/role/{role}/mintjwt", self.mount)
    }

    pub fn jwks_path(&self) -> String {
        format!("{}/.well-known/keys", self.mount)
    }

    pub fn discovery_path(&self) -> String {
        format!("{}/.well-known/openid-configuration", self.mount)
    }
}

#[derive(Deserialize)]
struct MintEnvelope {
    data: MintData,
}

#[derive(Deserialize)]
struct MintData {
    token: String,
}

impl<S: TokenSource> JwtMinter for VaultSpiffe<S> {
    fn mint(&self, role: &str, audience: &str) -> Result<String> {
        if role.contains('/') || role.is_empty() {
            return Err(Error::Identity(format!("{role:?} is not a role name")));
        }
        let path = self.mint_path(role);
        let body = serde_json::json!({ "audience": audience });
        let mut attempt = 0;
        loop {
            attempt += 1;
            let token = self.tokens.token()?;
            match self
                .http
                .post_json::<MintEnvelope>(&path, Some(&token), &[], &body)
            {
                Ok(v) if !v.data.token.is_empty() => return Ok(v.data.token),
                Ok(_) => return Err(Error::Protocol(format!("{path} returned no token"))),
                // As for PKI: a 403 may be a token Vault forgot. Log in once
                // more; a second 403 is a real refusal by policy.
                Err(Error::Backend { status: 403, .. }) if attempt == 1 => {
                    self.tokens.invalidate();
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn jwks(&self) -> Result<String> {
        self.http.get_text(&self.jwks_path())
    }
}
