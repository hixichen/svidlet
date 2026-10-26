//! Reading JWT-SVIDs and JWKS documents.
//!
//! Nothing here verifies a signature, and nothing here signs. Vault's SPIFFE
//! secrets engine mints every token and owns the key; the broker and the node
//! only need to read what a token *says* — its `kid`, `sub`, `aud` and expiry —
//! to decide whether a cached token may still be handed out (rules T5 and T6
//! in docs/DESIGN.md). Relying parties verify signatures against the published
//! JWKS, which is the only place verification belongs.

use std::collections::BTreeSet;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::Deserialize;

use crate::error::{Error, Result};

/// The parts of a JWT header the broker looks at.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Header {
    pub alg: String,
    #[serde(default)]
    pub kid: String,
}

/// The registered claims of a JWT-SVID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claims {
    pub sub: String,
    pub aud: Vec<String>,
    pub iss: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
}

#[derive(Deserialize)]
struct RawClaims {
    #[serde(default)]
    sub: String,
    #[serde(default)]
    aud: Audience,
    #[serde(default)]
    iss: String,
    exp: i64,
    #[serde(default)]
    iat: i64,
    #[serde(default)]
    jti: String,
}

/// `aud` is a string or an array of strings (RFC 7519 §4.1.3).
#[derive(Deserialize, Default)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
    #[default]
    None,
}

/// A token whose header and claims have been read but not verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unverified {
    pub header: Header,
    pub claims: Claims,
}

impl Unverified {
    /// Lifetime as minted, in seconds.
    pub fn lifetime(&self) -> i64 {
        (self.claims.exp - self.claims.iat).max(0)
    }

    /// True once more than half of the lifetime has passed at `now` — the
    /// point at which T5 stops serving the token from cache.
    pub fn past_half_life(&self, now: i64) -> bool {
        let half = self.claims.iat + self.lifetime() / 2;
        now >= half
    }
}

/// Split and decode a compact JWS without checking its signature.
pub fn decode_unverified(token: &str) -> Result<Unverified> {
    let mut parts = token.split('.');
    let (Some(h), Some(c), Some(sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::Protocol("a JWT has exactly three parts".into()));
    };
    if sig.is_empty() {
        return Err(Error::Protocol("the JWT is unsigned".into()));
    }
    let header: Header = serde_json::from_slice(&b64(h, "header")?)
        .map_err(|e| Error::Protocol(format!("JWT header is not JSON: {e}")))?;
    if header.alg.eq_ignore_ascii_case("none") {
        return Err(Error::Protocol("the JWT uses alg=none".into()));
    }
    let raw: RawClaims = serde_json::from_slice(&b64(c, "claims")?)
        .map_err(|e| Error::Protocol(format!("JWT claims are not JSON: {e}")))?;
    let aud = match raw.aud {
        Audience::One(a) => vec![a],
        Audience::Many(a) => a,
        Audience::None => Vec::new(),
    };
    Ok(Unverified {
        header,
        claims: Claims {
            sub: raw.sub,
            aud,
            iss: raw.iss,
            exp: raw.exp,
            iat: raw.iat,
            jti: raw.jti,
        },
    })
}

fn b64(part: &str, what: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(part.trim_end_matches('='))
        .map_err(|e| Error::Protocol(format!("JWT {what} is not base64url: {e}")))
}

/// A JSON Web Key Set, reduced to what publishing and T6 need: which key IDs
/// it holds, and that every key in it is well formed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Jwks {
    kids: BTreeSet<String>,
}

#[derive(Deserialize)]
struct RawJwks {
    keys: Vec<RawJwk>,
}

#[derive(Deserialize)]
struct RawJwk {
    #[serde(default)]
    kid: String,
    #[serde(default)]
    kty: String,
    #[serde(default)]
    crv: String,
    #[serde(default)]
    x: String,
    #[serde(default)]
    y: String,
    #[serde(default)]
    n: String,
    #[serde(default)]
    e: String,
}

impl Jwks {
    /// Parse a JWKS and check every key in it.
    ///
    /// A key without a `kid`, of an unknown type, or with a coordinate that is
    /// not base64url fails the whole set: publishing a set a relying party
    /// chokes on is worse than publishing nothing new.
    pub fn parse(json: &str) -> Result<Jwks> {
        let raw: RawJwks = serde_json::from_str(json)
            .map_err(|e| Error::Protocol(format!("JWKS is not JSON: {e}")))?;
        let mut kids = BTreeSet::new();
        for key in raw.keys {
            if key.kid.is_empty() {
                return Err(Error::Protocol("a JWKS key has no kid".into()));
            }
            match key.kty.as_str() {
                "EC" => {
                    if !matches!(key.crv.as_str(), "P-256" | "P-384" | "P-521") {
                        return Err(Error::Protocol(format!(
                            "key {} has unsupported curve {:?}",
                            key.kid, key.crv
                        )));
                    }
                    b64(&key.x, "JWK x")?;
                    b64(&key.y, "JWK y")?;
                }
                "RSA" => {
                    if b64(&key.n, "JWK n")?.len() < 256 {
                        return Err(Error::Protocol(format!(
                            "key {} is an RSA key shorter than 2048 bits",
                            key.kid
                        )));
                    }
                    b64(&key.e, "JWK e")?;
                }
                other => {
                    return Err(Error::Protocol(format!(
                        "key {} has unsupported type {other:?}",
                        key.kid
                    )))
                }
            }
            if !kids.insert(key.kid.clone()) {
                return Err(Error::Protocol(format!("kid {} appears twice", key.kid)));
            }
        }
        Ok(Jwks { kids })
    }

    pub fn contains(&self, kid: &str) -> bool {
        self.kids.contains(kid)
    }

    pub fn kids(&self) -> impl Iterator<Item = &str> {
        self.kids.iter().map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.kids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.kids.is_empty()
    }
}

/// Build an unsigned-looking but structurally valid token for tests: the
/// signature segment is a placeholder, which is all the readers above need.
#[doc(hidden)]
pub fn test_token(kid: &str, sub: &str, aud: &str, iat: i64, exp: i64) -> String {
    let header = serde_json::json!({ "alg": "ES256", "kid": kid, "typ": "JWT" });
    let claims = serde_json::json!({
        "iss": "https://oidc.example/v1/spiffe",
        "sub": sub, "aud": [aud], "iat": iat, "nbf": iat, "exp": exp,
        "jti": format!("{kid}-{sub}-{aud}-{iat}"),
    });
    format!(
        "{}.{}.c2ln",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    )
}
