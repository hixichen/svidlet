//! The pool of ES256 keys tokens are signed with, and the JWKS that publishes
//! them.
//!
//! A pool holds two to four keys. Some sign; all are published. Rotation is
//! done in generations, by configuration alone:
//!
//! 1. Add the next generation with `sign = false`. Relying parties fetch the
//!    JWKS and learn its `kid` before any token uses it.
//! 2. Once every relying party's JWKS cache has turned over (their documented
//!    maximum, typically a day), flip it to `sign = true` and the old
//!    generation to `sign = false`.
//! 3. Once the longest-lived token signed by the old generation has expired
//!    (the token lifetime, 6 h by default), remove it.
//!
//! The kid is the RFC 7638 JWK thumbprint, so it is derived from the key and
//! identical on every replica without coordination.

use std::fmt;

use base64::Engine as _;
use ring::rand::{SecureRandom as _, SystemRandom};
use ring::signature::{self, EcdsaKeyPair, KeyPair as _};

/// One key of the pool.
pub struct Key {
    kid: String,
    pair: EcdsaKeyPair,
    sign: bool,
    x: String,
    y: String,
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The private half is not printable; the kid names the key.
        f.debug_struct("Key")
            .field("kid", &self.kid)
            .field("sign", &self.sign)
            .finish_non_exhaustive()
    }
}

impl Key {
    /// Load a P-256 key from PKCS#8 DER.
    ///
    /// # Errors
    ///
    /// [`KeyError`] when the bytes are not a P-256 PKCS#8 key.
    pub fn from_pkcs8(der: &[u8], sign: bool) -> Result<Key, KeyError> {
        let pair = EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            der,
            &SystemRandom::new(),
        )
        .map_err(|e| KeyError(format!("not a P-256 PKCS#8 key: {e}")))?;
        // Uncompressed point: 0x04 || x (32 bytes) || y (32 bytes).
        let point = pair.public_key().as_ref();
        let b64 = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let (x, y) = (b64(&point[1..33]), b64(&point[33..65]));
        Ok(Key {
            kid: thumbprint(&x, &y),
            pair,
            sign,
            x,
            y,
        })
    }

    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The public key as a JWK.
    #[must_use]
    pub fn jwk(&self) -> serde_json::Value {
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": self.x,
            "y": self.y,
            "kid": self.kid,
            "alg": "ES256",
            "use": "sig",
        })
    }
}

/// RFC 7638: SHA-256 over the required members in lexicographic order, with
/// no whitespace, base64url-encoded.
fn thumbprint(x: &str, y: &str) -> String {
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    let digest = ring::digest::digest(&ring::digest::SHA256, canonical.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_ref())
}

/// Every key the issuer publishes, and the ones it signs with.
#[derive(Debug)]
pub struct KeyPool {
    keys: Vec<Key>,
    rng: SystemRandom,
}

impl KeyPool {
    /// Build a pool.
    ///
    /// # Errors
    ///
    /// [`KeyError`] when no key signs, or two keys share a kid (the same key
    /// configured twice).
    pub fn new(keys: Vec<Key>) -> Result<KeyPool, KeyError> {
        if !keys.iter().any(|k| k.sign) {
            return Err(KeyError(
                "no key has sign = true; the issuer could publish but never sign".into(),
            ));
        }
        for (i, key) in keys.iter().enumerate() {
            if keys[..i].iter().any(|k| k.kid == key.kid) {
                return Err(KeyError(format!("key {} is configured twice", key.kid)));
            }
        }
        Ok(KeyPool {
            keys,
            rng: SystemRandom::new(),
        })
    }

    /// The JWKS document: every key, signing or not.
    #[must_use]
    pub fn jwks(&self) -> serde_json::Value {
        serde_json::json!({ "keys": self.keys.iter().map(Key::jwk).collect::<Vec<_>>() })
    }

    /// Sign a JWS with a signing key chosen uniformly from the pool.
    ///
    /// `signing_input_for` gets the chosen key's kid, which belongs in the
    /// header, and returns `base64url(header) "." base64url(payload)`. The
    /// result is the kid and the compact JWS, signature raw `r || s` as ES256
    /// requires.
    ///
    /// # Errors
    ///
    /// [`KeyError`] if the system random source fails.
    pub fn sign(
        &self,
        signing_input_for: impl Fn(&str) -> String,
    ) -> Result<(String, String), KeyError> {
        let signing: Vec<&Key> = self.keys.iter().filter(|k| k.sign).collect();
        let mut pick = [0u8; 1];
        self.rng
            .fill(&mut pick)
            .map_err(|ring::error::Unspecified| KeyError("the random source failed".into()))?;
        let key = signing[usize::from(pick[0]) % signing.len()];
        let signing_input = signing_input_for(&key.kid);
        let sig = key
            .pair
            .sign(&self.rng, signing_input.as_bytes())
            .map_err(|ring::error::Unspecified| KeyError("ES256 signing failed".into()))?;
        let token = format!(
            "{signing_input}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.as_ref())
        );
        Ok((key.kid.clone(), token))
    }

    /// Fill `out` with random bytes.
    ///
    /// # Errors
    ///
    /// [`KeyError`] if the system random source fails.
    pub fn random(&self, out: &mut [u8]) -> Result<(), KeyError> {
        self.rng
            .fill(out)
            .map_err(|ring::error::Unspecified| KeyError("the random source failed".into()))
    }
}

/// A key or pool that cannot be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyError(String);

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "signing keys: {}", self.0)
    }
}

impl std::error::Error for KeyError {}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn pkcs8() -> Vec<u8> {
        EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &SystemRandom::new(),
        )
        .unwrap()
        .as_ref()
        .to_vec()
    }

    #[test]
    fn the_kid_is_the_rfc_7638_thumbprint_of_the_public_key() {
        let der = pkcs8();
        let a = Key::from_pkcs8(&der, true).unwrap();
        let b = Key::from_pkcs8(&der, false).unwrap();
        // Derived from the key alone: identical on every replica.
        assert_eq!(a.kid(), b.kid());
        // 32 bytes of SHA-256, base64url without padding.
        assert_eq!(a.kid().len(), 43);
        let other = Key::from_pkcs8(&pkcs8(), true).unwrap();
        assert_ne!(a.kid(), other.kid());
    }

    #[test]
    fn the_thumbprint_hashes_the_canonical_member_order() {
        // RFC 7638 §3.2: required members only, sorted, no whitespace.
        let expected = {
            let d = ring::digest::digest(
                &ring::digest::SHA256,
                br#"{"crv":"P-256","kty":"EC","x":"AA","y":"AQ"}"#,
            );
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(d.as_ref())
        };
        assert_eq!(thumbprint("AA", "AQ"), expected);
    }

    #[test]
    fn the_jwks_publishes_every_key_and_no_private_material() {
        let pool = KeyPool::new(vec![
            Key::from_pkcs8(&pkcs8(), true).unwrap(),
            Key::from_pkcs8(&pkcs8(), false).unwrap(),
        ])
        .unwrap();
        let jwks = pool.jwks();
        let keys = jwks["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 2);
        for k in keys {
            assert_eq!(k["kty"], "EC");
            assert_eq!(k["alg"], "ES256");
            assert!(k.get("d").is_none(), "a private scalar in the JWKS: {k}");
        }
    }

    #[test]
    fn only_signing_keys_sign() {
        let publish_only = Key::from_pkcs8(&pkcs8(), false).unwrap();
        let signer = Key::from_pkcs8(&pkcs8(), true).unwrap();
        let signer_kid = signer.kid().to_string();
        let pool = KeyPool::new(vec![publish_only, signer]).unwrap();
        for _ in 0..20 {
            let (kid, _) = pool.sign(|kid| format!("h-{kid}.p")).unwrap();
            assert_eq!(kid, signer_kid);
        }
    }

    #[test]
    fn a_pool_that_cannot_sign_or_repeats_a_key_is_refused() {
        let _ = KeyPool::new(vec![Key::from_pkcs8(&pkcs8(), false).unwrap()]).unwrap_err();
        let der = pkcs8();
        let _ = KeyPool::new(vec![
            Key::from_pkcs8(&der, true).unwrap(),
            Key::from_pkcs8(&der, false).unwrap(),
        ])
        .unwrap_err();
        let _ = Key::from_pkcs8(b"nope", true).unwrap_err();
    }

    #[test]
    fn debug_output_never_contains_the_private_key() {
        let der = pkcs8();
        let rendered = format!("{:?}", Key::from_pkcs8(&der, true).unwrap());
        assert!(rendered.contains("kid"));
        let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
        assert!(!rendered.contains(&b64[b64.len() - 20..]));
    }
}
