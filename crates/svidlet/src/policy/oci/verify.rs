//! Signature verification and content addressing.
//!
//! The trust chain is one signature, not two:
//!
//! ```text
//! trusted Ed25519 public key → rollout.toml signature → bundle digest → bundle bytes
//! ```
//!
//! A node verifies the rollout manifest's signature, and then checks that the
//! blob it pulled hashes to the digest that signed manifest named. Tampering
//! with a bundle changes its digest, which no longer matches; tampering with
//! the manifest breaks its signature. A per-bundle signature would add nothing
//! and would be one more thing for CI to get wrong.

use base64::Engine as _;
use ring::digest;
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::Deserialize;

use super::Error;

/// The envelope CI produces around `rollout.toml`.
///
/// Deliberately boring, so a release pipeline can build it with a few lines of
/// shell around whatever holds the private key.
#[derive(Debug, Deserialize)]
pub struct SignedEnvelope {
    /// Envelope schema. Only `1` is understood.
    pub svidlet_signature: u32,
    pub algorithm: String,
    /// Which key signed this, for logs and for key rotation.
    #[serde(default)]
    pub key_id: String,
    /// Base64 of the signed bytes.
    pub payload: String,
    /// Base64 of the Ed25519 signature over the raw payload bytes.
    pub signature: String,
}

/// An Ed25519 public key the fleet trusts.
#[derive(Clone)]
pub struct PublicKey {
    raw: Vec<u8>,
    /// For logs. Not authenticated — the envelope's `key_id` is advisory.
    pub id: String,
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicKey").field("id", &self.id).finish()
    }
}

impl PublicKey {
    /// Accept a key as base64, hex, or a PEM block.
    ///
    /// An Ed25519 public key is 32 bytes; a PEM `PUBLIC KEY` wraps it in
    /// SubjectPublicKeyInfo, whose last 32 bytes are the key itself.
    pub fn parse(text: &str) -> Result<PublicKey, Error> {
        let text = text.trim();
        let bytes = if text.contains("-----BEGIN") {
            let body: String = text
                .lines()
                .filter(|l| !l.starts_with("-----"))
                .collect::<Vec<_>>()
                .join("");
            let der = base64::engine::general_purpose::STANDARD
                .decode(body.trim())
                .map_err(|e| Error::Config(format!("public key PEM is not valid base64: {e}")))?;
            if der.len() < 32 {
                return Err(Error::Config(format!(
                    "public key PEM decodes to {} bytes, too short for Ed25519",
                    der.len()
                )));
            }
            // SubjectPublicKeyInfo for Ed25519 is a 12-byte prefix then the key.
            der[der.len() - 32..].to_vec()
        } else if text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit()) {
            (0..32)
                .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16))
                .collect::<Result<Vec<u8>, _>>()
                .map_err(|e| Error::Config(format!("public key is not valid hex: {e}")))?
        } else {
            base64::engine::general_purpose::STANDARD
                .decode(text)
                .map_err(|e| Error::Config(format!("public key is not valid base64: {e}")))?
        };

        if bytes.len() != 32 {
            return Err(Error::Config(format!(
                "an Ed25519 public key is 32 bytes, got {}",
                bytes.len()
            )));
        }
        Ok(PublicKey {
            id: short_id(&bytes),
            raw: bytes,
        })
    }

    /// Verify `signature` over `payload`.
    pub fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<(), Error> {
        UnparsedPublicKey::new(&ED25519, &self.raw)
            .verify(payload, signature)
            .map_err(|_| {
                Error::Signature(format!(
                    "the signature does not verify against trusted key {}",
                    self.id
                ))
            })
    }
}

/// Open a signed envelope, returning the payload only if the signature holds.
pub fn open(envelope_json: &[u8], key: &PublicKey) -> Result<Vec<u8>, Error> {
    let envelope: SignedEnvelope = serde_json::from_slice(envelope_json)
        .map_err(|e| Error::Malformed(format!("signed envelope is not valid JSON: {e}")))?;

    if envelope.svidlet_signature != 1 {
        return Err(Error::Malformed(format!(
            "signed envelope schema {} is not supported",
            envelope.svidlet_signature
        )));
    }
    if !envelope.algorithm.eq_ignore_ascii_case("ed25519") {
        return Err(Error::Malformed(format!(
            "signature algorithm {:?} is not supported",
            envelope.algorithm
        )));
    }

    let b64 = base64::engine::general_purpose::STANDARD;
    let payload = b64
        .decode(envelope.payload.trim())
        .map_err(|e| Error::Malformed(format!("envelope payload is not valid base64: {e}")))?;
    let signature = b64
        .decode(envelope.signature.trim())
        .map_err(|e| Error::Malformed(format!("envelope signature is not valid base64: {e}")))?;

    key.verify(&payload, &signature)?;
    Ok(payload)
}

/// `sha256:<hex>` over `bytes`, in the form OCI uses.
pub fn sha256_digest(bytes: &[u8]) -> String {
    let hash = digest::digest(&digest::SHA256, bytes);
    let mut out = String::with_capacity(7 + 64);
    out.push_str("sha256:");
    for byte in hash.as_ref() {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Check that `bytes` really is what `expected` names.
pub fn check_digest(bytes: &[u8], expected: &str) -> Result<(), Error> {
    let actual = sha256_digest(bytes);
    if actual != expected {
        return Err(Error::Signature(format!(
            "content digest is {actual}, but the signed manifest named {expected}"
        )));
    }
    Ok(())
}

fn short_id(key: &[u8]) -> String {
    sha256_digest(key)
        .trim_start_matches("sha256:")
        .chars()
        .take(12)
        .collect()
}

#[cfg(test)]
pub mod testkit {
    //! Signing helpers. Tests only — svidlet never holds a private key.

    use base64::Engine as _;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    pub struct Signer {
        pair: Ed25519KeyPair,
    }

    impl Default for Signer {
        fn default() -> Signer {
            Signer::new()
        }
    }

    impl Signer {
        pub fn new() -> Signer {
            let rng = SystemRandom::new();
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
            Signer {
                pair: Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap(),
            }
        }

        pub fn public_key_base64(&self) -> String {
            base64::engine::general_purpose::STANDARD.encode(self.pair.public_key().as_ref())
        }

        pub fn public_key_hex(&self) -> String {
            self.pair
                .public_key()
                .as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        }

        /// Build the envelope CI would push.
        pub fn envelope(&self, payload: &[u8]) -> Vec<u8> {
            let b64 = base64::engine::general_purpose::STANDARD;
            serde_json::json!({
                "svidlet_signature": 1,
                "algorithm": "ed25519",
                "key_id": "test",
                "payload": b64.encode(payload),
                "signature": b64.encode(self.pair.sign(payload).as_ref()),
            })
            .to_string()
            .into_bytes()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::Signer;
    use super::*;

    #[test]
    fn a_signed_envelope_round_trips() {
        let signer = Signer::new();
        let key = PublicKey::parse(&signer.public_key_base64()).unwrap();
        let envelope = signer.envelope(b"schema = 1\n");

        assert_eq!(open(&envelope, &key).unwrap(), b"schema = 1\n");
    }

    #[test]
    fn a_tampered_payload_does_not_verify() {
        let signer = Signer::new();
        let key = PublicKey::parse(&signer.public_key_base64()).unwrap();
        let envelope = signer.envelope(b"freeze = false\n");

        // Swap the payload for a different one, keeping the signature.
        let mut parsed: serde_json::Value = serde_json::from_slice(&envelope).unwrap();
        parsed["payload"] =
            serde_json::json!(base64::engine::general_purpose::STANDARD.encode(b"freeze = true\n"));
        let tampered = parsed.to_string().into_bytes();

        let err = open(&tampered, &key).unwrap_err();
        assert!(matches!(err, Error::Signature(_)));
    }

    #[test]
    fn another_key_does_not_verify() {
        let signer = Signer::new();
        let attacker = Signer::new();
        let key = PublicKey::parse(&signer.public_key_base64()).unwrap();
        let err = open(&attacker.envelope(b"x"), &key).unwrap_err();
        assert!(matches!(err, Error::Signature(_)));
    }

    #[test]
    fn keys_are_accepted_as_base64_hex_or_pem() {
        let signer = Signer::new();
        let from_b64 = PublicKey::parse(&signer.public_key_base64()).unwrap();
        let from_hex = PublicKey::parse(&signer.public_key_hex()).unwrap();
        assert_eq!(from_b64.raw, from_hex.raw);
        assert_eq!(from_b64.id, from_hex.id);
        assert_eq!(from_b64.id.len(), 12);

        // A PEM SubjectPublicKeyInfo: 12-byte prefix, then the key.
        let mut der = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        der.extend_from_slice(&from_b64.raw);
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            base64::engine::general_purpose::STANDARD.encode(&der)
        );
        assert_eq!(PublicKey::parse(&pem).unwrap().raw, from_b64.raw);
    }

    #[test]
    fn a_key_of_the_wrong_length_is_a_configuration_error() {
        for bad in ["", "abcd", "not base64 at all!!", "00ff"] {
            assert!(
                matches!(PublicKey::parse(bad), Err(Error::Config(_))),
                "{bad:?}"
            );
        }
        assert!(matches!(
            PublicKey::parse("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"),
            Err(Error::Config(_))
        ));
    }

    #[test]
    fn envelopes_from_the_future_or_another_algorithm_are_refused() {
        let signer = Signer::new();
        let key = PublicKey::parse(&signer.public_key_base64()).unwrap();

        let mut parsed: serde_json::Value = serde_json::from_slice(&signer.envelope(b"x")).unwrap();
        parsed["svidlet_signature"] = serde_json::json!(2);
        assert!(matches!(
            open(parsed.to_string().as_bytes(), &key),
            Err(Error::Malformed(_))
        ));

        let mut parsed: serde_json::Value = serde_json::from_slice(&signer.envelope(b"x")).unwrap();
        parsed["algorithm"] = serde_json::json!("rsa");
        assert!(matches!(
            open(parsed.to_string().as_bytes(), &key),
            Err(Error::Malformed(_))
        ));

        assert!(matches!(open(b"not json", &key), Err(Error::Malformed(_))));
    }

    #[test]
    fn digests_are_lowercase_hex_in_the_oci_form() {
        assert_eq!(
            sha256_digest(b""),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(check_digest(b"", &sha256_digest(b"")).is_ok());

        let err = check_digest(b"tampered", &sha256_digest(b"original")).unwrap_err();
        assert!(matches!(err, Error::Signature(_)));
        assert!(err.to_string().contains("signed manifest named"));
    }
}
