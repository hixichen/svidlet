//! Proof that the caller holds a pod's private key.
//!
//! A pod certificate is public: every peer it talks to receives it in the
//! handshake. Asking for a token with only the certificate would let anyone who
//! had seen it — and held some node certificate in the same cluster — obtain
//! tokens as that pod. So each request carries a signature by the pod's key
//! over a [`message`] naming the calling node, the pod, the audience and the
//! time.
//!
//! Naming the node binds the proof to the mTLS connection it arrives on: the
//! issuer takes the node's ID from the client certificate, never from the
//! request, so a proof captured in transit is worthless through any other
//! node. The time bounds replay through the same node to [`WINDOW_SECS`].
//!
//! svidlet can make the proof because it generated the key and wrote it into
//! the pod's volume. The algorithm is the pod key's: ECDSA P-256 with SHA-256,
//! signature in ASN.1 DER.

use std::fmt;

use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, UnparsedPublicKey};

/// How far a proof's time may be from the issuer's clock, either way.
///
/// Wide enough to absorb clock skew between rented nodes and the issuer and a
/// slow round trip; narrow enough that a captured proof expires before it can
/// be carried anywhere useful — and it is bound to one node regardless.
pub const WINDOW_SECS: i64 = 120;

/// Domain separation: this key signs nothing else in this format.
const CONTEXT: &str = "svidlet-token-proof-v1";

/// The bytes a proof signs.
///
/// Newline-separated, which is unambiguous because none of the fields can
/// contain a newline: SPIFFE IDs cannot, and audiences are printable ASCII.
#[must_use]
pub fn message(node_id: &str, pod_id: &str, audience: &str, time: i64) -> Vec<u8> {
    format!("{CONTEXT}\n{node_id}\n{pod_id}\n{audience}\n{time}").into_bytes()
}

/// Sign `message` with a pod key, as written to the volume's `tls.key`.
///
/// # Errors
///
/// [`ProofError`] when the key is not a PKCS#8 PEM P-256 key.
pub fn sign(pod_key_pem: &str, message: &[u8]) -> Result<Vec<u8>, ProofError> {
    let der = pem_body(pod_key_pem, "PRIVATE KEY")?;
    let rng = SystemRandom::new();
    let key = EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &der, &rng)
        .map_err(|e| ProofError(format!("the pod key is not a P-256 PKCS#8 key: {e}")))?;
    key.sign(&rng, message)
        .map(|sig| sig.as_ref().to_vec())
        .map_err(|e| ProofError(format!("signing failed: {e}")))
}

/// Check a proof against the pod certificate's public key, the uncompressed
/// EC point from its `SubjectPublicKeyInfo`.
///
/// # Errors
///
/// [`ProofError`] when the signature does not verify.
pub fn verify(public_key: &[u8], message: &[u8], proof: &[u8]) -> Result<(), ProofError> {
    UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, public_key)
        .verify(message, proof)
        .map_err(|ring::error::Unspecified| {
            ProofError("the proof was not signed by the pod certificate's key".into())
        })
}

/// Whether a proof made at `time` is acceptable at `now`.
#[must_use]
pub fn is_fresh(time: i64, now: i64) -> bool {
    time.abs_diff(now) <= WINDOW_SECS.unsigned_abs()
}

fn pem_body(pem: &str, label: &str) -> Result<Vec<u8>, ProofError> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = pem
        .find(&begin)
        .ok_or_else(|| ProofError(format!("no {begin} block")))?
        + begin.len();
    let stop = pem[start..]
        .find(&end)
        .ok_or_else(|| ProofError(format!("no {end} line")))?
        + start;
    let body: String = pem[start..stop].split_whitespace().collect();
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|e| ProofError(format!("the {label} block is not base64: {e}")))
}

/// A proof that cannot be made or does not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofError(String);

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ProofError {}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::KeyPair as _;

    fn key() -> (String, Vec<u8>) {
        let rng = SystemRandom::new();
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap();
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            base64::engine::general_purpose::STANDARD.encode(pkcs8.as_ref())
        );
        (pem, pair.public_key().as_ref().to_vec())
    }

    const NODE: &str = "spiffe://example.org/cluster/a/node/n1";
    const POD: &str = "spiffe://example.org/cluster/a/ns/payments/sa/api";

    #[test]
    fn a_proof_verifies_against_the_matching_public_key() {
        let (pem, public) = key();
        let msg = message(NODE, POD, "snowflake", 1_700_000_000);
        let proof = sign(&pem, &msg).unwrap();
        verify(&public, &msg, &proof).unwrap();
    }

    #[test]
    fn every_field_is_bound_by_the_signature() {
        let (pem, public) = key();
        let proof = sign(&pem, &message(NODE, POD, "snowflake", 100)).unwrap();
        for other in [
            message(
                "spiffe://example.org/cluster/a/node/n2",
                POD,
                "snowflake",
                100,
            ),
            message(
                NODE,
                "spiffe://example.org/cluster/a/ns/x/sa/y",
                "snowflake",
                100,
            ),
            message(NODE, POD, "azure", 100),
            message(NODE, POD, "snowflake", 101),
        ] {
            let _ = verify(&public, &other, &proof).unwrap_err();
        }
    }

    #[test]
    fn another_key_does_not_verify() {
        let (pem, _) = key();
        let (_, other_public) = key();
        let msg = message(NODE, POD, "a", 1);
        let proof = sign(&pem, &msg).unwrap();
        let _ = verify(&other_public, &msg, &proof).unwrap_err();
    }

    #[test]
    fn freshness_is_symmetric_and_inclusive() {
        assert!(is_fresh(1000, 1000 + WINDOW_SECS));
        assert!(is_fresh(1000 + WINDOW_SECS, 1000));
        assert!(!is_fresh(1000, 1001 + WINDOW_SECS));
        assert!(!is_fresh(1001 + WINDOW_SECS, 1000));
        assert!(!is_fresh(i64::MIN, 0));
    }

    #[test]
    fn a_key_that_is_not_pkcs8_pem_is_refused() {
        for bad in [
            "",
            "not pem",
            "-----BEGIN PRIVATE KEY-----\n!!\n-----END PRIVATE KEY-----",
        ] {
            let _ = sign(bad, b"m").expect_err(&format!("{bad:?}"));
        }
    }
}
