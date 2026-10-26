//! I6: what the broker accepts in a CSR.
//!
//! The CSR contributes exactly one thing: the public key. Its names are
//! ignored (the broker renders the SPIFFE ID itself, I7), but the request must
//! be self-signed by a P-256 key and must not ask for a CA certificate.

use x509_parser::der_parser::oid;
use x509_parser::prelude::*;

/// Check a PEM CSR. Returns a human-readable reason on refusal.
pub fn check(pem: &str) -> Result<(), String> {
    let (_, block) = parse_x509_pem(pem.as_bytes()).map_err(|e| format!("CSR is not PEM: {e}"))?;
    if block.label != "CERTIFICATE REQUEST" {
        return Err(format!(
            "expected a CERTIFICATE REQUEST, got {}",
            block.label
        ));
    }
    let (_, csr) = X509CertificationRequest::from_der(&block.contents)
        .map_err(|e| format!("CSR is not DER: {e}"))?;
    csr.verify_signature()
        .map_err(|_| "the CSR's signature does not verify".to_string())?;

    let spki = &csr.certification_request_info.subject_pki;
    let ec_public_key = oid!(1.2.840 .10045 .2 .1);
    let p256 = oid!(1.2.840 .10045 .3 .1 .7);
    if spki.algorithm.algorithm != ec_public_key {
        return Err("the key is not an EC key".into());
    }
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.as_oid().ok());
    if curve.as_ref() != Some(&p256) {
        return Err("the key is not on P-256".into());
    }

    if let Some(extensions) = csr.requested_extensions() {
        for ext in extensions {
            if let ParsedExtension::BasicConstraints(bc) = ext {
                if bc.ca {
                    return Err("the CSR asks for a CA certificate".into());
                }
            }
        }
    }
    Ok(())
}
