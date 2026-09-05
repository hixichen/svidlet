//! The material written into a pod's volume, and inspection of issued certificates.

use x509_parser::prelude::*;

use crate::error::{Error, Result};
use crate::template::SpiffeId;

/// PEM-encoded material written into the pod's volume.
#[derive(Debug, Clone)]
pub struct IssuedBundle {
    /// Leaf certificate followed by any intermediates. Written to `tls.crt`.
    pub cert_chain_pem: String,
    /// Trust bundle for the trust domain. Written to `ca.crt`.
    pub ca_pem: String,
    /// Unix seconds at which the leaf certificate expires.
    pub not_after: i64,
    /// Unix seconds at which the leaf certificate became valid.
    pub not_before: i64,
}

impl IssuedBundle {
    /// Certificate lifetime in seconds, as issued.
    pub fn lifetime_secs(&self) -> u64 {
        (self.not_after - self.not_before).max(0) as u64
    }
}

/// What a leaf certificate on disk says about itself.
///
/// Restart recovery rebuilds its renewal list from these: the identity and the
/// expiry both come from the certificate, so no state has to survive a restart
/// and nothing is re-issued just because the plugin was upgraded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertFacts {
    pub spiffe_id: SpiffeId,
    pub not_before: i64,
    pub not_after: i64,
}

/// Read the SPIFFE ID and validity window out of a PEM certificate chain.
///
/// Only the first certificate in the chain — the leaf — is inspected.
pub fn inspect(cert_chain_pem: &str) -> Result<CertFacts> {
    let (_, pem) = parse_x509_pem(cert_chain_pem.as_bytes())
        .map_err(|e| Error::Certificate(format!("not a PEM certificate: {e}")))?;
    let (_, cert) = X509Certificate::from_der(&pem.contents)
        .map_err(|e| Error::Certificate(format!("not a DER certificate: {e}")))?;

    let san = cert
        .subject_alternative_name()
        .map_err(|e| Error::Certificate(format!("malformed SubjectAlternativeName: {e}")))?
        .ok_or_else(|| Error::Certificate("certificate has no SubjectAlternativeName".into()))?;

    let raw = san
        .value
        .general_names
        .iter()
        .find_map(|name| match name {
            GeneralName::URI(uri) if uri.starts_with("spiffe://") => Some(*uri),
            _ => None,
        })
        .ok_or_else(|| Error::Certificate("certificate has no SPIFFE URI SAN".into()))?;

    Ok(CertFacts {
        spiffe_id: SpiffeId::parse(raw)?,
        not_before: cert.validity().not_before.timestamp(),
        not_after: cert.validity().not_after.timestamp(),
    })
}

/// Confirm the backend signed the identity that was asked for.
pub fn assert_identity(cert_chain_pem: &str, expected: &SpiffeId) -> Result<CertFacts> {
    let facts = inspect(cert_chain_pem)?;
    if facts.spiffe_id != *expected {
        return Err(Error::Certificate(format!(
            "backend signed {} but {expected} was requested",
            facts.spiffe_id
        )));
    }
    Ok(facts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCode;

    #[test]
    fn lifetime_never_goes_negative() {
        let bundle = |not_before, not_after| IssuedBundle {
            cert_chain_pem: String::new(),
            ca_pem: String::new(),
            not_before,
            not_after,
        };
        assert_eq!(bundle(100, 3700).lifetime_secs(), 3600);
        // A backend with a skewed clock must not produce a huge u64.
        assert_eq!(bundle(3700, 100).lifetime_secs(), 0);
    }

    #[test]
    fn garbage_is_reported_as_a_certificate_error() {
        for input in [
            "",
            "not pem",
            "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n",
        ] {
            let err = inspect(input).unwrap_err();
            assert_eq!(err.code(), ErrorCode::Certificate, "{input:?}");
            assert!(!err.is_retryable());
        }
    }
}
