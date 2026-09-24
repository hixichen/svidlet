//! Node-local key generation and CSR construction.
//!
//! The private key is generated on the node, held in memory only long enough to
//! be written into the pod's tmpfs, and never sent anywhere.

use rcgen::string::Ia5String;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};

use crate::error::{Error, Result};
use crate::template::SpiffeId;

/// A freshly generated P-256 key together with the CSR that requests a
/// certificate for one SPIFFE ID.
pub struct KeyAndCsr {
    /// PKCS#8 PEM. Written to `tls.key`.
    pub key_pem: String,
    /// PKCS#10 PEM, as Vault's `pki/sign` endpoint expects it.
    pub csr_pem: String,
}

/// Generate a P-256 key and a CSR whose only subject alternative name is the
/// workload's SPIFFE URI.
///
/// The SPIFFE ID is the whole identity. `common_name`, when given, is the
/// Subject's only attribute — a label for relying parties that insist on a
/// non-empty Subject (see [`crate::subject`]), never a SAN. Without one the
/// Subject is empty, and a Vault role must then set `require_cn=false`.
pub fn generate(spiffe_id: &SpiffeId, common_name: Option<&str>) -> Result<KeyAndCsr> {
    let san = Ia5String::try_from(spiffe_id.as_str())
        .map_err(|e| Error::Crypto(format!("SPIFFE ID is not a valid IA5 string: {e}")))?;

    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| Error::Crypto(format!("P-256 key generation failed: {e}")))?;

    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    if let Some(cn) = common_name {
        params.distinguished_name.push(DnType::CommonName, cn);
    }
    params.subject_alt_names = vec![SanType::URI(san)];

    let csr = params
        .serialize_request(&key_pair)
        .map_err(|e| Error::Crypto(format!("CSR construction failed: {e}")))?;

    Ok(KeyAndCsr {
        key_pem: key_pair.serialize_pem(),
        csr_pem: csr
            .pem()
            .map_err(|e| Error::Crypto(format!("CSR PEM encoding failed: {e}")))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::prelude::*;

    #[test]
    fn csr_carries_the_spiffe_uri_san_and_nothing_else() {
        let id = SpiffeId::parse("spiffe://example.org/cluster/a/ns/default/sa/web").unwrap();
        let out = generate(&id, None).unwrap();

        assert!(out.key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(out
            .csr_pem
            .starts_with("-----BEGIN CERTIFICATE REQUEST-----"));

        let (_, pem) = parse_x509_pem(out.csr_pem.as_bytes()).unwrap();
        let (_, csr) = X509CertificationRequest::from_der(&pem.contents).unwrap();
        csr.verify_signature().expect("CSR is self-signed");

        // Empty subject: the SPIFFE URI SAN is the entire identity.
        assert_eq!(csr.certification_request_info.subject.iter().count(), 0);

        let sans = csr
            .requested_extensions()
            .unwrap()
            .find_map(|ext| match ext {
                ParsedExtension::SubjectAlternativeName(san) => Some(san),
                _ => None,
            })
            .expect("CSR requests a SubjectAlternativeName extension");

        let names: Vec<_> = sans.general_names.iter().collect();
        assert_eq!(names.len(), 1, "exactly one SAN: {names:?}");
        assert!(matches!(names[0], GeneralName::URI(u) if *u == id.as_str()));
    }

    #[test]
    fn a_common_name_is_the_only_subject_attribute_and_never_a_san() {
        let id = SpiffeId::parse("spiffe://example.org/cluster/a/ns/default/sa/web").unwrap();
        let out = generate(&id, Some("web-7d9f-x2x")).unwrap();

        let (_, pem) = parse_x509_pem(out.csr_pem.as_bytes()).unwrap();
        let (_, csr) = X509CertificationRequest::from_der(&pem.contents).unwrap();
        let subject = &csr.certification_request_info.subject;
        assert_eq!(subject.iter_attributes().count(), 1);
        assert_eq!(
            subject.iter_common_name().next().unwrap().as_str().unwrap(),
            "web-7d9f-x2x"
        );

        let sans = csr
            .requested_extensions()
            .unwrap()
            .find_map(|ext| match ext {
                ParsedExtension::SubjectAlternativeName(san) => Some(san),
                _ => None,
            })
            .unwrap();
        assert_eq!(sans.general_names.len(), 1);
        assert!(matches!(sans.general_names[0], GeneralName::URI(_)));
    }

    #[test]
    fn each_call_generates_a_new_key() {
        let id = SpiffeId::parse("spiffe://example.org/ns/a/sa/b").unwrap();
        assert_ne!(
            generate(&id, None).unwrap().key_pem,
            generate(&id, None).unwrap().key_pem
        );
    }
}
