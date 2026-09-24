//! Will a cloud accept this certificate as a credential?
//!
//! Stage 1 of the roadmap makes the pod SVID the cloud credential itself: AWS
//! IAM Roles Anywhere and GCP Workload Identity Federation both trust a private
//! CA and condition access on the certificate's URI SAN. Each also has rules a
//! perfectly good mTLS certificate can break — an empty Subject, a second URI
//! SAN, a chain out of order — and each reports a violation as an opaque
//! `AccessDenied` at token-exchange time, long after issuance, in a pod's logs.
//!
//! This module checks an issued chain against those rules on the node, where a
//! misconfigured PKI role is cheap to spot. A finding is not an issuance
//! failure: the certificate is still a valid SVID for mTLS, and fail-stale says
//! a cloud-only defect must not cost a pod its identity. The caller reports it.
//!
//! The rules encoded here, and where they come from:
//!
//! | Rule | AWS | GCP | Why |
//! |---|---|---|---|
//! | `subject` | ✓ | | Roles Anywhere refuses an empty Subject |
//! | `common_name` | ✓ | | the CN becomes `sourceIdentity`: ≤64 bytes, `[\w+=,.@-]` |
//! | `uri_san` | ✓ | ✓ | exactly one URI SAN, a SPIFFE ID; AWS maps only the first |
//! | `basic_constraints` | ✓ | ✓ | the leaf must not be a CA |
//! | `key_usage` | ✓ | ✓ | `digitalSignature` must be present |
//! | `extended_key_usage` | | ✓ | GCP's STS is an mTLS client: `clientAuth` if EKU is present |
//! | `signature_algorithm` | ✓ | ✓ | SHA-256 or stronger |
//! | `key_algorithm` | ✓ | ✓ | P-256, P-384 or RSA |
//! | `chain_order` | ✓ | ✓ | leaf first, each certificate signed by the next |
//! | `chain_length` | | ✓ | at most 5 certificates |
//! | `lifetime` | | ✓ | at most 390 days |
//! | `gcp_subject` | | ✓ | `google.subject` is capped at 127 bytes |
//!
//! `gcp_subject` assumes the attribute mapping the roadmap recommends,
//! `google.subject = assertion.san.uri.extract('spiffe://<td>/cluster/{id}')`,
//! which yields the SPIFFE path after `cluster/`. An ID without that prefix is
//! measured by its whole path, which is what a mapping on the path would see.

use x509_parser::oid_registry::{
    Oid, OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_NIST_EC_P384, OID_PKCS1_RSAENCRYPTION,
    OID_PKCS1_RSASSAPSS, OID_PKCS1_SHA256WITHRSA, OID_PKCS1_SHA384WITHRSA, OID_PKCS1_SHA512WITHRSA,
    OID_SIG_ECDSA_WITH_SHA256, OID_SIG_ECDSA_WITH_SHA384, OID_SIG_ECDSA_WITH_SHA512,
};
use x509_parser::pem::Pem;
use x509_parser::prelude::*;

use crate::error::{Error, Result};
use crate::subject::{is_source_identity_byte, MAX_COMMON_NAME_LEN};

/// GCP's maximum certificate chain length for an X.509 workload identity pool.
pub const GCP_MAX_CHAIN_LEN: usize = 5;
/// GCP's maximum leaf lifetime: 390 days.
pub const GCP_MAX_LIFETIME_SECS: i64 = 390 * 86_400;
/// GCP's cap on the mapped `google.subject`.
pub const GCP_MAX_SUBJECT_LEN: usize = 127;

/// A relying party that accepts an X.509 SVID directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cloud {
    /// AWS IAM Roles Anywhere.
    Aws,
    /// GCP Workload Identity Federation with an X.509 provider.
    Gcp,
}

impl Cloud {
    pub const ALL: [Cloud; 2] = [Cloud::Aws, Cloud::Gcp];

    /// Position in [`Cloud::ALL`], for fixed-size metric tables.
    pub const fn index(self) -> usize {
        self as usize
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Cloud::Aws => "aws",
            Cloud::Gcp => "gcp",
        }
    }

    pub fn parse(text: &str) -> Result<Cloud> {
        match text {
            "aws" => Ok(Cloud::Aws),
            "gcp" => Ok(Cloud::Gcp),
            other => Err(Error::Config(format!(
                "cloud profile must be aws or gcp; got {other:?}"
            ))),
        }
    }

    /// Parse a comma-separated list such as `aws,gcp`. Empty means none.
    pub fn parse_list(text: &str) -> Result<Vec<Cloud>> {
        let mut out = Vec::new();
        for part in text.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let cloud = Cloud::parse(part)?;
            if !out.contains(&cloud) {
                out.push(cloud);
            }
        }
        Ok(out)
    }
}

/// One rule a certificate can break. The names are stable: they are metric
/// label values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rule {
    Subject,
    CommonName,
    UriSan,
    BasicConstraints,
    KeyUsage,
    ExtendedKeyUsage,
    SignatureAlgorithm,
    KeyAlgorithm,
    ChainOrder,
    ChainLength,
    Lifetime,
    GcpSubject,
}

impl Rule {
    pub const ALL: [Rule; 12] = [
        Rule::Subject,
        Rule::CommonName,
        Rule::UriSan,
        Rule::BasicConstraints,
        Rule::KeyUsage,
        Rule::ExtendedKeyUsage,
        Rule::SignatureAlgorithm,
        Rule::KeyAlgorithm,
        Rule::ChainOrder,
        Rule::ChainLength,
        Rule::Lifetime,
        Rule::GcpSubject,
    ];

    /// Position in [`Rule::ALL`], for fixed-size metric tables.
    pub const fn index(self) -> usize {
        self as usize
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Rule::Subject => "subject",
            Rule::CommonName => "common_name",
            Rule::UriSan => "uri_san",
            Rule::BasicConstraints => "basic_constraints",
            Rule::KeyUsage => "key_usage",
            Rule::ExtendedKeyUsage => "extended_key_usage",
            Rule::SignatureAlgorithm => "signature_algorithm",
            Rule::KeyAlgorithm => "key_algorithm",
            Rule::ChainOrder => "chain_order",
            Rule::ChainLength => "chain_length",
            Rule::Lifetime => "lifetime",
            Rule::GcpSubject => "gcp_subject",
        }
    }

    /// Whether `cloud` enforces this rule.
    pub fn applies_to(self, cloud: Cloud) -> bool {
        match self {
            Rule::Subject | Rule::CommonName => cloud == Cloud::Aws,
            Rule::ExtendedKeyUsage | Rule::ChainLength | Rule::Lifetime | Rule::GcpSubject => {
                cloud == Cloud::Gcp
            }
            _ => true,
        }
    }
}

/// A rule the certificate breaks, and for which cloud.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub cloud: Cloud,
    pub rule: Rule,
    pub detail: String,
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: {}: {}",
            self.cloud.as_str(),
            self.rule.as_str(),
            self.detail
        )
    }
}

/// Check a leaf-first PEM chain against every rule `clouds` enforce.
///
/// Returns the findings, each rule reported once per cloud that enforces it.
/// An empty result means every listed cloud should accept the chain as far as
/// its certificate can tell — trust anchors and IAM conditions are the
/// relying party's configuration, not the certificate's.
///
/// Errors only when the chain cannot be parsed at all.
pub fn check(chain_pem: &str, clouds: &[Cloud]) -> Result<Vec<Finding>> {
    if clouds.is_empty() {
        return Ok(Vec::new());
    }
    let pems: Vec<Pem> = Pem::iter_from_buffer(chain_pem.as_bytes())
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| Error::Certificate(format!("chain is not PEM: {e}")))?;
    if pems.is_empty() {
        return Err(Error::Certificate("chain holds no certificate".into()));
    }
    let certs: Vec<X509Certificate<'_>> = pems
        .iter()
        .map(|p| {
            X509Certificate::from_der(&p.contents)
                .map(|(_, c)| c)
                .map_err(|e| Error::Certificate(format!("not a DER certificate: {e}")))
        })
        .collect::<Result<_>>()?;

    let mut broken: Vec<(Rule, String)> = Vec::new();
    let leaf = &certs[0];
    check_subject(leaf, &mut broken);
    check_sans(leaf, &mut broken);
    check_usage(leaf, &mut broken);
    check_algorithms(leaf, &mut broken);
    check_chain(&certs, &mut broken);

    let lifetime = leaf.validity().not_after.timestamp() - leaf.validity().not_before.timestamp();
    if lifetime > GCP_MAX_LIFETIME_SECS {
        broken.push((
            Rule::Lifetime,
            format!("the leaf is valid for {lifetime}s; GCP accepts at most 390 days"),
        ));
    }

    let mut findings = Vec::new();
    for cloud in clouds {
        for (rule, detail) in &broken {
            if rule.applies_to(*cloud) {
                findings.push(Finding {
                    cloud: *cloud,
                    rule: *rule,
                    detail: detail.clone(),
                });
            }
        }
    }
    Ok(findings)
}

fn check_subject(leaf: &X509Certificate<'_>, broken: &mut Vec<(Rule, String)>) {
    if leaf.subject().iter_attributes().next().is_none() {
        broken.push((
            Rule::Subject,
            "the Subject is empty; set SVIDLET_CERT_SUBJECT and let the PKI role keep the CN"
                .into(),
        ));
        return;
    }
    if let Some(cn) = leaf.subject().iter_common_name().next() {
        match cn.as_str() {
            Ok(cn) if cn.len() > MAX_COMMON_NAME_LEN => broken.push((
                Rule::CommonName,
                format!(
                    "the CN is {} bytes; sourceIdentity takes at most 64",
                    cn.len()
                ),
            )),
            Ok(cn) if !cn.bytes().all(is_source_identity_byte) => broken.push((
                Rule::CommonName,
                format!("the CN {cn:?} has characters sourceIdentity refuses"),
            )),
            Ok(_) => {}
            Err(_) => broken.push((Rule::CommonName, "the CN is not a string".into())),
        }
    }
}

fn check_sans(leaf: &X509Certificate<'_>, broken: &mut Vec<(Rule, String)>) {
    let uris: Vec<&str> = match leaf.subject_alternative_name() {
        Ok(Some(san)) => san
            .value
            .general_names
            .iter()
            .filter_map(|n| match n {
                GeneralName::URI(u) => Some(*u),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };
    match uris.as_slice() {
        [only] if only.starts_with("spiffe://") => {
            let path = only["spiffe://".len()..]
                .split_once('/')
                .map(|(_, p)| p)
                .unwrap_or("");
            let mapped = path.strip_prefix("cluster/").unwrap_or(path);
            if mapped.len() > GCP_MAX_SUBJECT_LEN {
                broken.push((
                    Rule::GcpSubject,
                    format!(
                        "the mapped google.subject would be {} bytes; GCP accepts at most 127",
                        mapped.len()
                    ),
                ));
            }
        }
        [other] => broken.push((
            Rule::UriSan,
            format!("the URI SAN {other:?} is not a SPIFFE ID"),
        )),
        [] => broken.push((Rule::UriSan, "there is no URI SAN".into())),
        many => broken.push((
            Rule::UriSan,
            format!(
                "{} URI SANs; exactly one is mapped, so exactly one may be issued",
                many.len()
            ),
        )),
    }
}

fn check_usage(leaf: &X509Certificate<'_>, broken: &mut Vec<(Rule, String)>) {
    if leaf.is_ca() {
        broken.push((
            Rule::BasicConstraints,
            "the leaf is a CA certificate".into(),
        ));
    }
    match leaf.key_usage() {
        Ok(Some(ku)) if ku.value.digital_signature() => {}
        Ok(Some(_)) => broken.push((
            Rule::KeyUsage,
            "key usage does not include digitalSignature".into(),
        )),
        _ => broken.push((
            Rule::KeyUsage,
            "there is no key usage extension; digitalSignature is required".into(),
        )),
    }
    if let Ok(Some(eku)) = leaf.extended_key_usage() {
        if !eku.value.client_auth && !eku.value.any {
            broken.push((
                Rule::ExtendedKeyUsage,
                "extended key usage is present without clientAuth".into(),
            ));
        }
    }
}

fn check_algorithms(leaf: &X509Certificate<'_>, broken: &mut Vec<(Rule, String)>) {
    let strong: [&Oid<'static>; 7] = [
        &OID_SIG_ECDSA_WITH_SHA256,
        &OID_SIG_ECDSA_WITH_SHA384,
        &OID_SIG_ECDSA_WITH_SHA512,
        &OID_PKCS1_SHA256WITHRSA,
        &OID_PKCS1_SHA384WITHRSA,
        &OID_PKCS1_SHA512WITHRSA,
        &OID_PKCS1_RSASSAPSS,
    ];
    let sig = &leaf.signature_algorithm.algorithm;
    if !strong.contains(&sig) {
        broken.push((
            Rule::SignatureAlgorithm,
            format!("signed with {sig}; SHA-256 or stronger is required"),
        ));
    }

    let spki = &leaf.public_key().algorithm;
    let ok = if spki.algorithm == OID_KEY_TYPE_EC_PUBLIC_KEY {
        let curve = spki.parameters.as_ref().and_then(|p| p.as_oid().ok());
        curve.is_some_and(|c| c == OID_EC_P256 || c == OID_NIST_EC_P384)
    } else {
        spki.algorithm == OID_PKCS1_RSAENCRYPTION
    };
    if !ok {
        broken.push((
            Rule::KeyAlgorithm,
            format!(
                "the key is {}; P-256, P-384 or RSA is required",
                spki.algorithm
            ),
        ));
    }
}

fn check_chain(certs: &[X509Certificate<'_>], broken: &mut Vec<(Rule, String)>) {
    if certs.len() > GCP_MAX_CHAIN_LEN {
        broken.push((
            Rule::ChainLength,
            format!(
                "the chain holds {} certificates; GCP accepts at most {GCP_MAX_CHAIN_LEN}",
                certs.len()
            ),
        ));
    }
    for (i, pair) in certs.windows(2).enumerate() {
        let (child, parent) = (&pair[0], &pair[1]);
        let named = child.issuer().as_raw() == parent.subject().as_raw();
        if !named || child.verify_signature(Some(parent.public_key())).is_err() {
            broken.push((
                Rule::ChainOrder,
                format!(
                    "certificate {i} is not issued by certificate {}; the chain must be leaf first, \
                     then each issuer in turn",
                    i + 1
                ),
            ));
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
    };

    const ID: &str = "spiffe://example.org/cluster/a/ns/payments/sa/api";

    struct Ca {
        pem: String,
        issuer: Issuer<'static, KeyPair>,
    }

    fn ca(name: &str, parent: Option<&Ca>) -> Ca {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, name);
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let cert = match parent {
            None => params.self_signed(&key).unwrap(),
            Some(p) => params.signed_by(&key, &p.issuer).unwrap(),
        };
        let pem = cert.pem();
        Ca {
            issuer: Issuer::from_ca_cert_pem(&pem, key).unwrap(),
            pem,
        }
    }

    /// The profile svidlet and the documented Vault role produce.
    fn good_leaf() -> CertificateParams {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "api-7d9f8c-x2x4q");
        params.distinguished_name = dn;
        params.subject_alt_names = vec![SanType::URI(ID.try_into().unwrap())];
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyAgreement,
        ];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let now = ::time::OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + ::time::Duration::hours(6);
        params
    }

    fn sign(params: CertificateParams, by: &Ca) -> String {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        params.signed_by(&key, &by.issuer).unwrap().pem()
    }

    fn rules(findings: &[Finding], cloud: Cloud) -> Vec<Rule> {
        findings
            .iter()
            .filter(|f| f.cloud == cloud)
            .map(|f| f.rule)
            .collect()
    }

    #[test]
    fn the_svidlet_profile_passes_both_clouds() {
        let root = ca("root", None);
        let int = ca("intermediate", Some(&root));
        let chain = sign(good_leaf(), &int) + &int.pem;
        assert_eq!(check(&chain, &Cloud::ALL).unwrap(), vec![]);
    }

    #[test]
    fn no_clouds_means_no_checks() {
        assert_eq!(check("not even pem", &[]).unwrap(), vec![]);
    }

    #[test]
    fn an_empty_subject_is_refused_by_aws_only() {
        let root = ca("root", None);
        let mut leaf = good_leaf();
        leaf.distinguished_name = DistinguishedName::new();
        let findings = check(&sign(leaf, &root), &Cloud::ALL).unwrap();
        assert_eq!(rules(&findings, Cloud::Aws), vec![Rule::Subject]);
        assert_eq!(rules(&findings, Cloud::Gcp), vec![]);
    }

    #[test]
    fn a_common_name_that_cannot_be_a_source_identity_is_reported() {
        let root = ca("root", None);
        for bad in ["a".repeat(65), "has space".to_string()] {
            let mut leaf = good_leaf();
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, bad.as_str());
            leaf.distinguished_name = dn;
            let findings = check(&sign(leaf, &root), &[Cloud::Aws]).unwrap();
            assert_eq!(
                rules(&findings, Cloud::Aws),
                vec![Rule::CommonName],
                "{bad}"
            );
        }
    }

    #[test]
    fn exactly_one_spiffe_uri_san_is_required() {
        let root = ca("root", None);

        let mut two = good_leaf();
        two.subject_alt_names.push(SanType::URI(
            "spiffe://example.org/cluster/a/ns/x/sa/y"
                .try_into()
                .unwrap(),
        ));
        let findings = check(&sign(two, &root), &Cloud::ALL).unwrap();
        assert_eq!(rules(&findings, Cloud::Aws), vec![Rule::UriSan]);
        assert_eq!(rules(&findings, Cloud::Gcp), vec![Rule::UriSan]);

        let mut https = good_leaf();
        https.subject_alt_names = vec![SanType::URI("https://example.org".try_into().unwrap())];
        let findings = check(&sign(https, &root), &[Cloud::Gcp]).unwrap();
        assert_eq!(rules(&findings, Cloud::Gcp), vec![Rule::UriSan]);

        let mut none = good_leaf();
        none.subject_alt_names = vec![SanType::DnsName("api.example.org".try_into().unwrap())];
        let findings = check(&sign(none, &root), &[Cloud::Gcp]).unwrap();
        assert!(findings[0].detail.contains("no URI SAN"));
    }

    #[test]
    fn key_usage_must_include_digital_signature() {
        let root = ca("root", None);
        let mut leaf = good_leaf();
        leaf.key_usages = vec![KeyUsagePurpose::KeyEncipherment];
        let findings = check(&sign(leaf, &root), &Cloud::ALL).unwrap();
        assert_eq!(rules(&findings, Cloud::Aws), vec![Rule::KeyUsage]);

        let mut absent = good_leaf();
        absent.key_usages = vec![];
        let findings = check(&sign(absent, &root), &[Cloud::Aws]).unwrap();
        assert_eq!(rules(&findings, Cloud::Aws), vec![Rule::KeyUsage]);
    }

    #[test]
    fn gcp_needs_client_auth_when_extended_key_usage_is_present() {
        let root = ca("root", None);
        let mut server_only = good_leaf();
        server_only.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let findings = check(&sign(server_only, &root), &Cloud::ALL).unwrap();
        assert_eq!(rules(&findings, Cloud::Gcp), vec![Rule::ExtendedKeyUsage]);
        assert_eq!(rules(&findings, Cloud::Aws), vec![]);

        // No EKU at all constrains nothing.
        let mut none = good_leaf();
        none.extended_key_usages = vec![];
        assert_eq!(check(&sign(none, &root), &Cloud::ALL).unwrap(), vec![]);
    }

    #[test]
    fn a_ca_certificate_is_not_a_workload_credential() {
        let root = ca("root", None);
        let mut leaf = good_leaf();
        leaf.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let findings = check(&sign(leaf, &root), &[Cloud::Aws]).unwrap();
        assert_eq!(rules(&findings, Cloud::Aws), vec![Rule::BasicConstraints]);
    }

    #[test]
    fn the_chain_must_be_leaf_first_then_each_issuer() {
        let root = ca("root", None);
        let int = ca("intermediate", Some(&root));
        let leaf = sign(good_leaf(), &int);

        let reversed = int.pem.clone() + &leaf;
        let findings = check(&reversed, &[Cloud::Aws]).unwrap();
        assert!(rules(&findings, Cloud::Aws).contains(&Rule::ChainOrder));

        // Skipping the intermediate breaks the link as surely as reordering.
        let skipped = leaf.clone() + &root.pem;
        let findings = check(&skipped, &[Cloud::Gcp]).unwrap();
        assert_eq!(rules(&findings, Cloud::Gcp), vec![Rule::ChainOrder]);

        // Leaf, intermediate, root is fine.
        let full = leaf + &int.pem + &root.pem;
        assert_eq!(check(&full, &Cloud::ALL).unwrap(), vec![]);
    }

    #[test]
    fn gcp_limits_chain_length() {
        let mut cas = vec![ca("ca-0", None)];
        for i in 1..5 {
            let next = ca(&format!("ca-{i}"), cas.last());
            cas.push(next);
        }
        // Leaf plus five CAs, top of the stack first after the leaf.
        let mut chain = sign(good_leaf(), cas.last().unwrap());
        for c in cas.iter().rev() {
            chain.push_str(&c.pem);
        }
        let findings = check(&chain, &Cloud::ALL).unwrap();
        assert_eq!(rules(&findings, Cloud::Gcp), vec![Rule::ChainLength]);
        assert_eq!(rules(&findings, Cloud::Aws), vec![]);
    }

    #[test]
    fn gcp_limits_leaf_lifetime_to_390_days() {
        let root = ca("root", None);
        let mut leaf = good_leaf();
        leaf.not_after = leaf.not_before + ::time::Duration::days(391);
        let findings = check(&sign(leaf, &root), &Cloud::ALL).unwrap();
        assert_eq!(rules(&findings, Cloud::Gcp), vec![Rule::Lifetime]);
        assert_eq!(rules(&findings, Cloud::Aws), vec![]);
    }

    #[test]
    fn gcp_caps_the_mapped_subject_at_127_bytes() {
        let root = ca("root", None);
        // `cluster/` is dropped by the recommended mapping, so a path of
        // exactly 127 bytes after it passes and one more byte fails.
        let fits = format!("spiffe://example.org/cluster/{}", "a".repeat(127));
        let over = format!("spiffe://example.org/cluster/{}", "a".repeat(128));
        for (uri, expect) in [(fits, vec![]), (over, vec![Rule::GcpSubject])] {
            let mut leaf = good_leaf();
            leaf.subject_alt_names = vec![SanType::URI(uri.as_str().try_into().unwrap())];
            let findings = check(&sign(leaf, &root), &Cloud::ALL).unwrap();
            assert_eq!(rules(&findings, Cloud::Gcp), expect);
            assert_eq!(rules(&findings, Cloud::Aws), vec![]);
        }
    }

    #[test]
    fn unsupported_keys_are_reported() {
        let root = ca("root", None);
        let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let chain = good_leaf().signed_by(&key, &root.issuer).unwrap().pem();
        let findings = check(&chain, &[Cloud::Gcp]).unwrap();
        assert_eq!(rules(&findings, Cloud::Gcp), vec![Rule::KeyAlgorithm]);
    }

    #[test]
    fn garbage_is_an_error_not_a_finding() {
        for input in ["", "not pem"] {
            let err = check(input, &Cloud::ALL).unwrap_err();
            assert_eq!(err.code(), crate::error::ErrorCode::Certificate);
        }
    }

    #[test]
    fn cloud_lists_parse_and_deduplicate() {
        assert_eq!(Cloud::parse_list("").unwrap(), vec![]);
        assert_eq!(
            Cloud::parse_list(" aws, gcp ,aws").unwrap(),
            vec![Cloud::Aws, Cloud::Gcp]
        );
        assert!(Cloud::parse_list("azure").is_err());
        for (i, c) in Cloud::ALL.into_iter().enumerate() {
            assert_eq!(c.index(), i);
            assert_eq!(Cloud::parse(c.as_str()).unwrap(), c);
        }
    }

    #[test]
    fn every_rule_has_a_distinct_label_and_some_cloud() {
        let mut seen = std::collections::HashSet::new();
        for (i, r) in Rule::ALL.into_iter().enumerate() {
            assert_eq!(r.index(), i);
            assert!(seen.insert(r.as_str()));
            assert!(Cloud::ALL.iter().any(|c| r.applies_to(*c)));
        }
    }
}
