//! The certificate's Subject.
//!
//! The SPIFFE URI SAN is the identity; the Subject carries no authority. It is
//! still worth filling, because some relying parties insist on one: AWS IAM
//! Roles Anywhere refuses a certificate with an empty Subject and copies its
//! Common Name into the session's `sourceIdentity`, which is what `CloudTrail`
//! then shows. A pod name there is a useful breadcrumb; an empty Subject there
//! is a failed `CreateSession`.
//!
//! So svidlet sets exactly one attribute, `CN`, from a workload attribute the
//! operator picks — and never anything a relying party would mistake for an
//! identity. The CN is kept out of the SANs (the Vault request sets
//! `exclude_cn_from_sans`), so it can never become a DNS name a TLS client
//! would accept for a host.

use crate::error::{Error, Result};
use crate::template::WorkloadAttributes;

/// RFC 5280's upper bound for a Common Name, and AWS's upper bound for a
/// `sourceIdentity`. Both happen to be 64.
pub const MAX_COMMON_NAME_LEN: usize = 64;

/// Which workload attribute becomes the certificate's Common Name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SubjectSource {
    /// No Subject at all. What svidlet did before cloud federation; AWS IAM
    /// Roles Anywhere will not accept such a certificate.
    None,
    /// `CN=<pod name>` — distinct per pod, so `CloudTrail` can tell replicas
    /// apart. The default.
    #[default]
    PodName,
    /// `CN=<service account>` — stable across pod restarts, for relying
    /// parties that key anything off the Subject.
    ServiceAccount,
}

impl std::str::FromStr for SubjectSource {
    type Err = Error;

    fn from_str(text: &str) -> Result<SubjectSource> {
        match text {
            "none" => Ok(SubjectSource::None),
            "pod_name" => Ok(SubjectSource::PodName),
            "service_account" => Ok(SubjectSource::ServiceAccount),
            other => Err(Error::Config(format!(
                "certificate subject must be none, pod_name or service_account; got {other:?}"
            ))),
        }
    }
}

impl std::fmt::Display for SubjectSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl SubjectSource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            SubjectSource::None => "none",
            SubjectSource::PodName => "pod_name",
            SubjectSource::ServiceAccount => "service_account",
        }
    }

    /// The Common Name for a workload, or `None` when this source is off or
    /// the attribute is unusable.
    ///
    /// An attribute that is missing or would not survive as a CN yields no
    /// Subject rather than a failed issuance: the certificate is still a valid
    /// SVID for mTLS, and the cloud-profile check reports the gap.
    #[must_use]
    pub fn common_name(self, attrs: &WorkloadAttributes) -> Option<String> {
        match self {
            SubjectSource::None => None,
            SubjectSource::PodName => common_name(&attrs.pod_name),
            SubjectSource::ServiceAccount => common_name(&attrs.service_account),
        }
    }
}

/// Make a Common Name from a workload attribute.
///
/// Accepts only the characters AWS allows in a `sourceIdentity`
/// (`[A-Za-z0-9_+=,.@-]`), which covers every valid pod and `ServiceAccount`
/// name, and truncates to [`MAX_COMMON_NAME_LEN`] bytes. A pod name can be up
/// to 253 characters; the first 64 still identify a Deployment's pods, since
/// the random suffix is what gets cut only when the name is already very long.
pub fn common_name(raw: &str) -> Option<String> {
    if raw.is_empty() || !raw.bytes().all(is_source_identity_byte) {
        return None;
    }
    // Every accepted byte is ASCII, so any byte offset is a char boundary.
    Some(raw[..raw.len().min(MAX_COMMON_NAME_LEN)].to_string())
}

/// `[\w+=,.@-]`, the character class AWS documents for `sourceIdentity`.
#[must_use]
pub fn is_source_identity_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'+' | b'=' | b',' | b'.' | b'@' | b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attrs(pod: &str, sa: &str) -> WorkloadAttributes {
        WorkloadAttributes {
            pod_name: pod.into(),
            service_account: sa.into(),
            ..Default::default()
        }
    }

    #[test]
    fn the_default_is_the_pod_name() {
        assert_eq!(SubjectSource::default(), SubjectSource::PodName);
        assert_eq!(
            SubjectSource::default().common_name(&attrs("web-7d9f-x2x", "web")),
            Some("web-7d9f-x2x".into())
        );
    }

    #[test]
    fn each_source_picks_its_attribute() {
        let a = attrs("web-7d9f-x2x", "web");
        assert_eq!(SubjectSource::None.common_name(&a), None);
        assert_eq!(
            SubjectSource::ServiceAccount.common_name(&a),
            Some("web".into())
        );
    }

    #[test]
    fn sources_round_trip_through_their_names() {
        for s in [
            SubjectSource::None,
            SubjectSource::PodName,
            SubjectSource::ServiceAccount,
        ] {
            assert_eq!(s.to_string().parse::<SubjectSource>().unwrap(), s);
        }
        let err = "namespace".parse::<SubjectSource>().unwrap_err();
        assert_eq!(err.code(), crate::error::ErrorCode::Config);
    }

    #[test]
    fn long_names_are_cut_to_the_rfc_5280_bound() {
        let long = "a".repeat(253);
        let cn = common_name(&long).unwrap();
        assert_eq!(cn.len(), MAX_COMMON_NAME_LEN);
        assert_eq!(common_name("x").unwrap(), "x");
    }

    #[test]
    fn nothing_outside_the_source_identity_alphabet_becomes_a_subject() {
        assert_eq!(common_name(""), None);
        assert_eq!(common_name("a b"), None);
        assert_eq!(common_name("a/b"), None);
        assert_eq!(common_name("é"), None);
        assert_eq!(
            common_name("a,b=c+d@e_f.g-h"),
            Some("a,b=c+d@e_f.g-h".into())
        );
        // A missing attribute is no Subject, not an error.
        assert_eq!(SubjectSource::PodName.common_name(&attrs("", "web")), None);
    }
}
