//! The node certificate that `SVIDLET_VAULT_AUTH=cert` logs in with.
//!
//! svidlet does not obtain this certificate. Node bootstrap does —
//! [svidlet-node-bootstrap], an init container and a renewal sidecar in the
//! same pod, which attest the node (TPM where there is one) and write the
//! result into a shared memory-backed volume:
//!
//! | File | Content |
//! |---|---|
//! | `/node/node.crt` | PEM, leaf first, URI SAN `spiffe://<td>/cluster/<c>/node/<node>`, `CN=<node>` |
//! | `/node/node.key` | PEM private key for it |
//!
//! svidlet re-reads both on every Vault login, so a renewal swapped in by the
//! sidecar is used from the next login onwards, without a restart.
//!
//! This module is svidlet's side of that hand-off: it says what the
//! certificate must look like ([`expected_id`]), checks one against it
//! ([`check`]) and reads what is on disk ([`read`]). Problems are reported,
//! not fatal. A node whose bootstrap has not finished yet can still serve the
//! certificates it already published; failing stale beats failing closed.
//!
//! [svidlet-node-bootstrap]: https://github.com/hixichen/svidlet-node-bootstrap

use std::fmt;
use std::path::Path;

use svidlet_issue::CertFacts;

/// The SPIFFE ID a node certificate for `node` in `cluster` must carry.
///
/// Fixed, unlike workload IDs: the shape is the contract with node bootstrap
/// and with Vault's cert auth role, whose `allowed_uri_sans` is
/// `spiffe://<td>/cluster/<c>/node/*`.
#[must_use]
pub fn expected_id(trust_domain: &str, cluster: &str, node: &str) -> String {
    format!("spiffe://{trust_domain}/cluster/{cluster}/node/{node}")
}

/// Something wrong with a node certificate that svidlet can see before Vault
/// does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    /// The certificate names another node or cluster. Vault refuses another
    /// cluster; it cannot tell another node in the same cluster apart, so
    /// this is the only place that mismatch is caught.
    WrongIdentity { found: String, expected: String },
    /// No Subject CN. Vault's cert auth method names the entity alias after
    /// it and refuses the login without one.
    NoCommonName,
    /// Past `notAfter`: the renewal sidecar has stopped renewing.
    Expired { seconds_ago: i64 },
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Problem::WrongIdentity { found, expected } => {
                write!(f, "the node certificate is for {found}, not {expected}")
            }
            Problem::NoCommonName => f.write_str(
                "the node certificate has no Subject CN; Vault cert auth will refuse it",
            ),
            Problem::Expired { seconds_ago } => {
                write!(f, "the node certificate expired {seconds_ago}s ago")
            }
        }
    }
}

/// Everything wrong with `facts` as a node certificate for `expected`, at
/// Unix time `now`. Empty means Vault should accept it.
#[must_use]
pub fn check(facts: &CertFacts, expected: &str, now: i64) -> Vec<Problem> {
    let mut problems = Vec::new();
    if facts.spiffe_id.as_str() != expected {
        problems.push(Problem::WrongIdentity {
            found: facts.spiffe_id.to_string(),
            expected: expected.to_string(),
        });
    }
    if facts.common_name.as_deref().is_none_or(str::is_empty) {
        problems.push(Problem::NoCommonName);
    }
    if facts.not_after <= now {
        problems.push(Problem::Expired {
            seconds_ago: now - facts.not_after,
        });
    }
    problems
}

/// Read and parse the node certificate at `path`.
///
/// # Errors
///
/// The I/O error when the file cannot be read — typically because node
/// bootstrap has not written it yet — or an [`svidlet_issue::Error`] when it
/// is not a certificate with a SPIFFE ID.
pub fn read(path: &Path) -> Result<CertFacts, ReadError> {
    let pem = std::fs::read_to_string(path).map_err(ReadError::Missing)?;
    svidlet_issue::inspect(&pem).map_err(ReadError::Invalid)
}

/// Why [`read`] found no usable node certificate.
#[derive(Debug)]
pub enum ReadError {
    /// Not there, or not readable: bootstrap has not finished.
    Missing(std::io::Error),
    /// There, but not a certificate with a SPIFFE ID.
    Invalid(svidlet_issue::Error),
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadError::Missing(e) => write!(f, "cannot read the node certificate: {e}"),
            ReadError::Invalid(e) => write!(f, "the node certificate is unusable: {e}"),
        }
    }
}

impl std::error::Error for ReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ReadError::Missing(e) => Some(e),
            ReadError::Invalid(e) => Some(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use svidlet_issue::SpiffeId;

    const NODE: &str = "spiffe://example.org/cluster/a/node/gpu-17";

    fn facts(id: &str, cn: Option<&str>, not_after: i64) -> CertFacts {
        CertFacts {
            spiffe_id: SpiffeId::parse(id).unwrap(),
            common_name: cn.map(str::to_string),
            not_before: 0,
            not_after,
        }
    }

    #[test]
    fn the_expected_id_matches_the_cert_auth_role_prefix() {
        let id = expected_id("example.org", "a", "gpu-17");
        assert_eq!(id, NODE);
        // What vault-bootstrap.sh pins allowed_uri_sans to.
        assert!(id.starts_with("spiffe://example.org/cluster/a/node/"));
        SpiffeId::parse(&id).expect("a node ID is a valid SPIFFE ID");
    }

    #[test]
    fn a_certificate_bootstrap_would_write_has_no_problems() {
        assert_eq!(check(&facts(NODE, Some("gpu-17"), 1000), NODE, 10), vec![]);
    }

    #[test]
    fn another_nodes_certificate_is_caught_here_because_vault_cannot() {
        let other = "spiffe://example.org/cluster/a/node/gpu-18";
        let problems = check(&facts(other, Some("gpu-18"), 1000), NODE, 10);
        assert_eq!(
            problems,
            vec![Problem::WrongIdentity {
                found: other.into(),
                expected: NODE.into()
            }]
        );
        assert!(problems[0].to_string().contains("gpu-18"));
    }

    #[test]
    fn a_missing_common_name_is_reported_before_vault_refuses_it() {
        for cn in [None, Some("")] {
            assert_eq!(
                check(&facts(NODE, cn, 1000), NODE, 10),
                vec![Problem::NoCommonName]
            );
        }
    }

    #[test]
    fn expiry_is_reported_with_its_age() {
        let problems = check(&facts(NODE, Some("gpu-17"), 100), NODE, 160);
        assert_eq!(problems, vec![Problem::Expired { seconds_ago: 60 }]);
        // Expiry is inclusive: notAfter itself is too late.
        assert_eq!(
            check(&facts(NODE, Some("gpu-17"), 100), NODE, 100),
            vec![Problem::Expired { seconds_ago: 0 }]
        );
    }

    #[test]
    fn reading_distinguishes_not_yet_written_from_unusable() {
        let missing = read(Path::new("/nonexistent/node/node.crt")).unwrap_err();
        assert!(matches!(missing, ReadError::Missing(_)), "{missing}");

        let path = std::env::temp_dir().join(format!("svidlet-node-{}.crt", std::process::id()));
        std::fs::write(&path, "not a certificate").unwrap();
        let invalid = read(&path).unwrap_err();
        assert!(matches!(invalid, ReadError::Invalid(_)), "{invalid}");
        std::fs::remove_file(&path).unwrap();
    }
}
