//! Which SPIFFE IDs may have tokens for which audiences.
//!
//! A grant names an identity prefix and the audiences under it:
//!
//! ```toml
//! [[grant]]
//! prefix = "spiffe://example.org/cluster/prod-a/ns/payments/"
//! audiences = ["api://AzureADTokenExchange"]
//! ```
//!
//! Grants are per identity, not per cluster. A pod chooses its volume's
//! audiences itself, so a per-cluster allowlist would hand every pod in the
//! cluster every audience any of them needed. The relying party still checks
//! `sub`; this makes it the second check rather than the only one.
//!
//! Every prefix must name one cluster — `spiffe://<td>/cluster/<name>/…` with a
//! concrete name — and there is no wildcard syntax at all, so a grant spanning
//! clusters cannot be written. Losing a cluster costs that cluster's grants.

use std::fmt;

use serde::Deserialize;

/// One grant, as written in the configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Grant {
    /// An exact SPIFFE ID, or a prefix ending in `/`.
    pub prefix: String,
    pub audiences: Vec<String>,
}

/// The validated set of grants.
#[derive(Debug, Clone, Default)]
pub struct Grants(Vec<Grant>);

impl Grants {
    /// Validate grants for `trust_domain`.
    ///
    /// # Errors
    ///
    /// [`GrantError`] for a prefix outside the trust domain, not scoped to one
    /// named cluster, containing a `*`, or with no audiences.
    pub fn new(trust_domain: &str, grants: Vec<Grant>) -> Result<Grants, GrantError> {
        let root = format!("spiffe://{trust_domain}/cluster/");
        for grant in &grants {
            let Some(rest) = grant.prefix.strip_prefix(&root) else {
                return Err(GrantError(format!(
                    "{:?} is not under {root}<cluster>/",
                    grant.prefix
                )));
            };
            let cluster = rest.split('/').next().unwrap_or("");
            if cluster.is_empty() || !rest.contains('/') {
                return Err(GrantError(format!(
                    "{:?} does not name one cluster; grants never span clusters",
                    grant.prefix
                )));
            }
            if grant.prefix.contains('*') {
                return Err(GrantError(format!(
                    "{:?} contains '*'; grants are literal prefixes",
                    grant.prefix
                )));
            }
            if grant.audiences.is_empty() || grant.audiences.iter().any(String::is_empty) {
                return Err(GrantError(format!(
                    "{:?} grants no audience, or an empty one",
                    grant.prefix
                )));
            }
        }
        Ok(Grants(grants))
    }

    /// Whether `spiffe_id` may have a token for `audience`.
    ///
    /// A prefix ending in `/` covers every ID below it; any other prefix is
    /// an exact ID. `…/ns/pay` therefore never covers `…/ns/payments/…`.
    #[must_use]
    pub fn allows(&self, spiffe_id: &str, audience: &str) -> bool {
        self.0.iter().any(|g| {
            let covers = if g.prefix.ends_with('/') {
                spiffe_id.starts_with(&g.prefix)
            } else {
                spiffe_id == g.prefix
            };
            covers && g.audiences.iter().any(|a| a == audience)
        })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A grant that could reach further than it should, or nothing at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantError(String);

impl fmt::Display for GrantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid grant: {}", self.0)
    }
}

impl std::error::Error for GrantError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(prefix: &str, audiences: &[&str]) -> Grant {
        Grant {
            prefix: prefix.into(),
            audiences: audiences.iter().map(|a| (*a).to_string()).collect(),
        }
    }

    fn grants(list: Vec<Grant>) -> Result<Grants, GrantError> {
        Grants::new("example.org", list)
    }

    #[test]
    fn a_namespace_prefix_covers_its_identities_and_nothing_beside_them() {
        let g = grants(vec![grant(
            "spiffe://example.org/cluster/a/ns/payments/",
            &["azure"],
        )])
        .unwrap();
        assert!(g.allows("spiffe://example.org/cluster/a/ns/payments/sa/api", "azure"));
        assert!(!g.allows(
            "spiffe://example.org/cluster/a/ns/payments/sa/api",
            "snowflake"
        ));
        assert!(!g.allows(
            "spiffe://example.org/cluster/a/ns/payments-eu/sa/api",
            "azure"
        ));
        assert!(!g.allows("spiffe://example.org/cluster/b/ns/payments/sa/api", "azure"));
    }

    #[test]
    fn a_prefix_without_a_trailing_slash_is_one_exact_identity() {
        let g = grants(vec![grant(
            "spiffe://example.org/cluster/a/ns/p/sa/api",
            &["azure"],
        )])
        .unwrap();
        assert!(g.allows("spiffe://example.org/cluster/a/ns/p/sa/api", "azure"));
        assert!(!g.allows("spiffe://example.org/cluster/a/ns/p/sa/api-admin", "azure"));
    }

    #[test]
    fn grants_that_span_clusters_cannot_be_written() {
        for prefix in [
            "spiffe://example.org/",
            "spiffe://example.org/cluster/",
            "spiffe://example.org/cluster/a",
            "spiffe://example.org/cluster/*/ns/p/",
            "spiffe://example.org/cluster/prod-*/",
            "spiffe://other.org/cluster/a/",
            "spiffe://example.org/ns/p/",
        ] {
            let _ = grants(vec![grant(prefix, &["x"])]).expect_err(prefix);
        }
        grants(vec![grant("spiffe://example.org/cluster/a/", &["x"])]).unwrap();
    }

    #[test]
    fn a_grant_must_grant_something() {
        let _ = grants(vec![grant("spiffe://example.org/cluster/a/", &[])]).unwrap_err();
        let _ = grants(vec![grant("spiffe://example.org/cluster/a/", &[""])]).unwrap_err();
    }

    #[test]
    fn no_grants_allows_nothing() {
        let g = grants(vec![]).unwrap();
        assert!(g.is_empty());
        assert!(!g.allows("spiffe://example.org/cluster/a/ns/p/sa/api", "azure"));
    }
}
