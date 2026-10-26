//! The identity catalog: which identities may hold JWT-SVIDs, for which
//! audiences, and which identities are sensitive.
//!
//! One file per fleet, kept in Git. The broker reads it to enforce rules T3,
//! I8 and I9; CI renders the same file into the Vault SPIFFE roles and the
//! per-cluster broker policies, so Vault enforces it independently of the
//! broker. See docs/DESIGN.md §12.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::time::Duration;

use serde::Deserialize;

use crate::error::{Error, Result};

/// The SPIFFE path every identity in the catalog has, relative to the trust
/// domain. Must agree with the broker's SPIFFE ID template.
pub const DEFAULT_PATH_TEMPLATE: &str = "/cluster/{cluster}/ns/{namespace}/sa/{service_account}";

/// Token lifetime when an identity does not set one.
pub const DEFAULT_TOKEN_TTL: Duration = Duration::from_secs(12 * 3600);
/// The bounds of §6.2 and §7.2: 6 to 12 hours. Shorter tokens shrink the
/// fail-stale margin (a cached token is served only to half-life) below what
/// the 15-minute check-in and a Vault outage need.
const MIN_TOKEN_TTL: Duration = Duration::from_secs(6 * 3600);
const MAX_TOKEN_TTL: Duration = Duration::from_secs(12 * 3600);

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub schema: u32,
    pub trust_domain: String,
    #[serde(default = "default_path_template")]
    pub path_template: String,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub identity: Vec<Identity>,
    #[serde(default)]
    pub sensitive: Sensitive,
}

fn default_path_template() -> String {
    DEFAULT_PATH_TEMPLATE.to_string()
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mode {
    /// I8: deny certificates to identities that have no catalog entry.
    #[serde(default)]
    pub allowlist: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sensitive {
    /// I9: image prefixes a sensitive identity's containers must start with.
    #[serde(default)]
    pub registries: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    /// A cluster name, or `*` for every cluster.
    pub cluster: String,
    pub namespace: String,
    pub service_account: String,
    #[serde(default)]
    pub token_ttl: Option<String>,
    #[serde(default)]
    pub sensitive: bool,
    #[serde(default)]
    pub audiences: Vec<Audience>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Audience {
    /// File name under `jwt/`.
    pub alias: String,
    /// The `aud` claim.
    pub audience: String,
}

impl Identity {
    pub fn token_ttl(&self) -> Duration {
        self.token_ttl
            .as_deref()
            .and_then(parse_duration)
            .unwrap_or(DEFAULT_TOKEN_TTL)
    }

    pub fn audience(&self, aud: &str) -> Option<&Audience> {
        self.audiences.iter().find(|a| a.audience == aud)
    }
}

/// The Vault SPIFFE role for one identity: `<cluster>__<namespace>__<sa>`.
///
/// Kubernetes names cannot contain `__`, so the name splits back
/// unambiguously.
pub fn role_name(cluster: &str, namespace: &str, service_account: &str) -> String {
    format!("{cluster}__{namespace}__{service_account}")
}

impl Catalog {
    pub fn parse(text: &str) -> Result<Catalog> {
        let catalog: Catalog = basic_toml::from_str(text)
            .map_err(|e| Error::Config(format!("catalog is not valid TOML: {e}")))?;
        catalog.validate()?;
        Ok(catalog)
    }

    pub fn load(path: &std::path::Path) -> Result<Catalog> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            Error::Config(format!("cannot read the catalog {}: {e}", path.display()))
        })?;
        Catalog::parse(&text)
    }

    fn validate(&self) -> Result<()> {
        let bad = |m: String| Err(Error::Config(format!("catalog: {m}")));
        if self.schema != 1 {
            return bad(format!("unsupported schema {}", self.schema));
        }
        if self.trust_domain.is_empty() || self.trust_domain.contains('/') {
            return bad(format!(
                "trust_domain {:?} is not a domain",
                self.trust_domain
            ));
        }
        for placeholder in ["{cluster}", "{namespace}", "{service_account}"] {
            if !self.path_template.contains(placeholder) {
                return bad(format!("path_template lacks {placeholder}"));
            }
        }
        if !self.path_template.starts_with('/') {
            return bad("path_template must start with /".into());
        }
        for prefix in &self.sensitive.registries {
            if !prefix.ends_with('/') {
                // "registry.corp.example" would also match
                // "registry.corp.example.attacker.net/…".
                return bad(format!("sensitive registry {prefix:?} must end with /"));
            }
        }

        let mut seen = BTreeSet::new();
        for id in &self.identity {
            let what = format!("{}/{}/{}", id.cluster, id.namespace, id.service_account);
            if id.cluster != "*" && !is_name(&id.cluster) {
                return bad(format!("{what}: cluster is not a valid name"));
            }
            if !is_name(&id.namespace) || !is_name(&id.service_account) {
                return bad(format!(
                    "{what}: namespace and service_account must be Kubernetes names"
                ));
            }
            if !seen.insert((&id.cluster, &id.namespace, &id.service_account)) {
                return bad(format!("{what} appears twice"));
            }
            if let Some(ttl) = &id.token_ttl {
                match parse_duration(ttl) {
                    Some(d) if (MIN_TOKEN_TTL..=MAX_TOKEN_TTL).contains(&d) => {}
                    Some(_) => return bad(format!("{what}: token_ttl {ttl} is outside 6h..12h")),
                    None => return bad(format!("{what}: token_ttl {ttl:?} is not a duration")),
                }
            }
            let mut aliases = BTreeSet::new();
            let mut auds = BTreeSet::new();
            for aud in &id.audiences {
                if aud.alias.is_empty()
                    || aud.alias.len() > 63
                    || !aud
                        .alias
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                {
                    return bad(format!("{what}: alias {:?} must be [a-z0-9-]", aud.alias));
                }
                if aud.audience.is_empty() || aud.audience.contains(',') {
                    // Vault takes allowed_parameters as a list; a comma would
                    // split one approved audience into two.
                    return bad(format!(
                        "{what}: audience {:?} is empty or has a comma",
                        aud.audience
                    ));
                }
                if !aliases.insert(&aud.alias) {
                    return bad(format!("{what}: alias {} appears twice", aud.alias));
                }
                if !auds.insert(&aud.audience) {
                    return bad(format!("{what}: audience {} appears twice", aud.audience));
                }
            }
        }
        Ok(())
    }

    /// The entry for an identity in a cluster. An exact cluster entry wins
    /// over a `*` entry.
    pub fn lookup(
        &self,
        cluster: &str,
        namespace: &str,
        service_account: &str,
    ) -> Option<&Identity> {
        let matches = |c: &str| {
            self.identity.iter().find(|i| {
                i.cluster == c && i.namespace == namespace && i.service_account == service_account
            })
        };
        matches(cluster).or_else(|| matches("*"))
    }

    /// Every identity that applies to `cluster`, exact entries shadowing `*`.
    pub fn for_cluster<'a>(&'a self, cluster: &str) -> Vec<&'a Identity> {
        let mut out: Vec<&Identity> = Vec::new();
        for id in &self.identity {
            if id.cluster != cluster && id.cluster != "*" {
                continue;
            }
            if let Some(found) = self.lookup(cluster, &id.namespace, &id.service_account) {
                if std::ptr::eq(found, id) {
                    out.push(id);
                }
            }
        }
        out.sort_by(|a, b| {
            (&a.namespace, &a.service_account).cmp(&(&b.namespace, &b.service_account))
        });
        out
    }

    /// The SPIFFE path, relative to the trust domain, Vault's role puts in `sub`.
    pub fn subject_path(&self, cluster: &str, namespace: &str, service_account: &str) -> String {
        self.path_template
            .replace("{cluster}", cluster)
            .replace("{namespace}", namespace)
            .replace("{service_account}", service_account)
    }

    /// The full SPIFFE ID for an identity.
    pub fn spiffe_id(&self, cluster: &str, namespace: &str, service_account: &str) -> String {
        format!(
            "spiffe://{}{}",
            self.trust_domain,
            self.subject_path(cluster, namespace, service_account)
        )
    }

    /// §7.3: the Vault policy for one cluster's broker.
    pub fn render_policy(
        &self,
        cluster: &str,
        pki_mount: &str,
        pki_role: &str,
        spiffe_mount: &str,
    ) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "# svidlet-broker-{cluster} — generated from the catalog; do not edit"
        );
        let _ = writeln!(
            out,
            "path \"{}/sign/{pki_role}\" {{ capabilities = [\"update\"] }}",
            pki_mount.trim_matches('/')
        );
        for id in self.for_cluster(cluster) {
            if id.audiences.is_empty() {
                continue;
            }
            let auds: Vec<String> = id
                .audiences
                .iter()
                .map(|a| format!("{:?}", a.audience))
                .collect();
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "path \"{}/role/{}/mintjwt\" {{",
                spiffe_mount.trim_matches('/'),
                role_name(cluster, &id.namespace, &id.service_account)
            );
            let _ = writeln!(out, "  capabilities       = [\"update\"]");
            let _ = writeln!(
                out,
                "  allowed_parameters = {{ \"audience\" = [{}] }}",
                auds.join(", ")
            );
            let _ = writeln!(out, "}}");
        }
        out
    }

    /// §7.2: the `vault write` commands that create one cluster's SPIFFE roles.
    pub fn render_roles(&self, cluster: &str, spiffe_mount: &str) -> String {
        let mut out = String::new();
        for id in self.for_cluster(cluster) {
            if id.audiences.is_empty() {
                continue;
            }
            let template = serde_json::json!({
                "sub": self.subject_path(cluster, &id.namespace, &id.service_account)
            });
            let _ = writeln!(
                out,
                "vault write {}/role/{} template='{}' ttl={}s use_jti_claim=true",
                spiffe_mount.trim_matches('/'),
                role_name(cluster, &id.namespace, &id.service_account),
                template,
                id.token_ttl().as_secs()
            );
        }
        out
    }
}

/// A Kubernetes DNS label: lowercase alphanumerics and `-`, at most 63, and in
/// particular never `_`, which keeps `__` free as the role-name separator.
fn is_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
        && !s.starts_with(['-', '.'])
        && !s.ends_with(['-', '.'])
}

/// `30s`, `10m`, `12h`, `3d` or bare seconds.
pub fn parse_duration(text: &str) -> Option<Duration> {
    let text = text.trim();
    let (number, unit) = match text.find(|c: char| !c.is_ascii_digit()) {
        Some(i) => text.split_at(i),
        None => (text, "s"),
    };
    let n: u64 = number.parse().ok()?;
    let secs = match unit {
        "s" => n,
        "m" => n.checked_mul(60)?,
        "h" => n.checked_mul(3600)?,
        "d" => n.checked_mul(86_400)?,
        _ => return None,
    };
    Some(Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
schema = 1
trust_domain = "corp.internal"

[mode]
allowlist = true

[sensitive]
registries = ["registry.corp.example/"]

[[identity]]
cluster = "gpu-a"
namespace = "payments"
service_account = "api"
token_ttl = "6h"
sensitive = true
audiences = [
  { alias = "aws", audience = "sts.amazonaws.com" },
  { alias = "vault", audience = "vault" },
]

[[identity]]
cluster = "*"
namespace = "payments"
service_account = "api"
audiences = [{ alias = "vault", audience = "vault" }]

[[identity]]
cluster = "*"
namespace = "batch"
service_account = "runner"
"#;

    #[test]
    fn a_good_catalog_parses() {
        let c = Catalog::parse(GOOD).unwrap();
        assert!(c.mode.allowlist);
        assert_eq!(c.identity.len(), 3);
        assert_eq!(c.path_template, DEFAULT_PATH_TEMPLATE);
        let api = c.lookup("gpu-a", "payments", "api").unwrap();
        assert_eq!(api.token_ttl(), Duration::from_secs(6 * 3600));
        assert_eq!(api.audience("vault").unwrap().alias, "vault");
        assert!(api.audience("other").is_none());
    }

    #[test]
    fn an_exact_cluster_entry_shadows_the_wildcard() {
        let c = Catalog::parse(GOOD).unwrap();
        assert_eq!(
            c.lookup("gpu-a", "payments", "api").unwrap().cluster,
            "gpu-a"
        );
        assert_eq!(c.lookup("gpu-b", "payments", "api").unwrap().cluster, "*");
        assert!(c.lookup("gpu-b", "payments", "web").is_none());
        let names: Vec<_> = c
            .for_cluster("gpu-a")
            .iter()
            .map(|i| (i.cluster.as_str(), i.namespace.as_str()))
            .collect();
        assert_eq!(names, vec![("*", "batch"), ("gpu-a", "payments")]);
        assert_eq!(
            c.lookup("gpu-b", "batch", "runner").unwrap().token_ttl(),
            DEFAULT_TOKEN_TTL
        );
    }

    #[test]
    fn role_names_and_ids_follow_the_identity() {
        let c = Catalog::parse(GOOD).unwrap();
        assert_eq!(
            role_name("gpu-a", "payments", "api"),
            "gpu-a__payments__api"
        );
        assert_eq!(
            c.spiffe_id("gpu-a", "payments", "api"),
            "spiffe://corp.internal/cluster/gpu-a/ns/payments/sa/api"
        );
    }

    #[test]
    fn the_policy_grants_exactly_the_clusters_roles_and_audiences() {
        let c = Catalog::parse(GOOD).unwrap();
        let hcl = c.render_policy("gpu-a", "pki_int", "spiffe-gpu-a", "/spiffe/");
        assert!(hcl.contains(r#"path "pki_int/sign/spiffe-gpu-a""#));
        assert!(hcl.contains(r#"path "spiffe/role/gpu-a__payments__api/mintjwt""#));
        assert!(hcl.contains(r#"{ "audience" = ["sts.amazonaws.com", "vault"] }"#));
        // No audiences, no mint grant.
        assert!(!hcl.contains("batch__runner"));
        // Nothing for another cluster, and nothing broader than one role.
        assert!(!hcl.contains("gpu-b"));
        assert!(!hcl.contains('*'));

        let roles = c.render_roles("gpu-b", "spiffe");
        assert!(roles.contains("spiffe/role/gpu-b__payments__api"));
        assert!(roles.contains(r#"{"sub":"/cluster/gpu-b/ns/payments/sa/api"}"#));
        assert!(roles.contains("ttl=43200s"));
    }

    #[test]
    fn invalid_catalogs_are_refused() {
        let base =
            |identity: &str| format!("schema = 1\ntrust_domain = \"td\"\n[[identity]]\n{identity}");
        for bad in [
            "schema = 2\ntrust_domain = \"td\"".to_string(),
            "schema = 1\ntrust_domain = \"a/b\"".to_string(),
            "schema = 1\ntrust_domain = \"td\"\npath_template = \"/ns/{namespace}\"".to_string(),
            "schema = 1\ntrust_domain = \"td\"\n[sensitive]\nregistries = [\"registry.corp\"]".to_string(),
            "schema = 1\ntrust_domain = \"td\"\nunknown = 1".to_string(),
            base("cluster = \"a\"\nnamespace = \"Payments\"\nservice_account = \"api\""),
            base("cluster = \"a\"\nnamespace = \"pay__x\"\nservice_account = \"api\""),
            base("cluster = \"a\"\nnamespace = \"p\"\nservice_account = \"s\"\ntoken_ttl = \"24h\""),
            base("cluster = \"a\"\nnamespace = \"p\"\nservice_account = \"s\"\ntoken_ttl = \"1h\""),
            base("cluster = \"a\"\nnamespace = \"p\"\nservice_account = \"s\"\ntoken_ttl = \"soon\""),
            base("cluster = \"a\"\nnamespace = \"p\"\nservice_account = \"s\"\naudiences = [{ alias = \"A\", audience = \"x\" }]"),
            base("cluster = \"a\"\nnamespace = \"p\"\nservice_account = \"s\"\naudiences = [{ alias = \"a\", audience = \"x,y\" }]"),
            base("cluster = \"a\"\nnamespace = \"p\"\nservice_account = \"s\"\naudiences = [{ alias = \"a\", audience = \"x\" }, { alias = \"a\", audience = \"y\" }]"),
            base("cluster = \"a\"\nnamespace = \"p\"\nservice_account = \"s\"\naudiences = [{ alias = \"a\", audience = \"x\" }, { alias = \"b\", audience = \"x\" }]"),
            format!(
                "{}\n[[identity]]\ncluster = \"a\"\nnamespace = \"p\"\nservice_account = \"s\"",
                base("cluster = \"a\"\nnamespace = \"p\"\nservice_account = \"s\"")
            ),
        ] {
            assert!(Catalog::parse(&bad).is_err(), "accepted:\n{bad}");
        }
    }

    #[test]
    fn durations_parse_in_every_documented_unit() {
        assert_eq!(parse_duration("30"), Some(Duration::from_secs(30)));
        assert_eq!(parse_duration("30s"), Some(Duration::from_secs(30)));
        assert_eq!(parse_duration("10m"), Some(Duration::from_secs(600)));
        assert_eq!(parse_duration("12h"), Some(Duration::from_secs(43_200)));
        assert_eq!(parse_duration("2d"), Some(Duration::from_secs(172_800)));
        assert_eq!(parse_duration("1w"), None);
        assert_eq!(parse_duration("h"), None);
        assert_eq!(parse_duration(""), None);
    }
}
