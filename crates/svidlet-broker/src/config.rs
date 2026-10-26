//! Broker configuration. Everything is an environment variable, as for the
//! node, so one image serves every cluster and only a ConfigMap differs.

use std::path::PathBuf;
use std::time::Duration;

use svidlet_issue::catalog::parse_duration;
use svidlet_issue::{IdPolicy, IdTemplate};

#[derive(Debug, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

type Result<T> = std::result::Result<T, ConfigError>;

#[derive(Debug, Clone)]
pub struct Config {
    /// I2: the cluster is configuration, never request data.
    pub cluster: String,
    pub trust_domain: String,
    pub spiffe_id_template: String,
    pub spiffe_id_pattern: Option<String>,

    /// Certificate port (node token + pod token).
    pub sign_addr: String,
    /// Token port (mTLS with the pod's SVID).
    pub token_addr: String,
    /// Plain-HTTP metrics and health; empty disables it.
    pub metrics_addr: String,
    /// The broker's own serving certificate and key, re-read periodically.
    pub tls_cert_path: PathBuf,
    pub tls_key_path: PathBuf,
    /// T1: the trust bundle a caller's certificate must chain to.
    pub client_ca_path: PathBuf,
    /// The bundle served at `GET /v1/bundle` and returned with each
    /// certificate. Defaults to the client CA file.
    pub bundle_path: PathBuf,

    /// The identity catalog (§12).
    pub catalog_path: PathBuf,

    /// Audience every token presented to the broker must carry.
    pub audience: String,
    /// `system:serviceaccount:<ns>:<name>` of `svidlet-node`.
    pub node_namespace: String,
    pub node_service_account: String,
    /// The DaemonSet that owns `svidlet-node` pods.
    pub node_daemonset: String,
    /// I8: namespaces that never receive an identity.
    pub denied_namespaces: Vec<String>,

    /// I11: the TTL the broker requests, clamped to `cert_max_ttl`.
    pub cert_ttl: Duration,
    pub cert_max_ttl: Duration,

    /// I10: certificates per node per minute, and distinct identities per
    /// node per hour.
    pub node_rate_per_minute: u32,
    pub node_identities_per_hour: u32,
    /// T7: mints per identity per minute.
    pub mint_rate_per_minute: u32,

    pub kube: KubeSettings,
    pub vault: VaultSettings,

    /// T5/T6: where the public JWKS is read from. `None` reads Vault's own.
    pub jwks_url: Option<String>,
    pub jwks_refresh: Duration,
}

#[derive(Debug, Clone)]
pub struct KubeSettings {
    pub api_url: String,
    pub ca_cert_path: PathBuf,
    pub token_path: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct VaultSettings {
    pub address: String,
    pub namespace: Option<String>,
    pub ca_cert_path: Option<PathBuf>,
    pub timeout: Duration,
    pub pki_mount: String,
    pub pki_role: String,
    pub spiffe_mount: String,
    pub auth: VaultAuth,
}

/// §7.4 tiers. B3 (TPM certificate auth) is future work.
#[derive(Debug, Clone)]
pub enum VaultAuth {
    /// B1: JWT auth against this cluster's signing keys.
    Jwt {
        mount: String,
        role: String,
        token_path: PathBuf,
    },
    /// B2: AppRole with a mounted secret ID.
    AppRole {
        mount: String,
        role_id: String,
        secret_id_path: PathBuf,
    },
    /// Development only.
    Token { path: PathBuf },
}

impl VaultAuth {
    pub fn method(&self) -> &'static str {
        match self {
            VaultAuth::Jwt { .. } => "jwt",
            VaultAuth::AppRole { .. } => "approle",
            VaultAuth::Token { .. } => "token",
        }
    }
}

struct Env<'a>(&'a dyn Fn(&str) -> Option<String>);

impl Env<'_> {
    fn opt(&self, key: &str) -> Option<String> {
        (self.0)(key)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    }
    fn or(&self, key: &str, default: &str) -> String {
        self.opt(key).unwrap_or_else(|| default.to_string())
    }
    fn req(&self, key: &str) -> Result<String> {
        self.opt(key)
            .ok_or_else(|| ConfigError(format!("{key} is required")))
    }
    fn duration(&self, key: &str, default: Duration) -> Result<Duration> {
        match self.opt(key) {
            None => Ok(default),
            Some(v) => parse_duration(&v)
                .ok_or_else(|| ConfigError(format!("{key} must be a duration, got {v:?}"))),
        }
    }
    fn count(&self, key: &str, default: u32) -> Result<u32> {
        match self.opt(key) {
            None => Ok(default),
            Some(v) => v
                .parse()
                .map_err(|_| ConfigError(format!("{key} must be a whole number, got {v:?}"))),
        }
    }
}

impl Config {
    pub fn from_env() -> Result<Config> {
        Config::from_source(&|k| std::env::var(k).ok())
    }

    pub fn from_source(get: &dyn Fn(&str) -> Option<String>) -> Result<Config> {
        let env = Env(get);
        let cluster = env.req("SVIDLET_CLUSTER")?;
        let client_ca_path =
            PathBuf::from(env.or("SVIDLET_BROKER_CLIENT_CA", "/etc/svidlet/trust/ca.crt"));

        let kube_host = env.opt("KUBERNETES_SERVICE_HOST");
        let kube_port = env.or("KUBERNETES_SERVICE_PORT", "443");
        let api_url = env
            .opt("SVIDLET_KUBE_API")
            .unwrap_or_else(|| match &kube_host {
                // An IPv6 service host needs brackets in a URL.
                Some(h) if h.contains(':') => format!("https://[{h}]:{kube_port}"),
                Some(h) => format!("https://{h}:{kube_port}"),
                None => "https://kubernetes.default.svc".into(),
            });
        let sa_dir = "/var/run/secrets/kubernetes.io/serviceaccount";

        let auth = match env.or("SVIDLET_BROKER_VAULT_AUTH", "jwt").as_str() {
            "jwt" => VaultAuth::Jwt {
                mount: env.or("SVIDLET_BROKER_VAULT_JWT_MOUNT", &format!("k8s-{cluster}")),
                role: env.or("SVIDLET_BROKER_VAULT_JWT_ROLE", "svidlet-broker"),
                token_path: PathBuf::from(env.or(
                    "SVIDLET_BROKER_VAULT_TOKEN_FILE",
                    "/var/run/secrets/svidlet/vault/token",
                )),
            },
            "approle" => VaultAuth::AppRole {
                mount: env.or("SVIDLET_BROKER_APPROLE_MOUNT", "approle"),
                role_id: env.req("SVIDLET_BROKER_ROLE_ID")?,
                secret_id_path: PathBuf::from(env.or(
                    "SVIDLET_BROKER_SECRET_ID_FILE",
                    "/etc/svidlet/vault/secret-id",
                )),
            },
            "token" => VaultAuth::Token {
                path: PathBuf::from(env.or("VAULT_TOKEN_FILE", "/etc/svidlet/vault/token")),
            },
            other => {
                return Err(ConfigError(format!(
                    "SVIDLET_BROKER_VAULT_AUTH must be jwt, approle or token; got {other:?}"
                )))
            }
        };

        let cert_ttl = env.duration("SVIDLET_CERT_TTL", Duration::from_secs(48 * 3600))?;
        let cert_max_ttl = env.duration("SVIDLET_CERT_MAX_TTL", Duration::from_secs(48 * 3600))?;
        if cert_ttl.is_zero() || cert_max_ttl.is_zero() {
            return Err(ConfigError("certificate TTLs must be positive".into()));
        }

        let cfg = Config {
            trust_domain: env.req("SVIDLET_TRUST_DOMAIN")?,
            spiffe_id_template: env.or("SVIDLET_SPIFFE_ID_TEMPLATE", IdTemplate::DEFAULT),
            spiffe_id_pattern: env.opt("SVIDLET_SPIFFE_ID_PATTERN"),
            sign_addr: env.or("SVIDLET_BROKER_SIGN_ADDR", "0.0.0.0:8443"),
            token_addr: env.or("SVIDLET_BROKER_TOKEN_ADDR", "0.0.0.0:8444"),
            metrics_addr: env.or("SVIDLET_BROKER_METRICS_ADDR", "0.0.0.0:9466"),
            tls_cert_path: PathBuf::from(
                env.or("SVIDLET_BROKER_TLS_CERT", "/etc/svidlet/tls/tls.crt"),
            ),
            tls_key_path: PathBuf::from(
                env.or("SVIDLET_BROKER_TLS_KEY", "/etc/svidlet/tls/tls.key"),
            ),
            bundle_path: env
                .opt("SVIDLET_BROKER_BUNDLE")
                .map(PathBuf::from)
                .unwrap_or_else(|| client_ca_path.clone()),
            client_ca_path,
            catalog_path: PathBuf::from(
                env.or("SVIDLET_CATALOG", "/etc/svidlet/catalog/catalog.toml"),
            ),
            audience: env.or("SVIDLET_BROKER_AUDIENCE", "svidlet-broker"),
            node_namespace: env.or("SVIDLET_NODE_NAMESPACE", "svidlet-system"),
            node_service_account: env.or("SVIDLET_NODE_SERVICE_ACCOUNT", "svidlet-node"),
            node_daemonset: env.or("SVIDLET_NODE_DAEMONSET", "svidlet-node"),
            denied_namespaces: env
                .or(
                    "SVIDLET_DENIED_NAMESPACES",
                    "kube-system,kube-public,kube-node-lease,svidlet-system",
                )
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            cert_ttl,
            cert_max_ttl,
            node_rate_per_minute: env.count("SVIDLET_NODE_RATE_PER_MINUTE", 120)?,
            node_identities_per_hour: env.count("SVIDLET_NODE_IDENTITIES_PER_HOUR", 500)?,
            mint_rate_per_minute: env.count("SVIDLET_MINT_RATE_PER_MINUTE", 60)?,
            kube: KubeSettings {
                api_url,
                ca_cert_path: PathBuf::from(
                    env.or("SVIDLET_KUBE_CACERT", &format!("{sa_dir}/ca.crt")),
                ),
                token_path: PathBuf::from(
                    env.or("SVIDLET_KUBE_TOKEN_FILE", &format!("{sa_dir}/token")),
                ),
                timeout: env.duration("SVIDLET_KUBE_TIMEOUT", Duration::from_secs(5))?,
            },
            vault: VaultSettings {
                address: env.req("VAULT_ADDR")?,
                namespace: env.opt("VAULT_NAMESPACE"),
                ca_cert_path: env.opt("VAULT_CACERT").map(PathBuf::from),
                timeout: env.duration("SVIDLET_VAULT_TIMEOUT", Duration::from_secs(10))?,
                pki_mount: env.or("SVIDLET_PKI_MOUNT", "pki_int"),
                pki_role: env.or("SVIDLET_PKI_ROLE", &format!("spiffe-{cluster}")),
                spiffe_mount: env.or("SVIDLET_SPIFFE_MOUNT", "spiffe"),
                auth,
            },
            jwks_url: env.opt("SVIDLET_JWKS_URL"),
            jwks_refresh: env.duration("SVIDLET_JWKS_REFRESH", Duration::from_secs(60))?,
            cluster,
        };
        cfg.id_policy()?;
        Ok(cfg)
    }

    pub fn id_policy(&self) -> Result<IdPolicy> {
        IdPolicy::new(&self.spiffe_id_template, self.spiffe_id_pattern.as_deref())
            .map_err(|e| ConfigError(e.to_string()))
    }

    /// I11: the TTL actually requested.
    pub fn effective_ttl(&self) -> Duration {
        self.cert_ttl.min(self.cert_max_ttl)
    }

    pub fn node_username(&self) -> String {
        format!(
            "system:serviceaccount:{}:{}",
            self.node_namespace, self.node_service_account
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn load(pairs: &[(&str, &str)]) -> Result<Config> {
        let mut vars: HashMap<String, String> = HashMap::from([
            ("SVIDLET_CLUSTER".into(), "gpu-a".into()),
            ("SVIDLET_TRUST_DOMAIN".into(), "corp.internal".into()),
            ("VAULT_ADDR".into(), "https://vault:8200".into()),
        ]);
        for (k, v) in pairs {
            vars.insert(k.to_string(), v.to_string());
        }
        Config::from_source(&|k| vars.get(k).cloned())
    }

    #[test]
    fn defaults_follow_the_design() {
        let c = load(&[]).unwrap();
        assert_eq!(c.vault.pki_role, "spiffe-gpu-a");
        assert_eq!(c.vault.pki_mount, "pki_int");
        assert_eq!(c.vault.auth.method(), "jwt");
        assert!(matches!(&c.vault.auth, VaultAuth::Jwt { mount, .. } if mount == "k8s-gpu-a"));
        assert_eq!(c.effective_ttl(), Duration::from_secs(48 * 3600));
        assert_eq!(
            c.node_username(),
            "system:serviceaccount:svidlet-system:svidlet-node"
        );
        assert!(c.denied_namespaces.contains(&"kube-system".to_string()));
        assert_eq!(c.bundle_path, c.client_ca_path);
    }

    #[test]
    fn the_kubernetes_url_brackets_an_ipv6_host() {
        let c = load(&[
            ("KUBERNETES_SERVICE_HOST", "fd00::1"),
            ("KUBERNETES_SERVICE_PORT", "6443"),
        ])
        .unwrap();
        assert_eq!(c.kube.api_url, "https://[fd00::1]:6443");
    }

    #[test]
    fn bad_settings_stop_the_broker_at_start_up() {
        assert!(load(&[("SVIDLET_BROKER_VAULT_AUTH", "oidc")]).is_err());
        assert!(
            load(&[("SVIDLET_BROKER_VAULT_AUTH", "approle")]).is_err(),
            "role id required"
        );
        assert!(load(&[("SVIDLET_CERT_TTL", "soon")]).is_err());
        assert!(load(&[("SVIDLET_CERT_TTL", "0")]).is_err());
        assert!(load(&[("SVIDLET_NODE_RATE_PER_MINUTE", "-1")]).is_err());
        assert!(load(&[("SVIDLET_SPIFFE_ID_TEMPLATE", "spiffe://{nope}")]).is_err());
        let c = load(&[("SVIDLET_CERT_TTL", "72h"), ("SVIDLET_CERT_MAX_TTL", "24h")]).unwrap();
        assert_eq!(c.effective_ttl(), Duration::from_secs(24 * 3600));
    }
}
