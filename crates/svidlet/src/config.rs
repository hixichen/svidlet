//! Configuration, entirely from the environment.
//!
//! Everything that varies between clusters is an environment variable, so one
//! image and one manifest differ only by a ConfigMap.

use std::path::PathBuf;
use std::time::Duration;

use svidlet_issue::{IdPolicy, IdTemplate, KubernetesAuth};

use crate::log::Level;

/// Volume-context keys the kubelet supplies when the CSIDriver sets
/// `podInfoOnMount: true`. These — not pod labels or annotations — are the
/// source of the workload's identity.
pub mod volume_context {
    pub const POD_NAME: &str = "csi.storage.k8s.io/pod.name";
    pub const POD_NAMESPACE: &str = "csi.storage.k8s.io/pod.namespace";
    pub const POD_UID: &str = "csi.storage.k8s.io/pod.uid";
    pub const SERVICE_ACCOUNT: &str = "csi.storage.k8s.io/serviceAccount.name";
    pub const EPHEMERAL: &str = "csi.storage.k8s.io/ephemeral";
}

pub const CERT_FILE: &str = "tls.crt";
pub const KEY_FILE: &str = "tls.key";
pub const CA_FILE: &str = "ca.crt";
/// Holds the upstream revision of the published policy bundle, so an
/// application can detect a change without walking the policy directory.
pub const REVISION_FILE: &str = "policy.revision";

#[derive(Debug, Clone)]
pub struct Config {
    pub driver_name: String,
    pub node_name: String,
    pub trust_domain: String,
    pub cluster: String,

    /// CSI socket, as this process sees it.
    pub csi_socket: PathBuf,
    /// Registration socket in the kubelet's plugins_registry directory.
    pub registration_socket: PathBuf,
    /// CSI socket path as the *kubelet* sees it, reported by GetInfo. Differs
    /// from `csi_socket` only if the hostPath mount points somewhere else.
    pub advertised_endpoint: String,
    /// Kubelet root, used to rebuild state after a restart.
    pub kubelet_root: PathBuf,

    /// Shape of the SPIFFE IDs this node issues.
    pub spiffe_id_template: String,
    /// Optional regex every issued ID must match, on top of the template.
    pub spiffe_id_pattern: Option<String>,

    pub vault: VaultSettings,
    pub policy: PolicySettings,

    /// Requested certificate lifetime.
    pub cert_ttl: Duration,
    /// Renew at a uniformly random point in this fraction range of the
    /// certificate's lifetime.
    pub renew_fraction: (f64, f64),
    pub renew_check_interval: Duration,
    /// Renewals already due when the plugin starts are spread over this window,
    /// so a fleet-wide upgrade does not become a fleet-wide signing storm.
    pub startup_spread: Duration,
    pub ca_refresh_interval: Duration,

    /// tmpfs `size=` option for each published volume.
    pub tmpfs_size: String,
    /// Mode for `tls.key`. Pods that read it as non-root need a matching
    /// `fsGroup` (the CSIDriver sets `fsGroupPolicy: File`).
    pub key_mode: u32,
    pub cert_mode: u32,

    /// `host:port` for the Prometheus endpoint; empty disables it.
    pub metrics_addr: String,
    pub log_level: Level,
}

/// Where authorization policy comes from, and how strictly it is required.
#[derive(Debug, Clone)]
pub struct PolicySettings {
    /// Master switch, from `SVIDLET_POLICY_ENABLED`.
    ///
    /// Separate from `endpoint` so an endpoint can stay configured while the
    /// feature is switched off — which is what you want when running against a
    /// local Vault with no policy backend to hand, or when bisecting whether
    /// the policy stream is involved in a problem.
    pub enabled: bool,
    /// gRPC endpoint of the policy backend. `None` also disables the feature:
    /// there is nothing to connect to.
    pub endpoint: Option<String>,
    pub ca_cert_path: Option<PathBuf>,
    /// File holding a bearer token presented to the policy backend.
    pub token_path: Option<PathBuf>,
    /// Refuse to publish a volume until policy has arrived.
    ///
    /// Off by default: certificate issuance is the plugin's primary job, and
    /// putting a second network dependency in the pod-start critical path
    /// trades a real outage risk for a theoretical one. Operators who would
    /// rather a pod fail to start than start unpoliced turn this on.
    pub required: bool,
    /// How long publishing waits for the first bundle.
    pub initial_timeout: Duration,
    /// Directory inside the volume that holds policy documents.
    pub directory: String,
    /// First reconnection delay; doubles up to a minute.
    pub reconnect_backoff: Duration,
    /// Pull-based distribution from an OCI registry. `None` disables it.
    pub bundle: Option<BundleSettings>,
}

/// Signed, content-addressed policy bundles pulled from an OCI registry with a
/// staged ring rollout. See docs/POLICY.md.
#[derive(Debug, Clone)]
pub struct BundleSettings {
    /// `registry/repository:tag` of the signed rollout manifest.
    pub rollout_ref: Option<String>,
    /// Repository bundles are pulled from by digest. Defaults to the rollout
    /// manifest's own repository.
    pub bundle_repo: Option<String>,
    /// The fleet's trusted Ed25519 public key, inline.
    pub public_key: Option<String>,
    /// Or the same key in a file.
    pub public_key_path: Option<PathBuf>,
    pub ca_cert_path: Option<PathBuf>,
    /// Bearer token for registries that want one; re-read on every request.
    pub token_path: Option<PathBuf>,
    pub timeout: Duration,
    pub poll_interval: Duration,
    /// Polls land at `poll_interval ± poll_jitter`, so a fleet does not hit the
    /// registry in lockstep.
    pub poll_jitter: Duration,
    /// Node-local cache: `versions/`, `current`, `state.json`.
    pub directory: PathBuf,
    /// How many superseded versions stay unpacked for a network-free rollback.
    pub keep_versions: usize,
    /// Refuse a bundle larger than this, unpacked.
    pub max_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct VaultSettings {
    pub address: String,
    pub namespace: Option<String>,
    pub ca_cert_path: Option<PathBuf>,
    pub timeout: Duration,
    pub pki_mount: String,
    pub pki_role: String,
    pub auth: AuthSettings,
}

/// How this node proves who it is to Vault.
///
/// AppRole is the default because it is the only one that works everywhere,
/// including bare metal — but it is a shared bearer secret, and the other two
/// are stronger where the environment supports them. See the trust discussion
/// in docs/DESIGN.md.
#[derive(Debug, Clone)]
pub enum AuthSettings {
    AppRole {
        mount: String,
        role_id: String,
        secret_id_path: PathBuf,
    },
    Kubernetes {
        mount: String,
        role: String,
        token_path: PathBuf,
    },
    Token {
        path: PathBuf,
    },
}

impl AuthSettings {
    pub fn method(&self) -> &'static str {
        match self {
            AuthSettings::AppRole { .. } => "approle",
            AuthSettings::Kubernetes { .. } => "kubernetes",
            AuthSettings::Token { .. } => "token",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "configuration error: {}", self.0)
    }
}

impl std::error::Error for ConfigError {}

type Result<T> = std::result::Result<T, ConfigError>;

impl Config {
    pub fn from_env() -> Result<Config> {
        Config::from_source(&|key| std::env::var(key).ok())
    }

    /// Build a configuration from an arbitrary variable lookup, so the parsing
    /// rules can be tested without mutating the process environment.
    pub fn from_source(get: &dyn Fn(&str) -> Option<String>) -> Result<Config> {
        let env = Env(get);

        let driver_name = env
            .opt("SVIDLET_DRIVER_NAME")
            .unwrap_or_else(|| "csi.svidlet.io".into());
        let cluster = env.req("SVIDLET_CLUSTER")?;

        let csi_socket = PathBuf::from(
            env.opt("SVIDLET_CSI_SOCKET")
                .unwrap_or_else(|| format!("/var/lib/kubelet/plugins/{driver_name}/csi.sock")),
        );
        let registration_socket =
            PathBuf::from(env.opt("SVIDLET_REGISTRATION_SOCKET").unwrap_or_else(|| {
                format!("/var/lib/kubelet/plugins_registry/{driver_name}-reg.sock")
            }));
        let advertised_endpoint = env
            .opt("SVIDLET_ADVERTISED_ENDPOINT")
            .unwrap_or_else(|| csi_socket.display().to_string());

        let renew_min = env.float("SVIDLET_RENEW_MIN_FRACTION", 0.5)?;
        let renew_max = env.float("SVIDLET_RENEW_MAX_FRACTION", 0.7)?;
        if !(0.0 < renew_min && renew_min <= renew_max && renew_max < 1.0) {
            return Err(ConfigError(format!(
                "renew fractions must satisfy 0 < min <= max < 1, got {renew_min} and {renew_max}"
            )));
        }

        let spiffe_id_template = env
            .opt("SVIDLET_SPIFFE_ID_TEMPLATE")
            .unwrap_or_else(|| IdTemplate::DEFAULT.to_string());
        let spiffe_id_pattern = env.opt("SVIDLET_SPIFFE_ID_PATTERN");

        let cfg = Config {
            driver_name,
            node_name: env.req("NODE_NAME")?,
            trust_domain: env.req("SVIDLET_TRUST_DOMAIN")?,
            cluster: cluster.clone(),
            csi_socket,
            registration_socket,
            advertised_endpoint,
            kubelet_root: PathBuf::from(
                env.opt("SVIDLET_KUBELET_ROOT")
                    .unwrap_or_else(|| "/var/lib/kubelet".into()),
            ),
            spiffe_id_template,
            spiffe_id_pattern,
            vault: vault_settings(&env, &cluster)?,
            policy: PolicySettings {
                enabled: env.bool("SVIDLET_POLICY_ENABLED", true)?,
                endpoint: env.opt("SVIDLET_POLICY_ENDPOINT"),
                ca_cert_path: env.opt("SVIDLET_POLICY_CACERT").map(PathBuf::from),
                token_path: env.opt("SVIDLET_POLICY_TOKEN_FILE").map(PathBuf::from),
                required: env.bool("SVIDLET_POLICY_REQUIRED", false)?,
                initial_timeout: env
                    .duration("SVIDLET_POLICY_INITIAL_TIMEOUT", Duration::from_secs(10))?,
                directory: env
                    .opt("SVIDLET_POLICY_DIR")
                    .unwrap_or_else(|| "policy".into()),
                reconnect_backoff: env
                    .duration("SVIDLET_POLICY_RECONNECT_BACKOFF", Duration::from_secs(1))?,
                bundle: bundle_settings(&env)?,
            },
            cert_ttl: env.duration("SVIDLET_CERT_TTL", Duration::from_secs(86_400))?,
            renew_fraction: (renew_min, renew_max),
            renew_check_interval: env
                .duration("SVIDLET_RENEW_CHECK_INTERVAL", Duration::from_secs(30))?,
            startup_spread: env.duration("SVIDLET_STARTUP_SPREAD", Duration::from_secs(300))?,
            ca_refresh_interval: env
                .duration("SVIDLET_CA_REFRESH_INTERVAL", Duration::from_secs(3600))?,
            tmpfs_size: env.opt("SVIDLET_TMPFS_SIZE").unwrap_or_else(|| "1m".into()),
            key_mode: env.mode("SVIDLET_KEY_MODE", 0o640)?,
            cert_mode: env.mode("SVIDLET_CERT_MODE", 0o644)?,
            metrics_addr: env
                .opt("SVIDLET_METRICS_ADDR")
                .unwrap_or_else(|| "0.0.0.0:9464".into()),
            log_level: match env.opt("SVIDLET_LOG_LEVEL") {
                None => Level::Info,
                Some(v) => Level::parse(&v).ok_or_else(|| {
                    ConfigError(format!(
                        "SVIDLET_LOG_LEVEL must be one of error, warn, info, debug; got {v:?}"
                    ))
                })?,
            },
        };

        // Compile the identity policy here so a bad template or pattern stops
        // the process at start-up rather than failing the first pod that lands.
        cfg.id_policy()?;
        Ok(cfg)
    }

    /// Compile the SPIFFE ID template and the operator's pattern.
    pub fn id_policy(&self) -> Result<IdPolicy> {
        IdPolicy::new(&self.spiffe_id_template, self.spiffe_id_pattern.as_deref())
            .map_err(|e| ConfigError(e.to_string()))
    }
}

/// `None` when no rollout reference is configured, which is how the pull-based
/// source is switched off.
fn bundle_settings(env: &Env<'_>) -> Result<Option<BundleSettings>> {
    let Some(rollout_ref) = env.opt("SVIDLET_BUNDLE_ROLLOUT_REF") else {
        return Ok(None);
    };

    let public_key = env.opt("SVIDLET_BUNDLE_PUBLIC_KEY");
    let public_key_path = env.opt("SVIDLET_BUNDLE_PUBLIC_KEY_FILE").map(PathBuf::from);
    if public_key.is_none() && public_key_path.is_none() {
        // Refusing to start is the point: a node with no key could not verify
        // anything, and a bundle svidlet cannot verify must never be published.
        return Err(ConfigError(
            "SVIDLET_BUNDLE_ROLLOUT_REF is set, so a trusted key is required:              set SVIDLET_BUNDLE_PUBLIC_KEY or SVIDLET_BUNDLE_PUBLIC_KEY_FILE"
                .into(),
        ));
    }

    Ok(Some(BundleSettings {
        rollout_ref: Some(rollout_ref),
        bundle_repo: env.opt("SVIDLET_BUNDLE_REPO"),
        public_key,
        public_key_path,
        ca_cert_path: env.opt("SVIDLET_BUNDLE_CACERT").map(PathBuf::from),
        token_path: env.opt("SVIDLET_BUNDLE_TOKEN_FILE").map(PathBuf::from),
        timeout: env.duration("SVIDLET_BUNDLE_TIMEOUT", Duration::from_secs(30))?,
        poll_interval: env.duration("SVIDLET_BUNDLE_POLL_INTERVAL", Duration::from_secs(60))?,
        poll_jitter: env.duration("SVIDLET_BUNDLE_POLL_JITTER", Duration::from_secs(30))?,
        directory: PathBuf::from(
            env.opt("SVIDLET_BUNDLE_DIR")
                .unwrap_or_else(|| "/var/lib/svidlet/policy".into()),
        ),
        keep_versions: env.count("SVIDLET_BUNDLE_KEEP_VERSIONS", 2)?,
        max_bytes: env.count("SVIDLET_BUNDLE_MAX_BYTES", 10 * 1024 * 1024)?,
    }))
}

fn vault_settings(env: &Env<'_>, cluster: &str) -> Result<VaultSettings> {
    let method = env
        .opt("SVIDLET_VAULT_AUTH")
        .unwrap_or_else(|| "approle".into());

    let auth = match method.as_str() {
        "approle" => AuthSettings::AppRole {
            mount: env
                .opt("SVIDLET_APPROLE_MOUNT")
                .unwrap_or_else(|| "approle".into()),
            role_id: env.req("SVIDLET_ROLE_ID")?,
            secret_id_path: PathBuf::from(
                env.opt("SVIDLET_SECRET_ID_FILE")
                    .unwrap_or_else(|| "/etc/svidlet/vault/secret-id".into()),
            ),
        },
        "kubernetes" => AuthSettings::Kubernetes {
            mount: env
                .opt("SVIDLET_VAULT_K8S_MOUNT")
                .unwrap_or_else(|| "kubernetes".into()),
            role: env.req("SVIDLET_VAULT_K8S_ROLE")?,
            token_path: PathBuf::from(
                env.opt("SVIDLET_VAULT_K8S_TOKEN_FILE")
                    .unwrap_or_else(|| KubernetesAuth::DEFAULT_TOKEN_PATH.into()),
            ),
        },
        "token" => AuthSettings::Token {
            path: PathBuf::from(
                env.opt("SVIDLET_VAULT_TOKEN_FILE")
                    .unwrap_or_else(|| "/etc/svidlet/vault/token".into()),
            ),
        },
        other => {
            return Err(ConfigError(format!(
                "SVIDLET_VAULT_AUTH must be approle, kubernetes or token; got {other:?}"
            )))
        }
    };

    Ok(VaultSettings {
        address: env.req("VAULT_ADDR")?,
        namespace: env.opt("VAULT_NAMESPACE"),
        ca_cert_path: env.opt("VAULT_CACERT").map(PathBuf::from),
        timeout: env.duration("SVIDLET_VAULT_TIMEOUT", Duration::from_secs(10))?,
        pki_mount: env.opt("SVIDLET_PKI_MOUNT").unwrap_or_else(|| "pki".into()),
        pki_role: env
            .opt("SVIDLET_PKI_ROLE")
            .unwrap_or_else(|| format!("spiffe-{cluster}")),
        auth,
    })
}

struct Env<'a>(&'a dyn Fn(&str) -> Option<String>);

impl Env<'_> {
    fn opt(&self, key: &str) -> Option<String> {
        match (self.0)(key) {
            Some(v) if !v.trim().is_empty() => Some(v.trim().to_string()),
            _ => None,
        }
    }

    fn req(&self, key: &str) -> Result<String> {
        self.opt(key)
            .ok_or_else(|| ConfigError(format!("{key} is required")))
    }

    fn duration(&self, key: &str, default: Duration) -> Result<Duration> {
        match self.opt(key) {
            None => Ok(default),
            Some(v) => parse_duration(&v).ok_or_else(|| {
                ConfigError(format!(
                    "{key} must be a duration like 30s, 10m, 24h or 3d; got {v:?}"
                ))
            }),
        }
    }

    fn bool(&self, key: &str, default: bool) -> Result<bool> {
        match self.opt(key) {
            None => Ok(default),
            Some(v) => match v.to_ascii_lowercase().as_str() {
                "true" | "yes" | "1" | "on" => Ok(true),
                "false" | "no" | "0" | "off" => Ok(false),
                _ => Err(ConfigError(format!(
                    "{key} must be true or false, got {v:?}"
                ))),
            },
        }
    }

    fn count(&self, key: &str, default: usize) -> Result<usize> {
        match self.opt(key) {
            None => Ok(default),
            Some(v) => v
                .parse::<usize>()
                .map_err(|_| ConfigError(format!("{key} must be a whole number, got {v:?}"))),
        }
    }

    fn float(&self, key: &str, default: f64) -> Result<f64> {
        match self.opt(key) {
            None => Ok(default),
            Some(v) => v
                .parse::<f64>()
                .map_err(|_| ConfigError(format!("{key} must be a number, got {v:?}"))),
        }
    }

    fn mode(&self, key: &str, default: u32) -> Result<u32> {
        match self.opt(key) {
            None => Ok(default),
            Some(v) => {
                let digits = v.trim_start_matches("0o");
                match u32::from_str_radix(digits, 8) {
                    Ok(mode) if mode <= 0o777 => Ok(mode),
                    _ => Err(ConfigError(format!(
                        "{key} must be an octal file mode like 0640, got {v:?}"
                    ))),
                }
            }
        }
    }
}

/// Parse `30s`, `10m`, `24h`, `3d`, or a bare number of seconds.
pub fn parse_duration(text: &str) -> Option<Duration> {
    let text = text.trim();
    let (digits, multiplier) = match text.chars().last()? {
        's' => (&text[..text.len() - 1], 1),
        'm' => (&text[..text.len() - 1], 60),
        'h' => (&text[..text.len() - 1], 3600),
        'd' => (&text[..text.len() - 1], 86_400),
        '0'..='9' => (text, 1),
        _ => return None,
    };
    let value: u64 = digits.trim().parse().ok()?;
    value.checked_mul(multiplier).map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// The minimum that makes a configuration valid.
    fn base() -> HashMap<String, String> {
        HashMap::from([
            ("NODE_NAME".into(), "node-1".into()),
            ("SVIDLET_CLUSTER".into(), "cluster-a".into()),
            ("SVIDLET_TRUST_DOMAIN".into(), "example.org".into()),
            ("VAULT_ADDR".into(), "https://vault.example:8200".into()),
            ("SVIDLET_ROLE_ID".into(), "role-id".into()),
        ])
    }

    fn load(vars: HashMap<String, String>) -> Result<Config> {
        Config::from_source(&move |key| vars.get(key).cloned())
    }

    fn with(pairs: &[(&str, &str)]) -> Result<Config> {
        let mut vars = base();
        for (k, v) in pairs {
            vars.insert((*k).into(), (*v).into());
        }
        load(vars)
    }

    #[test]
    fn defaults_match_the_documented_ones() {
        let cfg = load(base()).unwrap();
        assert_eq!(cfg.driver_name, "csi.svidlet.io");
        assert_eq!(
            cfg.csi_socket,
            PathBuf::from("/var/lib/kubelet/plugins/csi.svidlet.io/csi.sock")
        );
        assert_eq!(
            cfg.registration_socket,
            PathBuf::from("/var/lib/kubelet/plugins_registry/csi.svidlet.io-reg.sock")
        );
        assert_eq!(
            cfg.advertised_endpoint,
            cfg.csi_socket.display().to_string()
        );
        assert_eq!(cfg.kubelet_root, PathBuf::from("/var/lib/kubelet"));
        assert_eq!(cfg.spiffe_id_template, IdTemplate::DEFAULT);
        assert_eq!(cfg.spiffe_id_pattern, None);
        assert_eq!(cfg.cert_ttl, Duration::from_secs(86_400));
        assert_eq!(cfg.renew_fraction, (0.5, 0.7));
        assert_eq!(cfg.renew_check_interval, Duration::from_secs(30));
        assert_eq!(cfg.startup_spread, Duration::from_secs(300));
        assert_eq!(cfg.ca_refresh_interval, Duration::from_secs(3600));
        assert_eq!(cfg.tmpfs_size, "1m");
        assert_eq!((cfg.key_mode, cfg.cert_mode), (0o640, 0o644));
        assert_eq!(cfg.metrics_addr, "0.0.0.0:9464");
        assert_eq!(cfg.log_level, Level::Info);
        // The PKI role defaults to the cluster's own role.
        assert_eq!(cfg.vault.pki_role, "spiffe-cluster-a");
        assert_eq!(cfg.vault.pki_mount, "pki");
        assert_eq!(cfg.vault.timeout, Duration::from_secs(10));
        assert_eq!(cfg.vault.auth.method(), "approle");
    }

    #[test]
    fn every_required_variable_is_named_when_missing() {
        for key in [
            "NODE_NAME",
            "SVIDLET_CLUSTER",
            "SVIDLET_TRUST_DOMAIN",
            "VAULT_ADDR",
            "SVIDLET_ROLE_ID",
        ] {
            let mut vars = base();
            vars.remove(key);
            let err = load(vars).unwrap_err();
            assert!(err.0.contains(key), "{key}: {err}");
            assert!(err.to_string().starts_with("configuration error:"));
        }
    }

    #[test]
    fn blank_values_count_as_unset_and_whitespace_is_trimmed() {
        let cfg = with(&[
            ("SVIDLET_TMPFS_SIZE", "   "),
            ("SVIDLET_PKI_MOUNT", " pki-eu "),
        ])
        .unwrap();
        assert_eq!(cfg.tmpfs_size, "1m");
        assert_eq!(cfg.vault.pki_mount, "pki-eu");

        let mut vars = base();
        vars.insert("NODE_NAME".into(), "  ".into());
        assert!(load(vars).is_err());
    }

    #[test]
    fn each_auth_method_demands_its_own_settings() {
        let cfg = with(&[("SVIDLET_VAULT_AUTH", "approle")]).unwrap();
        match cfg.vault.auth {
            AuthSettings::AppRole {
                mount,
                role_id,
                secret_id_path,
            } => {
                assert_eq!(mount, "approle");
                assert_eq!(role_id, "role-id");
                assert_eq!(
                    secret_id_path,
                    PathBuf::from("/etc/svidlet/vault/secret-id")
                );
            }
            other => panic!("expected approle, got {other:?}"),
        }

        let cfg = with(&[
            ("SVIDLET_VAULT_AUTH", "kubernetes"),
            ("SVIDLET_VAULT_K8S_ROLE", "svidlet"),
        ])
        .unwrap();
        match cfg.vault.auth {
            AuthSettings::Kubernetes {
                mount,
                role,
                token_path,
            } => {
                assert_eq!(mount, "kubernetes");
                assert_eq!(role, "svidlet");
                assert_eq!(
                    token_path,
                    PathBuf::from(KubernetesAuth::DEFAULT_TOKEN_PATH)
                );
            }
            other => panic!("expected kubernetes, got {other:?}"),
        }
        // Without a role there is nothing to log in as.
        let err = with(&[("SVIDLET_VAULT_AUTH", "kubernetes")]).unwrap_err();
        assert!(err.0.contains("SVIDLET_VAULT_K8S_ROLE"));

        let cfg = with(&[("SVIDLET_VAULT_AUTH", "token")]).unwrap();
        assert_eq!(cfg.vault.auth.method(), "token");
        assert!(matches!(cfg.vault.auth, AuthSettings::Token { .. }));

        let err = with(&[("SVIDLET_VAULT_AUTH", "oidc")]).unwrap_err();
        assert!(err.0.contains("approle, kubernetes or token"));
    }

    #[test]
    fn approle_does_not_need_a_role_id_when_another_method_is_chosen() {
        let mut vars = base();
        vars.remove("SVIDLET_ROLE_ID");
        vars.insert("SVIDLET_VAULT_AUTH".into(), "token".into());
        assert!(load(vars).is_ok());
    }

    #[test]
    fn a_bad_spiffe_id_template_stops_start_up() {
        let err = with(&[("SVIDLET_SPIFFE_ID_TEMPLATE", "spiffe://{nope}/x")]).unwrap_err();
        assert!(err.0.contains("unknown placeholder"), "{err}");

        let err = with(&[("SVIDLET_SPIFFE_ID_PATTERN", "(unclosed")]).unwrap_err();
        assert!(err.0.contains("not a valid regex"), "{err}");
    }

    #[test]
    fn a_custom_template_and_pattern_are_carried_through() {
        let cfg = with(&[
            (
                "SVIDLET_SPIFFE_ID_TEMPLATE",
                "spiffe://{trust_domain}/ns/{namespace}/sa/{service_account}",
            ),
            ("SVIDLET_SPIFFE_ID_PATTERN", "spiffe://example.org/ns/.*"),
        ])
        .unwrap();
        let policy = cfg.id_policy().unwrap();
        assert_eq!(
            policy.template().as_str(),
            "spiffe://{trust_domain}/ns/{namespace}/sa/{service_account}"
        );
        assert_eq!(policy.pattern(), Some("spiffe://example.org/ns/.*"));
    }

    #[test]
    fn policy_is_off_until_an_endpoint_is_configured() {
        // Nothing set: no stream, no policy directory.
        let cfg = load(base()).unwrap();
        assert!(cfg.policy.enabled, "the flag itself defaults to on");
        assert_eq!(cfg.policy.endpoint, None);
        assert_eq!(cfg.policy.directory, "policy");
        assert!(!cfg.policy.required);
        assert_eq!(cfg.policy.initial_timeout, Duration::from_secs(10));

        let cfg = with(&[("SVIDLET_POLICY_ENDPOINT", "https://policy.example:9000")]).unwrap();
        assert_eq!(
            cfg.policy.endpoint.as_deref(),
            Some("https://policy.example:9000")
        );
    }

    #[test]
    fn the_policy_flag_switches_a_configured_endpoint_off() {
        // Keeping the endpoint in the ConfigMap and flipping one variable is
        // the point: no manifest surgery to run without a policy backend.
        let cfg = with(&[
            ("SVIDLET_POLICY_ENDPOINT", "https://policy.example:9000"),
            ("SVIDLET_POLICY_ENABLED", "false"),
        ])
        .unwrap();
        assert!(!cfg.policy.enabled);
        assert_eq!(
            cfg.policy.endpoint.as_deref(),
            Some("https://policy.example:9000"),
            "the endpoint is kept, just not used"
        );
    }

    #[test]
    fn booleans_accept_the_usual_spellings_and_reject_the_rest() {
        for on in ["true", "TRUE", "yes", "1", "on"] {
            assert!(
                with(&[("SVIDLET_POLICY_ENABLED", on)])
                    .unwrap()
                    .policy
                    .enabled,
                "{on}"
            );
        }
        for off in ["false", "False", "no", "0", "off"] {
            assert!(
                !with(&[("SVIDLET_POLICY_ENABLED", off)])
                    .unwrap()
                    .policy
                    .enabled,
                "{off}"
            );
        }
        let err = with(&[("SVIDLET_POLICY_ENABLED", "maybe")]).unwrap_err();
        assert!(err.0.contains("must be true or false"), "{err}");

        // The same parser backs SVIDLET_POLICY_REQUIRED.
        assert!(
            with(&[("SVIDLET_POLICY_REQUIRED", "yes")])
                .unwrap()
                .policy
                .required
        );
    }

    #[test]
    fn renew_fractions_must_bracket_a_real_window() {
        for (min, max) in [
            ("0.9", "0.5"),
            ("0", "0.7"),
            ("0.5", "1.0"),
            ("-0.1", "0.5"),
        ] {
            let err = with(&[
                ("SVIDLET_RENEW_MIN_FRACTION", min),
                ("SVIDLET_RENEW_MAX_FRACTION", max),
            ])
            .unwrap_err();
            assert!(err.0.contains("renew fractions"), "{min}..{max}: {err}");
        }
        // A zero-width window is legal: it means "always at exactly this point".
        let cfg = with(&[
            ("SVIDLET_RENEW_MIN_FRACTION", "0.6"),
            ("SVIDLET_RENEW_MAX_FRACTION", "0.6"),
        ])
        .unwrap();
        assert_eq!(cfg.renew_fraction, (0.6, 0.6));

        let err = with(&[("SVIDLET_RENEW_MIN_FRACTION", "half")]).unwrap_err();
        assert!(err.0.contains("must be a number"));
    }

    #[test]
    fn file_modes_are_octal_and_bounded() {
        let cfg = with(&[("SVIDLET_KEY_MODE", "0600"), ("SVIDLET_CERT_MODE", "0o644")]).unwrap();
        assert_eq!((cfg.key_mode, cfg.cert_mode), (0o600, 0o644));

        for bad in ["999", "rw-r-----", "1777", ""] {
            if bad.is_empty() {
                continue; // empty means unset, covered elsewhere
            }
            let err = with(&[("SVIDLET_KEY_MODE", bad)]).unwrap_err();
            assert!(err.0.contains("octal file mode"), "{bad}: {err}");
        }
    }

    #[test]
    fn log_level_is_validated_rather_than_silently_ignored() {
        assert_eq!(
            with(&[("SVIDLET_LOG_LEVEL", "debug")]).unwrap().log_level,
            Level::Debug
        );
        assert_eq!(
            with(&[("SVIDLET_LOG_LEVEL", "WARN")]).unwrap().log_level,
            Level::Warn
        );
        let err = with(&[("SVIDLET_LOG_LEVEL", "verbose")]).unwrap_err();
        assert!(err.0.contains("error, warn, info, debug"));
    }

    #[test]
    fn durations_accept_units_and_reject_nonsense() {
        assert_eq!(parse_duration("45"), Some(Duration::from_secs(45)));
        assert_eq!(parse_duration("30s"), Some(Duration::from_secs(30)));
        assert_eq!(parse_duration("10m"), Some(Duration::from_secs(600)));
        assert_eq!(parse_duration("24h"), Some(Duration::from_secs(86_400)));
        assert_eq!(parse_duration(" 3d "), Some(Duration::from_secs(259_200)));
        for bad in [
            "",
            "h",
            "-5s",
            "1w",
            "1.5h",
            "abc",
            "999999999999999999999d",
        ] {
            assert_eq!(parse_duration(bad), None, "{bad:?}");
        }

        let cfg = with(&[
            ("SVIDLET_CERT_TTL", "48h"),
            ("SVIDLET_VAULT_TIMEOUT", "5s"),
            ("SVIDLET_CA_REFRESH_INTERVAL", "30m"),
        ])
        .unwrap();
        assert_eq!(cfg.cert_ttl, Duration::from_secs(172_800));
        assert_eq!(cfg.vault.timeout, Duration::from_secs(5));
        assert_eq!(cfg.ca_refresh_interval, Duration::from_secs(1800));

        let err = with(&[("SVIDLET_CERT_TTL", "one day")]).unwrap_err();
        assert!(err.0.contains("30s, 10m, 24h or 3d"));
    }

    #[test]
    fn socket_paths_follow_a_custom_driver_name() {
        let cfg = with(&[("SVIDLET_DRIVER_NAME", "spiffe.example.com")]).unwrap();
        assert_eq!(
            cfg.csi_socket,
            PathBuf::from("/var/lib/kubelet/plugins/spiffe.example.com/csi.sock")
        );
        assert_eq!(
            cfg.registration_socket,
            PathBuf::from("/var/lib/kubelet/plugins_registry/spiffe.example.com-reg.sock")
        );

        // An advertised endpoint can differ when the hostPath is remapped.
        let cfg = with(&[("SVIDLET_ADVERTISED_ENDPOINT", "/host/csi.sock")]).unwrap();
        assert_eq!(cfg.advertised_endpoint, "/host/csi.sock");
    }

    #[test]
    fn optional_vault_settings_are_passed_through() {
        let cfg = with(&[
            ("VAULT_NAMESPACE", "team-a"),
            ("VAULT_CACERT", "/etc/ssl/vault.pem"),
            ("SVIDLET_PKI_ROLE", "custom-role"),
        ])
        .unwrap();
        assert_eq!(cfg.vault.namespace.as_deref(), Some("team-a"));
        assert_eq!(
            cfg.vault.ca_cert_path,
            Some(PathBuf::from("/etc/ssl/vault.pem"))
        );
        assert_eq!(cfg.vault.pki_role, "custom-role");
    }
}
