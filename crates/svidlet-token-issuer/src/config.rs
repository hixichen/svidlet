//! The issuer's configuration file.
//!
//! ```toml
//! issuer = "https://tokens.example.org"   # the `iss` claim; serves discovery
//! trust_domain = "example.org"
//! token_ttl_secs = 21600                  # capped per token at the pod certificate's notAfter
//!
//! listen = "0.0.0.0:8443"                 # gRPC, mutual TLS, for svidlet
//! public_listen = "0.0.0.0:8080"          # discovery and JWKS, plain HTTP behind the load balancer
//! metrics_listen = "0.0.0.0:9466"
//!
//! server_cert = "/etc/token-issuer/tls/tls.crt"   # this issuer's TLS certificate, from Vault
//! server_key = "/etc/token-issuer/tls/tls.key"
//! node_ca = "/etc/token-issuer/node-ca.pem"       # who may call: the node registration CA
//! pod_ca = "/etc/token-issuer/pod-ca.pem"         # whose certificates count: the Vault PKI chain
//!
//! [[key]]
//! path = "/etc/token-issuer/keys/2026-09-22.pem"  # PKCS#8 PEM, P-256
//! sign = true
//!
//! [[grant]]
//! prefix = "spiffe://example.org/cluster/prod-a/ns/payments/"
//! audiences = ["api://AzureADTokenExchange"]
//! ```

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

use crate::grants::Grant;

/// The file, as written.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub issuer: String,
    pub trust_domain: String,
    #[serde(default = "default_ttl")]
    pub token_ttl_secs: u64,
    pub listen: SocketAddr,
    pub public_listen: Option<SocketAddr>,
    pub metrics_listen: Option<SocketAddr>,
    pub server_cert: PathBuf,
    pub server_key: PathBuf,
    pub node_ca: PathBuf,
    pub pod_ca: PathBuf,
    #[serde(rename = "key")]
    pub keys: Vec<KeyFile>,
    #[serde(rename = "grant", default)]
    pub grants: Vec<Grant>,
}

/// A signing key on disk.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyFile {
    pub path: PathBuf,
    /// `false` publishes the key without signing with it: the next
    /// generation before it takes over, or the last one while its tokens
    /// expire.
    pub sign: bool,
}

/// Six hours, the roadmap's JWT lifetime: renewed at 50–70 %, so about three
/// hours of issuer outage pass before any pod lacks a fresh token.
const fn default_ttl() -> u64 {
    21_600
}

impl Config {
    /// Parse and sanity-check a configuration file's contents.
    ///
    /// # Errors
    ///
    /// A description of the problem for malformed TOML, an unknown field, an
    /// issuer that is not an `https://` URL, or a zero token lifetime.
    pub fn parse(text: &str) -> Result<Config, String> {
        let cfg: Config = basic_toml::from_str(text).map_err(|e| e.to_string())?;
        if !cfg.issuer.starts_with("https://") || cfg.issuer.ends_with('/') {
            return Err(format!(
                "issuer must be an https:// URL without a trailing slash, got {:?}",
                cfg.issuer
            ));
        }
        if cfg.token_ttl_secs == 0 {
            return Err("token_ttl_secs must be positive".into());
        }
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
        issuer = "https://tokens.example.org"
        trust_domain = "example.org"
        listen = "127.0.0.1:8443"
        server_cert = "c"
        server_key = "k"
        node_ca = "n"
        pod_ca = "p"
        [[key]]
        path = "k1.pem"
        sign = true
    "#;

    #[test]
    fn a_minimal_file_parses_with_the_documented_defaults() {
        let cfg = Config::parse(MINIMAL).unwrap();
        assert_eq!(cfg.token_ttl_secs, 21_600);
        assert_eq!(cfg.keys.len(), 1);
        assert!(cfg.grants.is_empty());
        assert!(cfg.public_listen.is_none());
    }

    #[test]
    fn grants_and_several_keys_parse() {
        let text = format!(
            "{MINIMAL}\n[[key]]\npath = \"k2.pem\"\nsign = false\n\
             [[grant]]\nprefix = \"spiffe://example.org/cluster/a/ns/p/\"\naudiences = [\"x\", \"y\"]\n"
        );
        let cfg = Config::parse(&text).unwrap();
        assert_eq!(cfg.keys.len(), 2);
        assert!(!cfg.keys[1].sign);
        assert_eq!(cfg.grants[0].audiences, vec!["x", "y"]);
    }

    #[test]
    fn typos_and_unsafe_values_are_refused() {
        let _ = Config::parse(&format!("{MINIMAL}\ntoken_tll_secs = 5")).unwrap_err();
        let _ =
            Config::parse(&MINIMAL.replace("https://tokens.example.org", "http://x")).unwrap_err();
        let _ = Config::parse(&MINIMAL.replace("tokens.example.org", "tokens.example.org/"))
            .unwrap_err();
        let _ = Config::parse(&format!("{MINIMAL}\ntoken_ttl_secs = 0")).unwrap_err();
    }

    #[test]
    fn the_shipped_example_is_valid() {
        let cfg = Config::parse(include_str!("../../../deploy/token-issuer/config.toml")).unwrap();
        let _ = crate::grants::Grants::new(&cfg.trust_domain, cfg.grants).unwrap();
        assert!(cfg.keys.iter().any(|k| k.sign));
    }
}
