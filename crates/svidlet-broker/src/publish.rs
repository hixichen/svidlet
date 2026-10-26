//! `oidc-publisher` (docs/DESIGN.md §8): copy Vault's discovery document and
//! JWKS to the directory a bucket is synced from, after checking them.
//!
//! Writing the bucket is Tier-0 — whoever writes the JWKS decides which
//! signatures relying parties accept — so this refuses anything it cannot
//! vouch for and leaves the last good copy in place.

use std::path::Path;

use svidlet_issue::jwt::Jwks;

/// What was checked, for the log line.
#[derive(Debug, PartialEq, Eq)]
pub struct Checked {
    pub issuer: String,
    pub kids: Vec<String>,
}

/// Check a discovery document and JWKS against the expected issuer.
pub fn check(discovery: &str, jwks: &str, expected_issuer: &str) -> Result<Checked, String> {
    let doc: serde_json::Value =
        serde_json::from_str(discovery).map_err(|e| format!("discovery is not JSON: {e}"))?;
    let issuer = doc
        .get("issuer")
        .and_then(|v| v.as_str())
        .ok_or("discovery has no issuer")?;
    if issuer != expected_issuer {
        return Err(format!(
            "issuer is {issuer:?}, expected {expected_issuer:?}"
        ));
    }
    let jwks_uri = doc
        .get("jwks_uri")
        .and_then(|v| v.as_str())
        .ok_or("discovery has no jwks_uri")?;
    if !jwks_uri.starts_with(&format!("{}/", expected_issuer.trim_end_matches('/'))) {
        return Err(format!("jwks_uri {jwks_uri:?} is not under the issuer"));
    }
    let set = Jwks::parse(jwks).map_err(|e| e.to_string())?;
    if set.is_empty() {
        return Err("the JWKS holds no keys".into());
    }
    Ok(Checked {
        issuer: issuer.to_string(),
        kids: set.kids().map(str::to_string).collect(),
    })
}

/// Write both files under `<out>/<issuer path>/.well-known/`, each by
/// rename so the sync never uploads a half-written file.
pub fn write(out: &Path, issuer: &str, discovery: &str, jwks: &str) -> std::io::Result<()> {
    let path = issuer
        .split_once("://")
        .map(|(_, rest)| rest.split_once('/').map(|(_, p)| p).unwrap_or(""))
        .unwrap_or("");
    let dir = out.join(path).join(".well-known");
    std::fs::create_dir_all(&dir)?;
    for (name, body) in [("openid-configuration", discovery), ("keys", jwks)] {
        let tmp = dir.join(format!(".{name}.tmp"));
        std::fs::write(&tmp, body)?;
        std::fs::rename(&tmp, dir.join(name))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUER: &str = "https://oidc.corp.example/v1/spiffe";
    const KEYS: &str = r#"{"keys":[{"kid":"k1","kty":"EC","crv":"P-256","x":"AAAA","y":"AAAA"}]}"#;

    fn discovery(issuer: &str, jwks_uri: &str) -> String {
        serde_json::json!({ "issuer": issuer, "jwks_uri": jwks_uri }).to_string()
    }

    #[test]
    fn a_consistent_pair_is_published_under_the_issuer_path() {
        let d = discovery(ISSUER, &format!("{ISSUER}/.well-known/keys"));
        let checked = check(&d, KEYS, ISSUER).unwrap();
        assert_eq!(checked.kids, vec!["k1"]);

        let out = std::env::temp_dir().join(format!("svidlet-publish-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&out);
        write(&out, ISSUER, &d, KEYS).unwrap();
        let keys = out.join("v1/spiffe/.well-known/keys");
        assert_eq!(std::fs::read_to_string(keys).unwrap(), KEYS);
        assert!(out
            .join("v1/spiffe/.well-known/openid-configuration")
            .exists());
        std::fs::remove_dir_all(&out).unwrap();
    }

    #[test]
    fn anything_relying_parties_should_not_trust_is_refused() {
        let good_uri = format!("{ISSUER}/.well-known/keys");
        for (d, k) in [
            (discovery("https://evil.example/v1/spiffe", &good_uri), KEYS),
            (discovery(ISSUER, "https://evil.example/keys"), KEYS),
            (discovery(ISSUER, &good_uri), r#"{"keys":[]}"#),
            (discovery(ISSUER, &good_uri), r#"{"keys":[{"kty":"EC"}]}"#),
            ("not json".to_string(), KEYS),
        ] {
            assert!(check(&d, k, ISSUER).is_err(), "{d} {k}");
        }
    }
}
