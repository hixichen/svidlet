//! The rollout manifest: which bundle this node should be running.
//!
//! Rings are evaluated top to bottom and the first match wins. `node_hash_percent`
//! compares a stable hash of (cluster, node) against a threshold, so a node's
//! ring never changes across restarts and the *same* nodes are the canary for
//! every rollout — which is the point of a canary. Randomising membership per
//! rollout would spread the risk across the fleet instead of concentrating it
//! where it is being watched.

use ring::digest;
use serde::Deserialize;

use super::Error;

/// The highest manifest schema this build understands.
pub const SUPPORTED_SCHEMA: u32 = 1;

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct Rollout {
    pub schema: u32,
    /// The kill switch. While true, nodes apply nothing at all — not even a
    /// rollback — so that humans looking at a live incident are not racing an
    /// automated promotion.
    #[serde(default)]
    pub freeze: bool,
    #[serde(default, rename = "ring")]
    pub rings: Vec<Ring>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct Ring {
    pub name: String,
    #[serde(default)]
    pub r#match: Match,
    /// The bundle digest this ring should be running, `sha256:…`.
    pub bundle: String,
}

#[derive(Debug, Deserialize, Default, PartialEq, Eq)]
pub struct Match {
    /// Glob patterns matched against the cluster name, e.g. `dev-*`.
    #[serde(default)]
    pub clusters: Vec<String>,
    /// Match when the node's stable hash falls below this percentage.
    #[serde(default)]
    pub node_hash_percent: Option<u8>,
    /// Exact node names, for one-off debugging.
    #[serde(default)]
    pub nodes: Vec<String>,
}

impl Match {
    /// An empty match matches everything, so `[[ring]]` with no `match` is a
    /// catch-all — the shape a single-ring fleet wants.
    fn is_catch_all(&self) -> bool {
        self.clusters.is_empty() && self.node_hash_percent.is_none() && self.nodes.is_empty()
    }

    fn matches(&self, cluster: &str, node: &str) -> bool {
        if self.is_catch_all() {
            return true;
        }
        // Any clause matching is enough: a ring is "dev clusters, or these
        // named nodes, or this slice of the fleet".
        if self.nodes.iter().any(|n| n == node) {
            return true;
        }
        if self.clusters.iter().any(|glob| glob_match(glob, cluster)) {
            return true;
        }
        match self.node_hash_percent {
            Some(percent) => node_bucket(cluster, node) < percent as u32,
            None => false,
        }
    }
}

impl Rollout {
    pub fn parse(toml: &[u8]) -> Result<Rollout, Error> {
        let text = std::str::from_utf8(toml)
            .map_err(|e| Error::Malformed(format!("rollout manifest is not UTF-8: {e}")))?;
        let rollout: Rollout = basic_toml::from_str(text)
            .map_err(|e| Error::Malformed(format!("rollout manifest is not valid TOML: {e}")))?;

        if rollout.schema != SUPPORTED_SCHEMA {
            // Refusing a newer schema is deliberate: a node that guessed at a
            // manifest it does not understand could apply the wrong bundle
            // fleet-wide. Staying on the current bundle is always safe.
            return Err(Error::Malformed(format!(
                "rollout manifest schema {} is not supported (this build understands {SUPPORTED_SCHEMA})",
                rollout.schema
            )));
        }
        for ring in &rollout.rings {
            if ring.name.is_empty() {
                return Err(Error::Malformed("a ring has no name".into()));
            }
            check_digest_form(&ring.bundle, &ring.name)?;
            if let Some(percent) = ring.r#match.node_hash_percent {
                if percent > 100 {
                    return Err(Error::Malformed(format!(
                        "ring {:?} has node_hash_percent = {percent}, which is above 100",
                        ring.name
                    )));
                }
            }
        }
        Ok(rollout)
    }

    /// The ring this node belongs to, and the bundle it should be running.
    pub fn target(&self, cluster: &str, node: &str) -> Option<&Ring> {
        self.rings
            .iter()
            .find(|ring| ring.r#match.matches(cluster, node))
    }
}

fn check_digest_form(digest: &str, ring: &str) -> Result<(), Error> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(Error::Malformed(format!(
            "ring {ring:?} names bundle {digest:?}, which is not a sha256: digest"
        )));
    };
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Malformed(format!(
            "ring {ring:?} names bundle {digest:?}, whose digest is not 64 hex characters"
        )));
    }
    Ok(())
}

/// A node's stable position in `0..100`.
///
/// SHA-256 rather than a language hash: the value has to mean the same thing on
/// every node and across every build, and `DefaultHasher` guarantees neither.
pub fn node_bucket(cluster: &str, node: &str) -> u32 {
    let mut input = Vec::with_capacity(cluster.len() + node.len() + 1);
    input.extend_from_slice(cluster.as_bytes());
    input.push(0);
    input.extend_from_slice(node.as_bytes());

    let hash = digest::digest(&digest::SHA256, &input);
    let bytes = hash.as_ref();
    let value = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    value % 100
}

/// `*` matches any run of characters; everything else is literal. Enough for
/// `dev-*` and `*-prod`, and small enough to have no surprises in it.
fn glob_match(pattern: &str, text: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == text,
        Some((head, tail)) => {
            if !text.starts_with(head) {
                return false;
            }
            let rest = &text[head.len()..];
            // The tail may itself contain further wildcards.
            if tail.contains('*') {
                (0..=rest.len()).any(|i| glob_match(tail, &rest[i..]))
            } else {
                rest.len() >= tail.len() && rest.ends_with(tail)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST_A: &str =
        "sha256:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
    const DIGEST_B: &str =
        "sha256:9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f";

    fn manifest() -> String {
        format!(
            r#"
schema = 1
freeze = false

[[ring]]
name = "dev"
match = {{ clusters = ["dev-*"] }}
bundle = "{DIGEST_A}"

[[ring]]
name = "canary"
match = {{ node_hash_percent = 1 }}
bundle = "{DIGEST_A}"

[[ring]]
name = "broad"
match = {{ node_hash_percent = 25 }}
bundle = "{DIGEST_A}"

[[ring]]
name = "all"
match = {{ node_hash_percent = 100 }}
bundle = "{DIGEST_B}"
"#
        )
    }

    #[test]
    fn the_manifest_from_the_design_document_parses() {
        let rollout = Rollout::parse(manifest().as_bytes()).unwrap();
        assert_eq!(rollout.schema, 1);
        assert!(!rollout.freeze);
        assert_eq!(rollout.rings.len(), 4);
        assert_eq!(rollout.rings[0].name, "dev");
        assert_eq!(rollout.rings[0].r#match.clusters, vec!["dev-*"]);
        assert_eq!(rollout.rings[1].r#match.node_hash_percent, Some(1));
    }

    #[test]
    fn a_dev_cluster_takes_the_first_ring_whatever_its_hash() {
        let rollout = Rollout::parse(manifest().as_bytes()).unwrap();
        for node in ["node-1", "node-2", "node-3"] {
            let ring = rollout.target("dev-eu", node).unwrap();
            assert_eq!(ring.name, "dev");
            assert_eq!(ring.bundle, DIGEST_A);
        }
        // A production cluster does not match the glob.
        assert_ne!(rollout.target("prod-eu", "node-1").unwrap().name, "dev");
    }

    #[test]
    fn ring_membership_splits_the_fleet_roughly_as_the_percentages_say() {
        let rollout = Rollout::parse(manifest().as_bytes()).unwrap();
        let mut counts = std::collections::HashMap::new();
        for i in 0..10_000 {
            let node = format!("node-{i}");
            let ring = rollout.target("prod-eu", &node).unwrap();
            *counts.entry(ring.name.clone()).or_insert(0usize) += 1;
        }
        // Rings are evaluated in order, so "broad" gets 25% minus canary's 1%.
        let canary = counts["canary"] as f64 / 100.0;
        let broad = counts["broad"] as f64 / 100.0;
        let all = counts["all"] as f64 / 100.0;
        assert!((0.5..1.5).contains(&canary), "canary {canary}%");
        assert!((23.0..26.0).contains(&broad), "broad {broad}%");
        assert!((73.0..77.0).contains(&all), "all {all}%");
    }

    #[test]
    fn a_nodes_ring_is_stable_across_restarts_and_across_rollouts() {
        // The same node always lands in the same bucket: this is what makes a
        // canary a canary rather than a random 1% each time.
        let first = node_bucket("prod-eu", "node-7");
        for _ in 0..100 {
            assert_eq!(node_bucket("prod-eu", "node-7"), first);
        }
        // And the bucket depends on both cluster and node.
        assert_ne!(node_bucket("prod-us", "node-7"), first);
        assert_ne!(node_bucket("prod-eu", "node-8"), first);
        assert!(node_bucket("a", "b") < 100);
    }

    #[test]
    fn the_cluster_and_node_cannot_be_confused_with_each_other() {
        // Without a separator, ("ab", "c") and ("a", "bc") would hash alike.
        assert_ne!(node_bucket("ab", "c"), node_bucket("a", "bc"));
    }

    #[test]
    fn a_ring_with_no_match_clause_is_a_catch_all() {
        let toml = format!("schema = 1\n\n[[ring]]\nname = \"all\"\nbundle = \"{DIGEST_A}\"\n");
        let rollout = Rollout::parse(toml.as_bytes()).unwrap();
        assert_eq!(rollout.target("anything", "any-node").unwrap().name, "all");
    }

    #[test]
    fn named_nodes_match_for_one_off_debugging() {
        let toml = format!(
            r#"
schema = 1

[[ring]]
name = "debug"
match = {{ nodes = ["node-broken"] }}
bundle = "{DIGEST_A}"

[[ring]]
name = "all"
bundle = "{DIGEST_B}"
"#
        );
        let rollout = Rollout::parse(toml.as_bytes()).unwrap();
        assert_eq!(rollout.target("prod", "node-broken").unwrap().name, "debug");
        assert_eq!(rollout.target("prod", "node-fine").unwrap().name, "all");
    }

    #[test]
    fn a_node_matching_nothing_gets_no_target() {
        let toml = format!(
            "schema = 1\n\n[[ring]]\nname = \"dev\"\nmatch = {{ clusters = [\"dev-*\"] }}\nbundle = \"{DIGEST_A}\"\n"
        );
        let rollout = Rollout::parse(toml.as_bytes()).unwrap();
        assert!(rollout.target("prod-eu", "node-1").is_none());
    }

    #[test]
    fn freeze_is_read_and_defaults_to_off() {
        let frozen = Rollout::parse(b"schema = 1\nfreeze = true\n").unwrap();
        assert!(frozen.freeze);
        assert!(!Rollout::parse(b"schema = 1\n").unwrap().freeze);
    }

    #[test]
    fn a_newer_schema_is_refused_rather_than_guessed_at() {
        let err = Rollout::parse(b"schema = 2\n").unwrap_err();
        assert!(matches!(err, Error::Malformed(_)));
        assert!(err.to_string().contains("not supported"));
    }

    #[test]
    fn a_ring_naming_something_that_is_not_a_digest_is_refused() {
        for bad in ["latest", "sha256:short", "sha512:aaaa", "sha256:zz"] {
            let toml = format!("schema = 1\n\n[[ring]]\nname = \"all\"\nbundle = \"{bad}\"\n");
            let err = Rollout::parse(toml.as_bytes()).unwrap_err();
            assert!(matches!(err, Error::Malformed(_)), "{bad}: {err}");
        }
    }

    #[test]
    fn nonsense_manifests_are_refused() {
        assert!(Rollout::parse(b"not toml at all [[[").is_err());
        assert!(Rollout::parse(&[0xff, 0xfe]).is_err());
        // A percentage above 100 is a typo, not a wider rollout.
        let toml = format!(
            "schema = 1\n\n[[ring]]\nname = \"all\"\nmatch = {{ node_hash_percent = 250 }}\nbundle = \"{DIGEST_A}\"\n"
        );
        assert!(Rollout::parse(toml.as_bytes()).is_err());
        // A nameless ring cannot be reported in a metric.
        let toml = format!("schema = 1\n\n[[ring]]\nname = \"\"\nbundle = \"{DIGEST_A}\"\n");
        assert!(Rollout::parse(toml.as_bytes()).is_err());
    }

    #[test]
    fn globs_match_the_shapes_a_cluster_name_takes() {
        assert!(glob_match("dev-*", "dev-eu"));
        assert!(glob_match("dev-*", "dev-"));
        assert!(!glob_match("dev-*", "prod-eu"));
        assert!(glob_match("*-prod", "eu-prod"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "exactly"));
        assert!(glob_match("a*c*e", "abcde"));
        assert!(!glob_match("a*c*e", "abcd"));
    }
}
