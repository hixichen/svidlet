//! Rebuilding the renewal list after a restart.
//!
//! The plugin keeps no state of its own on disk. On start it walks the
//! kubelet's CSI volume records under `<kubelet-root>/pods`, and for every
//! volume that belongs to this driver it reads the certificate that is already
//! published and takes the identity and the validity window from the
//! certificate itself.
//!
//! Nothing is re-issued. This is a correctness requirement, not a tuning knob:
//! a plugin upgrade that re-signed every certificate on the node would turn a
//! rolling DaemonSet update into a fleet-wide signing storm.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use svidlet_issue::{CertFacts, Field, IdPolicy};

use crate::config::Config;
use crate::metrics::Metrics;
use crate::store::{jittered_renew_at, Entry, PodRef, Store};
use crate::{debug, info, rand, volume, warn};

/// The kubelet's own record of a mounted CSI volume.
#[derive(Debug, Deserialize)]
struct VolData {
    #[serde(rename = "driverName")]
    driver_name: String,
    #[serde(rename = "volumeHandle", default)]
    volume_handle: String,
    #[serde(rename = "specVolID", default)]
    spec_vol_id: String,
}

/// A volume record found on disk, before its certificate has been read.
#[derive(Debug, PartialEq, Eq)]
pub struct Discovered {
    pub volume_id: String,
    pub target_path: PathBuf,
    pub pod_uid: String,
}

/// Walk `<kubelet_root>/pods/*/volumes/kubernetes.io~csi/*/vol_data.json` and
/// return the volumes belonging to `driver_name`.
pub fn discover(kubelet_root: &Path, driver_name: &str) -> Vec<Discovered> {
    let mut found = Vec::new();
    let pods = kubelet_root.join("pods");
    let Ok(pod_dirs) = std::fs::read_dir(&pods) else {
        warn!(
            "cannot list pod directory; starting with an empty renewal list",
            path = pods.display()
        );
        return found;
    };

    for pod in pod_dirs.flatten() {
        let pod_uid = pod.file_name().to_string_lossy().into_owned();
        let csi_dir = pod.path().join("volumes").join("kubernetes.io~csi");
        let Ok(volumes) = std::fs::read_dir(&csi_dir) else {
            continue;
        };
        for volume_dir in volumes.flatten() {
            let record = volume_dir.path().join("vol_data.json");
            let Ok(raw) = std::fs::read_to_string(&record) else {
                continue;
            };
            let data: VolData = match serde_json::from_str(&raw) {
                Ok(d) => d,
                Err(e) => {
                    debug!(
                        "skipping unparsable volume record",
                        path = record.display(),
                        error = e
                    );
                    continue;
                }
            };
            if data.driver_name != driver_name {
                continue;
            }
            let volume_id = if data.volume_handle.is_empty() {
                data.spec_vol_id.clone()
            } else {
                data.volume_handle.clone()
            };
            found.push(Discovered {
                volume_id,
                target_path: volume_dir.path().join("mount"),
                pod_uid: pod_uid.clone(),
            });
        }
    }
    found.sort_by(|a, b| a.target_path.cmp(&b.target_path));
    found
}

/// Adopt every discovered volume into `store`, and return how many were adopted.
///
/// Volumes whose certificate is missing, unreadable, or does not carry a SPIFFE
/// ID this plugin would have issued are left alone and logged: the kubelet will
/// call `NodePublishVolume` again if the pod still needs one.
pub fn adopt(cfg: &Config, policy: &IdPolicy, store: &Store, metrics: &Metrics) -> usize {
    let now = crate::log::unix_now();
    let mut adopted = 0;
    let mut skipped = 0;

    for found in discover(&cfg.kubelet_root, &cfg.driver_name) {
        let chain = match volume::read_cert_chain(&found.target_path) {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    "no certificate to adopt at published volume; it will be re-issued",
                    path = found.target_path.display(),
                    error = e,
                );
                skipped += 1;
                continue;
            }
        };
        let facts: CertFacts = match svidlet_issue::inspect(&chain) {
            Ok(f) => f,
            Err(e) => {
                warn!(
                    "cannot read certificate; leaving volume alone",
                    path = found.target_path.display(),
                    code = e.code(),
                    error = e,
                );
                skipped += 1;
                continue;
            }
        };

        if let Err(reason) = identity_belongs_here(
            policy,
            facts.spiffe_id.as_str(),
            &cfg.trust_domain,
            &cfg.cluster,
            &cfg.node_name,
        ) {
            warn!(
                "not adopting a published certificate; it will be re-issued",
                spiffe_id = facts.spiffe_id,
                path = found.target_path.display(),
                reason = reason,
            );
            skipped += 1;
            continue;
        }

        let mut renew_at = jittered_renew_at(facts.not_before, facts.not_after, cfg.renew_fraction);
        // Certificates already past their renewal point would otherwise all
        // renew in the first tick after a rolling upgrade. Spread them.
        if renew_at <= now {
            renew_at = now + rand::range_i64(0, cfg.startup_spread.as_secs() as i64);
        }

        let attrs = policy
            .attributes_of(facts.spiffe_id.as_str())
            .unwrap_or_default();
        let pod = PodRef {
            // Only what the ID itself carries is recoverable; the rest is used
            // for logging only, so an empty value is harmless.
            name: attrs.pod_name,
            namespace: attrs.namespace,
            uid: found.pod_uid,
        };
        store.insert(Entry {
            volume_id: found.volume_id,
            target_path: found.target_path.clone(),
            spiffe_id: facts.spiffe_id.clone(),
            pod,
            not_before: facts.not_before,
            not_after: facts.not_after,
            renew_at,
            failures: 0,
        });
        adopted += 1;
    }

    metrics
        .adoption_skipped
        .fetch_add(skipped as u64, std::sync::atomic::Ordering::Relaxed);
    if skipped > 0 {
        // Each of these becomes a fresh signing request, so it is worth
        // noticing when the number is not zero.
        warn!(
            "some published volumes could not be adopted",
            adopted = adopted,
            skipped = skipped
        );
    } else {
        info!("restart recovery complete", adopted = adopted);
    }
    adopted
}

/// Whether a certificate found on disk is one this node would have issued.
///
/// Shared by restart recovery and by `svidlet-policy`, which has the same
/// question to answer for a different reason: recovery must not adopt a
/// certificate it cannot renew, and the policy daemon must not hand a bundle to
/// an identity that belongs to another fleet.
///
/// A template that does not substitute a field cannot constrain it — a fleet
/// whose IDs carry no cluster segment has nothing to check the cluster against.
pub fn identity_belongs_here(
    policy: &IdPolicy,
    spiffe_id: &str,
    trust_domain: &str,
    cluster: &str,
    node_name: &str,
) -> std::result::Result<(), String> {
    let Some(attrs) = policy.attributes_of(spiffe_id) else {
        return Err(format!(
            "does not match the configured SPIFFE ID template {:?}",
            policy.template().as_str()
        ));
    };
    if let Err(e) = policy.check(spiffe_id) {
        return Err(e.to_string());
    }

    let fields = policy.template().required_fields();
    if fields.contains(&Field::TrustDomain) && attrs.trust_domain != trust_domain {
        return Err(format!(
            "belongs to trust domain {:?}, not {trust_domain:?}",
            attrs.trust_domain
        ));
    }
    if fields.contains(&Field::Cluster) && attrs.cluster != cluster {
        return Err(format!(
            "belongs to cluster {:?}, not {cluster:?}",
            attrs.cluster
        ));
    }
    if fields.contains(&Field::NodeName) && attrs.node_name != node_name {
        return Err(format!(
            "was issued for node {:?}, not {node_name:?}",
            attrs.node_name
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("svidlet-recover-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_volume(root: &Path, pod_uid: &str, vol: &str, driver: &str) -> PathBuf {
        let dir = root
            .join("pods")
            .join(pod_uid)
            .join("volumes")
            .join("kubernetes.io~csi")
            .join(vol);
        fs::create_dir_all(dir.join("mount")).unwrap();
        fs::write(
            dir.join("vol_data.json"),
            format!(
                r#"{{"driverName":"{driver}","specVolID":"{vol}","volumeHandle":"csi-{pod_uid}-{vol}","volumeLifecycleMode":"Ephemeral"}}"#
            ),
        )
        .unwrap();
        dir.join("mount")
    }

    #[test]
    fn discovers_only_this_drivers_volumes() {
        let root = scratch("discover");
        let mine = write_volume(&root, "pod-a", "svid", "csi.svidlet.io");
        write_volume(&root, "pod-b", "other", "ebs.csi.aws.com");

        // A pod with no CSI volumes at all must not break the walk.
        fs::create_dir_all(root.join("pods").join("pod-c").join("volumes")).unwrap();
        // Nor must an unparsable record.
        let broken = root.join("pods/pod-d/volumes/kubernetes.io~csi/bad");
        fs::create_dir_all(&broken).unwrap();
        fs::write(broken.join("vol_data.json"), "{not json").unwrap();

        let found = discover(&root, "csi.svidlet.io");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].target_path, mine);
        assert_eq!(found[0].volume_id, "csi-pod-a-svid");
        assert_eq!(found[0].pod_uid, "pod-a");

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn missing_kubelet_root_yields_nothing() {
        assert!(discover(Path::new("/nonexistent/kubelet"), "csi.svidlet.io").is_empty());
    }
}
