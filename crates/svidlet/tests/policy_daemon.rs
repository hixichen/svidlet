//! `svidlet-policy` against volumes that svidlet published.
//!
//! The two processes share no state and no IPC. The whole interface is the
//! volume: svidlet writes `tls.crt`, the daemon reads it to learn the identity,
//! and the daemon writes `policy/` beside it. These tests exercise exactly that
//! boundary — nothing here holds a Vault credential, because the daemon never
//! has one.

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use rcgen::{
    CertificateParams, DistinguishedName, DnType, Issuer as CaIssuer, KeyPair, KeyUsagePurpose,
    SanType,
};

use svidlet::config::PolicyConfig;
use svidlet::policy::daemon::Daemon;
use svidlet::policy::testkit::test_config;
use svidlet::policy::{PolicyBundle, PolicyDocument, PolicyManager};
use svidlet::volume::{self, Identity, Modes};

const MODES: Modes = Modes {
    key: 0o640,
    cert: 0o644,
    key_gid: None,
};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "svidlet-daemon-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// Stand in for svidlet: publish a certificate for `spiffe_id` into a volume at
/// the path the kubelet would use, with the record the kubelet writes.
fn publish_certificate(root: &Path, pod_uid: &str, spiffe_id: &str) -> PathBuf {
    let dir = root
        .join("pods")
        .join(pod_uid)
        .join("volumes/kubernetes.io~csi/svid");
    let target = dir.join("mount");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(
        dir.join("vol_data.json"),
        format!(
            r#"{{"driverName":"csi.svidlet.io","specVolID":"svid","volumeHandle":"csi-{pod_uid}"}}"#
        ),
    )
    .unwrap();

    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut ca_params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "test ca");
    ca_params.distinguished_name = dn;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca = ca_params.self_signed(&key).unwrap();
    let issuer = CaIssuer::from_ca_cert_pem(&ca.pem(), key).unwrap();

    let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut leaf = CertificateParams::default();
    leaf.distinguished_name = DistinguishedName::new();
    leaf.subject_alt_names = vec![SanType::URI(
        rcgen::string::Ia5String::try_from(spiffe_id).unwrap(),
    )];
    let cert = leaf.signed_by(&leaf_key, &issuer).unwrap();

    volume::publish_identity(
        &target,
        &Identity {
            key_pem: leaf_key.serialize_pem(),
            cert_chain_pem: cert.pem(),
            ca_pem: ca.pem(),
        },
        MODES,
    )
    .unwrap();
    target
}

fn config(root: &Path) -> PolicyConfig {
    let mut cfg = test_config(Some("http://policy.invalid:9000"));
    cfg.kubelet_root = root.to_path_buf();
    cfg.trust_domain = "example.org".into();
    cfg.cluster = "a".into();
    cfg
}

fn daemon_for(cfg: PolicyConfig) -> (Arc<Daemon>, Arc<PolicyManager>) {
    let policy = PolicyManager::new(cfg.clone());
    let daemon = Daemon::new(cfg, policy.clone(), None).unwrap();
    (daemon, policy)
}

fn bundle(revision: &str, docs: &[(&str, &str)]) -> PolicyBundle {
    PolicyBundle::build(
        revision.into(),
        docs.iter()
            .map(|(n, c)| PolicyDocument {
                name: (*n).into(),
                content: c.as_bytes().to_vec(),
            })
            .collect(),
    )
    .unwrap()
}

const API: &str = "spiffe://example.org/cluster/a/ns/payments/sa/api";
const WEB: &str = "spiffe://example.org/cluster/a/ns/default/sa/web";

#[test]
fn the_daemon_learns_identities_from_the_certificates_svidlet_wrote() {
    let root = scratch("discover");
    let api = publish_certificate(&root, "pod-a", API);
    let web = publish_certificate(&root, "pod-b", WEB);

    let (daemon, policy) = daemon_for(config(&root));
    let (appeared, gone) = daemon.scan();

    // Scanning subscribes, so a per-identity bundle can arrive for either.
    assert_eq!(policy.subscription_count(), 2);
    // No IPC: everything the daemon knows came from reading tls.crt.
    assert_eq!(appeared.len(), 2);
    assert!(appeared.contains(&API.to_string()));
    assert!(appeared.contains(&WEB.to_string()));
    assert!(gone.is_empty());
    assert_eq!(daemon.volume_count(), 2);

    let targets: Vec<PathBuf> = daemon.volumes().into_iter().map(|v| v.target).collect();
    assert!(targets.contains(&api));
    assert!(targets.contains(&web));

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn policy_is_written_beside_the_certificate_it_belongs_to() {
    let root = scratch("write");
    let api = publish_certificate(&root, "pod-a", API);
    let web = publish_certificate(&root, "pod-b", WEB);

    let (daemon, policy) = daemon_for(config(&root));
    daemon.scan();

    // A per-identity bundle for one, the fleet bundle for the other.
    policy.apply(API, bundle("api-r1", &[("authz.rego", "api only")]));
    policy.apply_fleet(bundle("fleet-r1", &[("authz.rego", "everyone")]));

    assert_eq!(daemon.apply(), 2);
    assert_eq!(
        std::fs::read_to_string(api.join("policy/authz.rego")).unwrap(),
        "api only"
    );
    assert_eq!(
        std::fs::read_to_string(web.join("policy/authz.rego")).unwrap(),
        "everyone"
    );
    assert_eq!(volume::published_revision(&api).as_deref(), Some("api-r1"));
    assert_eq!(
        volume::published_revision(&web).as_deref(),
        Some("fleet-r1")
    );

    // A second pass rewrites nothing: the revisions already match.
    assert_eq!(daemon.apply(), 0);

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn the_daemon_never_touches_the_certificate_chain() {
    // The property the split rests on. This process has no Vault credential and
    // no reason to write these files; the layout means it structurally cannot
    // do so by accident.
    let root = scratch("no-touch");
    let target = publish_certificate(&root, "pod-a", API);
    let cert_before = std::fs::read_to_string(target.join("tls.crt")).unwrap();
    let key_before = std::fs::read_to_string(target.join("tls.key")).unwrap();

    let (daemon, policy) = daemon_for(config(&root));
    daemon.scan();
    for revision in ["r1", "r2", "r3"] {
        policy.apply_fleet(bundle(revision, &[("authz.rego", revision)]));
        daemon.apply();
    }

    assert_eq!(
        std::fs::read_to_string(target.join("tls.crt")).unwrap(),
        cert_before
    );
    assert_eq!(
        std::fs::read_to_string(target.join("tls.key")).unwrap(),
        key_before
    );
    assert_eq!(volume::published_revision(&target).as_deref(), Some("r3"));

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_pod_going_away_is_noticed_and_unsubscribed() {
    let root = scratch("gone");
    publish_certificate(&root, "pod-a", API);
    let web = publish_certificate(&root, "pod-b", WEB);

    let (daemon, policy) = daemon_for(config(&root));
    daemon.scan();
    assert_eq!(policy.subscription_count(), 2);

    // The kubelet tears the pod down.
    std::fs::remove_dir_all(web.parent().unwrap()).unwrap();
    let (appeared, gone) = daemon.scan();

    assert!(appeared.is_empty());
    assert_eq!(gone, vec![WEB.to_string()]);
    assert_eq!(daemon.volume_count(), 1);
    // And the backend is no longer asked for policy nobody will write.
    assert_eq!(policy.subscription_count(), 1);

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_volume_holding_a_foreign_identity_is_left_alone() {
    // A certificate this fleet's template would not produce gets no policy,
    // rather than being handed a bundle meant for somebody else.
    let root = scratch("foreign");
    let ours = publish_certificate(&root, "pod-a", API);
    let theirs = publish_certificate(&root, "pod-b", "spiffe://other.example/cluster/z/ns/x/sa/y");

    let (daemon, policy) = daemon_for(config(&root));
    let (appeared, _) = daemon.scan();
    assert_eq!(appeared, vec![API.to_string()]);

    policy.apply_fleet(bundle("r1", &[("authz.rego", "x")]));
    assert_eq!(daemon.apply(), 1);
    assert!(ours.join("policy").exists());
    assert!(!theirs.join("policy").exists());

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn an_id_pattern_gates_which_volumes_receive_policy() {
    let root = scratch("pattern");
    let payments = publish_certificate(&root, "pod-a", API);
    let default = publish_certificate(&root, "pod-b", WEB);

    let mut cfg = config(&root);
    cfg.spiffe_id_pattern = Some(r"spiffe://example\.org/cluster/a/ns/payments/sa/.+".into());
    let (daemon, policy) = daemon_for(cfg);

    let (appeared, _) = daemon.scan();
    assert_eq!(appeared, vec![API.to_string()]);

    policy.apply_fleet(bundle("r1", &[("authz.rego", "x")]));
    daemon.apply();
    assert!(payments.join("policy").exists());
    assert!(!default.join("policy").exists());

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_volume_without_a_certificate_yet_is_skipped_quietly() {
    // svidlet mounts the tmpfs before it has a signature, so the daemon will
    // routinely see an empty volume. That is not an error.
    let root = scratch("no-cert");
    let dir = root.join("pods/pod-a/volumes/kubernetes.io~csi/svid");
    std::fs::create_dir_all(dir.join("mount")).unwrap();
    std::fs::write(
        dir.join("vol_data.json"),
        r#"{"driverName":"csi.svidlet.io","specVolID":"svid","volumeHandle":"csi-a"}"#,
    )
    .unwrap();

    let (daemon, _policy) = daemon_for(config(&root));
    let (appeared, gone) = daemon.scan();

    assert!(appeared.is_empty() && gone.is_empty());
    assert_eq!(daemon.volume_count(), 0);
    assert_eq!(daemon.metrics.unreadable_volumes.load(Ordering::Relaxed), 1);

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn other_drivers_volumes_are_not_touched() {
    let root = scratch("other-driver");
    let dir = root.join("pods/pod-a/volumes/kubernetes.io~csi/data");
    std::fs::create_dir_all(dir.join("mount")).unwrap();
    std::fs::write(
        dir.join("vol_data.json"),
        r#"{"driverName":"ebs.csi.aws.com","specVolID":"data","volumeHandle":"vol-1"}"#,
    )
    .unwrap();

    let (daemon, _policy) = daemon_for(config(&root));
    assert_eq!(daemon.scan(), (vec![], vec![]));
    assert_eq!(daemon.volume_count(), 0);

    std::fs::remove_dir_all(&root).unwrap();
}

#[tokio::test]
async fn the_run_loop_converges_a_node_on_its_own() {
    let root = scratch("run-loop");
    let target = publish_certificate(&root, "pod-a", API);

    let mut cfg = config(&root);
    cfg.scan_interval = Duration::from_millis(20);
    let (daemon, policy) = daemon_for(cfg);
    policy.subscribe(API);
    policy.apply_fleet(bundle("r1", &[("authz.rego", "allow")]));

    let running = tokio::spawn(svidlet::policy::daemon::run_loop(daemon.clone()));
    let _ = &policy;
    for _ in 0..100 {
        if volume::published_revision(&target).as_deref() == Some("r1") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    running.abort();

    assert_eq!(volume::published_revision(&target).as_deref(), Some("r1"));
    assert_eq!(
        std::fs::read_to_string(target.join("policy/authz.rego")).unwrap(),
        "allow"
    );
    assert!(daemon.metrics.scans.load(Ordering::Relaxed) > 0);

    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn the_metrics_endpoint_reports_what_this_process_owns() {
    let root = scratch("metrics");
    publish_certificate(&root, "pod-a", API);
    let (daemon, _policy) = daemon_for(config(&root));
    daemon.scan();

    let response = svidlet::policy::daemon::respond("GET /metrics HTTP/1.1", &daemon);
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(response.contains("svidlet_policy_volumes 1"));
    assert!(response.contains("svidlet_policy_scans_total 1"));
    // The rollout series exist even with no bundle source configured, so a
    // dashboard does not break when one is switched on.
    assert!(response.contains("svidlet_bundle_rejected_total{reason=\"signature\"} 0"));
    assert!(response.contains("svidlet_bundle_age_seconds NaN"));

    // Every non-comment line must parse as Prometheus text.
    let body = response.split_once("\r\n\r\n").unwrap().1;
    for line in body
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let (_, value) = line
            .rsplit_once(' ')
            .unwrap_or_else(|| panic!("no value: {line}"));
        assert!(
            value == "NaN" || value.parse::<f64>().is_ok(),
            "unparsable: {line}"
        );
    }

    assert!(
        svidlet::policy::daemon::respond("GET /healthz HTTP/1.1", &daemon)
            .starts_with("HTTP/1.1 200 OK")
    );
    assert!(
        svidlet::policy::daemon::respond("GET /nope HTTP/1.1", &daemon).starts_with("HTTP/1.1 404")
    );

    std::fs::remove_dir_all(&root).unwrap();
}

// ------------------------------------------------ policy over a real stream

mod stream {
    //! The daemon against a real gRPC policy backend, over a real socket.

    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Mutex;
    use tokio::sync::mpsc;
    use tokio_stream::wrappers::{TcpListenerStream, UnboundedReceiverStream};
    use tokio_stream::StreamExt;
    use tonic::{Response, Status, Streaming};

    use svidlet::policy::proto::policy_service_server::{PolicyService, PolicyServiceServer};
    use svidlet::policy::proto::{
        watch_request, PolicyDocument as ProtoDocument, PolicyUpdate, WatchRequest,
    };

    #[derive(Clone)]
    struct Backend {
        subscribes: Arc<AtomicUsize>,
        revision: Arc<Mutex<String>>,
    }

    #[tonic::async_trait]
    impl PolicyService for Backend {
        type WatchStream = UnboundedReceiverStream<Result<PolicyUpdate, Status>>;

        async fn watch(
            &self,
            request: tonic::Request<Streaming<WatchRequest>>,
        ) -> Result<Response<Self::WatchStream>, Status> {
            let mut inbound = request.into_inner();
            let (tx, rx) = mpsc::unbounded_channel();
            let subscribes = self.subscribes.clone();
            let revision = self.revision.clone();

            tokio::spawn(async move {
                while let Some(Ok(message)) = inbound.next().await {
                    let Some(watch_request::Request::Subscribe(sub)) = message.request else {
                        continue;
                    };
                    subscribes.fetch_add(1, Ordering::SeqCst);
                    let update = PolicyUpdate {
                        spiffe_id: sub.spiffe_id,
                        revision: revision.lock().unwrap().clone(),
                        documents: vec![ProtoDocument {
                            name: "authz.rego".into(),
                            content: b"allow := true".to_vec(),
                        }],
                        empty: false,
                    };
                    if tx.send(Ok(update)).is_err() {
                        return;
                    }
                }
            });
            Ok(Response::new(UnboundedReceiverStream::new(rx)))
        }
    }

    #[tokio::test]
    async fn a_certificate_appearing_pulls_its_policy_over_the_stream() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        let subscribes = Arc::new(AtomicUsize::new(0));
        let backend = Backend {
            subscribes: subscribes.clone(),
            revision: Arc::new(Mutex::new("git-r1".into())),
        };
        let server = tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(PolicyServiceServer::new(backend))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await;
        });

        let root = scratch("stream");
        let target = publish_certificate(&root, "pod-a", API);

        let mut cfg = config(&root);
        cfg.stream.endpoint = Some(addr);
        cfg.scan_interval = Duration::from_millis(20);
        let (daemon, policy) = daemon_for(cfg);

        // The whole chain: scan finds the certificate svidlet wrote, subscribes
        // for that identity, the backend answers, and the bundle lands beside
        // the certificate.
        let watcher = tokio::spawn(svidlet::policy::grpc::watch_loop(
            policy.clone(),
            "node-1".into(),
        ));
        let running = tokio::spawn(svidlet::policy::daemon::run_loop(daemon.clone()));

        // Watch the path a workload watches, not svidlet's internal one.
        for _ in 0..200 {
            if target.join("policy/authz.rego").exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        running.abort();
        watcher.abort();
        server.abort();

        assert_eq!(
            volume::published_revision(&target).as_deref(),
            Some("git-r1")
        );
        assert_eq!(
            std::fs::read_to_string(target.join("policy/authz.rego")).unwrap(),
            "allow := true"
        );
        assert!(subscribes.load(Ordering::SeqCst) >= 1);
        // The certificate is untouched: this process never writes that chain.
        assert!(target.join("tls.crt").exists());

        std::fs::remove_dir_all(&root).unwrap();
    }
}
