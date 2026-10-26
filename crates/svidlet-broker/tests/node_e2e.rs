//! The whole v0.2 path on one machine: the node plugin's CSI service in
//! broker mode, publishing a real volume, talking over TLS to an in-process
//! broker backed by a fake API server and fake Vault engines.
//!
//! Run as root: the plugin mounts a real tmpfs per volume, as on a node.

mod common;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::*;
use svidlet::config::{volume_context as vc, Config};
use svidlet::csi::node::NodeService;
use svidlet::csi::proto::csi::node_server::Node;
use svidlet::csi::proto::csi::{NodePublishVolumeRequest, NodeUnpublishVolumeRequest};
use svidlet::issue::Publisher;
use svidlet::metrics::Metrics;
use svidlet::store::{PodToken, Store};
use svidlet::{renew, volume};
use svidlet_issue::{BrokerClient, BrokerEndpoint};
use tonic::{Code, Request};

struct TestNode {
    publisher: Arc<Publisher>,
    service: NodeService,
    root: PathBuf,
}

fn node(r: &Running, name: &str) -> TestNode {
    let root = r.dir.join(format!("node-{name}"));
    std::fs::create_dir_all(&root).unwrap();
    let vars: HashMap<&str, String> = HashMap::from([
        ("NODE_NAME", "n1".to_string()),
        ("SVIDLET_CLUSTER", CLUSTER.into()),
        ("SVIDLET_TRUST_DOMAIN", TD.into()),
        ("SVIDLET_ISSUER", "broker".into()),
        ("SVIDLET_BROKER_URL", r.sign_url.clone()),
        ("SVIDLET_BROKER_TOKEN_URL", r.token_url.clone()),
        (
            "SVIDLET_BROKER_CACERT",
            r.dir.join("ca.crt").display().to_string(),
        ),
        (
            "SVIDLET_BROKER_TOKEN_FILE",
            r.dir.join("node-token").display().to_string(),
        ),
        ("SVIDLET_KUBELET_ROOT", root.display().to_string()),
        (
            "SVIDLET_VOLUMES_DIR",
            root.join("farm").display().to_string(),
        ),
        ("SVIDLET_CERT_TTL", "48h".into()),
    ]);
    let cfg = Arc::new(Config::from_source(&|k| vars.get(k).cloned()).unwrap());
    let b = cfg.broker.clone().unwrap();
    let client = Arc::new(
        BrokerClient::new(BrokerEndpoint {
            sign_url: b.sign_url,
            token_url: b.token_url,
            ca_cert_pem: std::fs::read_to_string(&b.ca_cert_path).unwrap(),
            node_token_path: b.node_token_path,
            timeout: b.timeout,
        })
        .unwrap(),
    );
    let publisher = Arc::new(
        Publisher::new(
            cfg.clone(),
            Arc::new(cfg.id_policy().unwrap()),
            client.clone(),
            Arc::new(Store::new()),
            Arc::new(Metrics::default()),
        )
        .with_broker(client),
    );
    TestNode {
        service: NodeService::new(publisher.clone()),
        publisher,
        root,
    }
}

fn request(
    target: &Path,
    pod_token: Option<&str>,
    name: &str,
    uid: &str,
) -> NodePublishVolumeRequest {
    let mut ctx = HashMap::from([
        (vc::EPHEMERAL.to_string(), "true".to_string()),
        (vc::POD_NAMESPACE.into(), "payments".into()),
        (vc::SERVICE_ACCOUNT.into(), "api".into()),
        (vc::POD_NAME.into(), name.into()),
        (vc::POD_UID.into(), uid.into()),
    ]);
    if let Some(t) = pod_token {
        ctx.insert(
            vc::SERVICE_ACCOUNT_TOKENS.into(),
            serde_json::json!({ "svidlet-broker": { "token": t, "expirationTimestamp": "2026-10-26T00:10:00Z" } })
                .to_string(),
        );
    }
    NodePublishVolumeRequest {
        volume_id: format!("csi-{name}"),
        target_path: target.display().to_string(),
        readonly: true,
        volume_context: ctx,
    }
}

async fn unpublish(n: &TestNode, target: &Path) {
    n.service
        .node_unpublish_volume(Request::new(NodeUnpublishVolumeRequest {
            volume_id: "v".into(),
            target_path: target.display().to_string(),
        }))
        .await
        .unwrap();
}

fn spiffe_id_on_disk(target: &Path) -> String {
    let chain = std::fs::read_to_string(target.join("tls.crt")).unwrap();
    svidlet_issue::inspect(&chain)
        .unwrap()
        .spiffe_id
        .to_string()
}

#[tokio::test]
async fn a_published_volume_holds_the_certificate_and_every_approved_token() {
    let r = start_broker("node-publish", fixture()).await;
    let n = node(&r, "publish");
    let target = n.root.join("pods/api-0/volumes/svid");

    n.service
        .node_publish_volume(Request::new(request(
            &target,
            Some(POD_TOKEN),
            "api-0",
            "uid-api-0",
        )))
        .await
        .unwrap();

    assert_eq!(spiffe_id_on_disk(&target), id("payments", "api"));
    // The key on disk is the key the certificate is for.
    let identity = volume::read_identity(&target).unwrap();
    let key = rcgen::KeyPair::from_pem(&identity.key_pem).unwrap();
    assert_eq!(
        svidlet_issue::leaf_public_key(&identity.cert_chain_pem).unwrap(),
        key.public_key_raw()
    );
    // §6.2 file mode: one file per approved audience, each a JWT for this SAN.
    let tokens = volume::read_tokens(&target);
    assert_eq!(tokens.keys().collect::<Vec<_>>(), vec!["aws", "vault"]);
    for (alias, jwt) in &tokens {
        let u = svidlet_issue::jwt::decode_unverified(jwt).unwrap();
        assert_eq!(u.claims.sub, id("payments", "api"), "{alias}");
    }
    assert_eq!(
        std::fs::read_to_string(target.join("jwt/vault")).unwrap(),
        tokens["vault"]
    );
    assert_eq!(*r.ca.signed.lock().unwrap(), vec![id("payments", "api")]);

    unpublish(&n, &target).await;
    assert!(!target.exists());
    std::fs::remove_dir_all(&r.dir).unwrap();
}

#[tokio::test]
async fn a_republish_only_refreshes_the_pod_token_and_renewal_uses_it() {
    let r = start_broker("node-renew", fixture()).await;
    let n = node(&r, "renew");
    let target = n.root.join("pods/api-0/volumes/svid");
    n.service
        .node_publish_volume(Request::new(request(
            &target,
            Some(POD_TOKEN),
            "api-0",
            "uid-api-0",
        )))
        .await
        .unwrap();
    let first = std::fs::read_to_string(target.join("tls.crt")).unwrap();

    // The kubelet republishes about every minute with a fresh token (§5.2).
    r.kube.add_pod(
        "pod-token-api-2",
        "payments",
        "api",
        "api-0",
        "uid-api-0",
        "n1",
    );
    n.service
        .node_publish_volume(Request::new(request(
            &target,
            Some("pod-token-api-2"),
            "api-0",
            "uid-api-0",
        )))
        .await
        .unwrap();
    let entry = n.publisher.store.get(&target).unwrap();
    assert_eq!(entry.pod_token, Some(PodToken("pod-token-api-2".into())));
    assert_eq!(
        r.ca.signed.lock().unwrap().len(),
        1,
        "a republish issues nothing"
    );

    // The old token stops validating; renewal works on the cached new one.
    r.kube.reviews.lock().unwrap().remove(POD_TOKEN);
    let p = n.publisher.clone();
    tokio::task::spawn_blocking(move || renew::renew_one(&p, &entry))
        .await
        .unwrap();
    assert_eq!(r.ca.signed.lock().unwrap().len(), 2);
    let renewed = std::fs::read_to_string(target.join("tls.crt")).unwrap();
    assert_ne!(first, renewed);
    assert_eq!(n.publisher.store.get(&target).unwrap().failures, 0);

    unpublish(&n, &target).await;
    std::fs::remove_dir_all(&r.dir).unwrap();
}

#[tokio::test]
async fn a_deleted_pod_cannot_renew_and_keeps_its_current_files() {
    let r = start_broker("node-deleted", fixture()).await;
    let n = node(&r, "deleted");
    let target = n.root.join("pods/api-0/volumes/svid");
    n.service
        .node_publish_volume(Request::new(request(
            &target,
            Some(POD_TOKEN),
            "api-0",
            "uid-api-0",
        )))
        .await
        .unwrap();
    let before = std::fs::read_to_string(target.join("tls.crt")).unwrap();

    r.kube
        .pods
        .lock()
        .unwrap()
        .remove(&("payments".into(), "api-0".into()));
    let entry = n.publisher.store.get(&target).unwrap();
    let p = n.publisher.clone();
    tokio::task::spawn_blocking(move || renew::renew_one(&p, &entry))
        .await
        .unwrap();

    // Refused (I4), backed off, and fail stale: the old certificate stays.
    assert_eq!(n.publisher.store.get(&target).unwrap().failures, 1);
    assert_eq!(
        std::fs::read_to_string(target.join("tls.crt")).unwrap(),
        before
    );

    unpublish(&n, &target).await;
    std::fs::remove_dir_all(&r.dir).unwrap();
}

#[tokio::test]
async fn refusals_reach_the_kubelet_with_the_right_code_and_leave_nothing_behind() {
    let r = start_broker("node-refusals", fixture()).await;
    let n = node(&r, "refusals");

    // No tokenRequests on the CSIDriver: refused before anything is sent.
    let t1 = n.root.join("pods/a/volumes/svid");
    let e = n
        .service
        .node_publish_volume(Request::new(request(&t1, None, "api-0", "uid-api-0")))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::InvalidArgument);

    // A pod scheduled on another node: I3.
    r.kube
        .add_pod("t-elsewhere", "payments", "api", "api-1", "uid-api-1", "n2");
    let t2 = n.root.join("pods/b/volumes/svid");
    let e = n
        .service
        .node_publish_volume(Request::new(request(
            &t2,
            Some("t-elsewhere"),
            "api-1",
            "uid-api-1",
        )))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::PermissionDenied);
    assert!(e.message().contains("I3"), "{}", e.message());
    assert!(!t2.join("tls.crt").exists(), "nothing half-published");

    // An API-server outage is retryable for the kubelet.
    *r.kube.down.lock().unwrap() = true;
    let t3 = n.root.join("pods/c/volumes/svid");
    let e = n
        .service
        .node_publish_volume(Request::new(request(
            &t3,
            Some(POD_TOKEN),
            "api-0",
            "uid-api-0",
        )))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::Unavailable);
    assert!(r.ca.signed.lock().unwrap().is_empty());
    std::fs::remove_dir_all(&r.dir).unwrap();
}

#[tokio::test]
async fn an_emergency_key_rotation_reaches_the_volume_on_the_next_check_in() {
    let r = start_broker("node-rotate", fixture()).await;
    let n = node(&r, "rotate");
    let target = n.root.join("pods/api-0/volumes/svid");
    n.service
        .node_publish_volume(Request::new(request(
            &target,
            Some(POD_TOKEN),
            "api-0",
            "uid-api-0",
        )))
        .await
        .unwrap();
    let before = volume::read_tokens(&target);

    // Nothing changed: a check-in rewrites nothing.
    assert_eq!(renew::refresh_tokens_once(n.publisher.clone()).await, 0);

    // Retire k1 (§9): Vault signs with k2, k1 leaves the public JWKS. The
    // broker's housekeeping would pick that up; here it is refreshed directly.
    *r.minter.kid.lock().unwrap() = "k2".into();
    *r.minter.published.lock().unwrap() = vec!["k2".into()];
    r.broker.tokens.jwks.refresh().unwrap();

    assert_eq!(renew::refresh_tokens_once(n.publisher.clone()).await, 1);
    let after = volume::read_tokens(&target);
    assert_eq!(
        after.keys().collect::<Vec<_>>(),
        before.keys().collect::<Vec<_>>()
    );
    for jwt in after.values() {
        assert_eq!(
            svidlet_issue::jwt::decode_unverified(jwt)
                .unwrap()
                .header
                .kid,
            "k2"
        );
    }

    unpublish(&n, &target).await;
    std::fs::remove_dir_all(&r.dir).unwrap();
}
