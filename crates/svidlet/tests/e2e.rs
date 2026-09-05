//! End-to-end test of the node plugin against a real signing CA.
//!
//! Everything below the gRPC method is the production path: the same
//! `NodeService`, `Publisher`, `Store` and volume writer the DaemonSet runs.
//! Only the PKI backend is local — a `TestCa` that parses the CSR svidlet
//! produced and signs it the way Vault would.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rcgen::{
    CertificateParams, CertificateSigningRequestParams, DistinguishedName, DnType, Issuer, KeyPair,
    KeyUsagePurpose,
};
use time::OffsetDateTime;
use tonic::Request;

use svidlet::config::{
    volume_context as vc, AuthSettings, Config, PolicySettings, VaultSettings, CA_FILE, CERT_FILE,
    KEY_FILE, REVISION_FILE,
};
use svidlet::csi::node::NodeService;
use svidlet::csi::proto::csi::node_server::Node;
use svidlet::csi::proto::csi::{NodePublishVolumeRequest, NodeUnpublishVolumeRequest};
use svidlet::issue::Publisher;
use svidlet::metrics::Metrics;
use svidlet::policy::{PolicyBundle, PolicyDocument, PolicyManager};
use svidlet::store::Store;
use svidlet_issue::{IdTemplate, IssuedBundle, SignRequest};

// ---------------------------------------------------------------- test backend

/// A signing CA that stands in for Vault PKI.
struct TestCa {
    issuer: Issuer<'static, KeyPair>,
    ca_pem: String,
    lifetime_secs: i64,
    /// Every SPIFFE ID it was asked to sign, in order.
    signed: Mutex<Vec<String>>,
    /// When set, `sign` fails — used to prove a failed renewal leaves the
    /// existing certificate in place.
    fail: Mutex<Option<String>>,
}

impl TestCa {
    fn new(lifetime_secs: i64) -> Self {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "svidlet test intermediate");
        params.distinguished_name = dn;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let cert = params.self_signed(&key).unwrap();

        TestCa {
            ca_pem: cert.pem(),
            issuer: Issuer::from_ca_cert_pem(&cert.pem(), key).unwrap(),
            lifetime_secs,
            signed: Mutex::new(Vec::new()),
            fail: Mutex::new(None),
        }
    }

    fn signed_ids(&self) -> Vec<String> {
        self.signed.lock().unwrap().clone()
    }

    fn break_signing(&self, why: &str) {
        *self.fail.lock().unwrap() = Some(why.to_string());
    }
}

impl svidlet_issue::Issuer for TestCa {
    fn sign(&self, request: &SignRequest<'_>) -> svidlet_issue::Result<IssuedBundle> {
        if let Some(why) = self.fail.lock().unwrap().clone() {
            return Err(svidlet_issue::Error::Transport(why));
        }
        assert!(
            !request.node_name.is_empty(),
            "the backend is told which node asked"
        );
        assert!(
            request.ttl > std::time::Duration::ZERO,
            "a lifetime is requested"
        );

        // Parsing verifies the CSR's self-signature, exactly as Vault does.
        let mut csr = CertificateSigningRequestParams::from_pem(request.csr_pem)
            .map_err(|e| svidlet_issue::Error::Protocol(e.to_string()))?;

        let now = OffsetDateTime::now_utc();
        csr.params.not_before = now;
        csr.params.not_after = now + time::Duration::seconds(self.lifetime_secs);

        let cert = csr
            .signed_by(&self.issuer)
            .map_err(|e| svidlet_issue::Error::Protocol(e.to_string()))?;

        self.signed
            .lock()
            .unwrap()
            .push(request.spiffe_id.to_string());
        let chain = cert.pem();
        let facts = svidlet_issue::assert_identity(&chain, request.spiffe_id)?;
        Ok(IssuedBundle {
            cert_chain_pem: chain,
            ca_pem: self.ca_pem.clone(),
            not_after: facts.not_after,
            not_before: facts.not_before,
        })
    }

    fn ca_chain(&self) -> svidlet_issue::Result<String> {
        Ok(self.ca_pem.clone())
    }

    fn name(&self) -> &'static str {
        "test-ca"
    }

    fn auth_name(&self) -> &'static str {
        "none"
    }
}

// -------------------------------------------------------------------- fixtures

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "svidlet-e2e-{name}-{}-{}",
        std::process::id(),
        svidlet::log::unix_now()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn config(kubelet_root: &Path) -> Config {
    config_with(
        kubelet_root,
        IdTemplate::DEFAULT,
        None,
        policy_settings(None),
    )
}

/// Policy is off unless a test asks for it.
fn policy_settings(endpoint: Option<&str>) -> PolicySettings {
    PolicySettings {
        enabled: true,
        bundle: None,
        endpoint: endpoint.map(str::to_string),
        ca_cert_path: None,
        token_path: None,
        required: false,
        initial_timeout: std::time::Duration::from_millis(100),
        directory: "policy".into(),
        reconnect_backoff: std::time::Duration::from_millis(10),
    }
}

fn config_with(
    kubelet_root: &Path,
    template: &str,
    pattern: Option<&str>,
    policy: PolicySettings,
) -> Config {
    Config {
        driver_name: "csi.svidlet.io".into(),
        node_name: "node-1".into(),
        trust_domain: "example.org".into(),
        cluster: "a".into(),
        csi_socket: kubelet_root.join("csi.sock"),
        registration_socket: kubelet_root.join("reg.sock"),
        advertised_endpoint: "/var/lib/kubelet/plugins/csi.svidlet.io/csi.sock".into(),
        kubelet_root: kubelet_root.to_path_buf(),
        spiffe_id_template: template.to_string(),
        spiffe_id_pattern: pattern.map(str::to_string),
        vault: VaultSettings {
            address: "https://vault.invalid".into(),
            namespace: None,
            ca_cert_path: None,
            timeout: std::time::Duration::from_secs(5),
            pki_mount: "pki".into(),
            pki_role: "spiffe-a".into(),
            auth: AuthSettings::Token {
                path: PathBuf::from("/dev/null"),
            },
        },
        policy,
        cert_ttl: std::time::Duration::from_secs(3600),
        renew_fraction: (0.5, 0.7),
        renew_check_interval: std::time::Duration::from_secs(30),
        startup_spread: std::time::Duration::from_secs(300),
        ca_refresh_interval: std::time::Duration::from_secs(3600),
        tmpfs_size: "1m".into(),
        key_mode: 0o640,
        cert_mode: 0o644,
        metrics_addr: String::new(),
        log_level: svidlet::log::Level::Warn,
    }
}

struct Fixture {
    publisher: Arc<Publisher>,
    node: NodeService,
    ca: Arc<TestCa>,
    store: Arc<Store>,
    policy: Arc<PolicyManager>,
    root: PathBuf,
}

fn fixture(name: &str, lifetime_secs: i64) -> Fixture {
    fixture_with(
        name,
        lifetime_secs,
        IdTemplate::DEFAULT,
        None,
        policy_settings(None),
    )
}

fn fixture_with(
    name: &str,
    lifetime_secs: i64,
    template: &str,
    pattern: Option<&str>,
    policy_settings: PolicySettings,
) -> Fixture {
    svidlet::rand::seed();
    let root = scratch(name);
    let ca = Arc::new(TestCa::new(lifetime_secs));
    let store = Arc::new(Store::new());
    let cfg = config_with(&root, template, pattern, policy_settings);
    let id_policy = Arc::new(cfg.id_policy().expect("the template compiles"));
    let policy = PolicyManager::new(cfg.policy.clone());
    let publisher = Arc::new(Publisher::new(
        Arc::new(cfg),
        id_policy,
        ca.clone(),
        store.clone(),
        Arc::new(Metrics::default()),
        policy.clone(),
    ));
    publisher.prime_ca().unwrap();
    Fixture {
        node: NodeService::new(publisher.clone()),
        publisher,
        ca,
        store,
        policy,
        root,
    }
}

/// A publish request shaped the way the kubelet sends one for an inline
/// ephemeral volume when the CSIDriver sets `podInfoOnMount: true`.
fn publish_request(
    target: &Path,
    namespace: &str,
    service_account: &str,
) -> NodePublishVolumeRequest {
    let mut ctx = std::collections::HashMap::new();
    ctx.insert(vc::EPHEMERAL.into(), "true".into());
    ctx.insert(vc::POD_NAME.into(), "web-0".into());
    ctx.insert(vc::POD_NAMESPACE.into(), namespace.into());
    ctx.insert(
        vc::POD_UID.into(),
        "11111111-2222-3333-4444-555555555555".into(),
    );
    ctx.insert(vc::SERVICE_ACCOUNT.into(), service_account.into());

    NodePublishVolumeRequest {
        volume_id: "csi-abcdef".into(),
        target_path: target.display().to_string(),
        readonly: true,
        volume_context: ctx,
    }
}

fn published_spiffe_id(target: &Path) -> String {
    let chain = std::fs::read_to_string(target.join(CERT_FILE)).unwrap();
    svidlet_issue::inspect(&chain)
        .unwrap()
        .spiffe_id
        .to_string()
}

// ----------------------------------------------------------------------- tests

#[tokio::test]
async fn publish_issues_a_certificate_for_the_kubelet_supplied_identity() {
    let fx = fixture("publish", 3600);
    let target = fx.root.join("mount");

    fx.node
        .node_publish_volume(Request::new(publish_request(&target, "payments", "api")))
        .await
        .unwrap();

    // The three files a workload expects, all present and consistent.
    assert_eq!(
        published_spiffe_id(&target),
        "spiffe://example.org/cluster/a/ns/payments/sa/api"
    );
    let key = std::fs::read_to_string(target.join(KEY_FILE)).unwrap();
    assert!(key.starts_with("-----BEGIN PRIVATE KEY-----"));
    let ca = std::fs::read_to_string(target.join(CA_FILE)).unwrap();
    assert_eq!(ca, fx.ca.ca_pem);

    // The private key is not world readable; the certificate and CA are.
    use std::os::unix::fs::PermissionsExt;
    let mode = |name: &str| {
        std::fs::metadata(target.join("..data").join(name))
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(mode(KEY_FILE), 0o640);
    assert_eq!(mode(CERT_FILE), 0o644);

    // It is on the renewal list, due inside the configured window.
    let entry = fx.store.get(&target).unwrap();
    let lifetime = entry.not_after - entry.not_before;
    let offset = entry.renew_at - entry.not_before;
    assert!(
        offset >= lifetime / 2 && offset <= lifetime * 7 / 10,
        "renewal at {offset}s into a {lifetime}s lifetime"
    );

    std::fs::remove_dir_all(&fx.root).unwrap();
}

#[tokio::test]
async fn republishing_the_same_volume_does_not_mint_a_second_certificate() {
    let fx = fixture("republish", 3600);
    let target = fx.root.join("mount");
    let request = || publish_request(&target, "default", "web");

    fx.node
        .node_publish_volume(Request::new(request()))
        .await
        .unwrap();
    let first = std::fs::read_to_string(target.join(CERT_FILE)).unwrap();

    // The kubelet retries NodePublishVolume freely; a retry must be a no-op.
    fx.node
        .node_publish_volume(Request::new(request()))
        .await
        .unwrap();

    assert_eq!(fx.ca.signed_ids().len(), 1, "signed twice for one volume");
    assert_eq!(
        std::fs::read_to_string(target.join(CERT_FILE)).unwrap(),
        first
    );
    assert_eq!(fx.store.len(), 1);

    std::fs::remove_dir_all(&fx.root).unwrap();
}

#[tokio::test]
async fn identity_must_come_from_the_kubelet() {
    let fx = fixture("identity", 3600);
    let target = fx.root.join("mount");

    // No serviceAccount.name: the CSIDriver is missing podInfoOnMount, and
    // guessing an identity here is exactly what must not happen.
    let mut req = publish_request(&target, "default", "web");
    req.volume_context.remove(vc::SERVICE_ACCOUNT);
    let err = fx
        .node
        .node_publish_volume(Request::new(req))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("podInfoOnMount"));

    // A ServiceAccount name that would extend the SPIFFE path is refused.
    let mut req = publish_request(&target, "default", "web/ns/kube-system/sa/admin");
    req.volume_context.insert(
        vc::SERVICE_ACCOUNT.into(),
        "web/ns/kube-system/sa/admin".into(),
    );
    let err = fx
        .node
        .node_publish_volume(Request::new(req))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    // A non-ephemeral volume has no pod context to derive identity from.
    let mut req = publish_request(&target, "default", "web");
    req.volume_context.remove(vc::EPHEMERAL);
    let err = fx
        .node
        .node_publish_volume(Request::new(req))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    assert!(fx.ca.signed_ids().is_empty());
    std::fs::remove_dir_all(&fx.root).unwrap();
}

#[tokio::test]
async fn renewal_replaces_the_certificate_in_place() {
    let fx = fixture("renew", 3600);
    let target = fx.root.join("mount");
    fx.node
        .node_publish_volume(Request::new(publish_request(&target, "default", "web")))
        .await
        .unwrap();
    let before = std::fs::read_to_string(target.join(CERT_FILE)).unwrap();
    let key_before = std::fs::read_to_string(target.join(KEY_FILE)).unwrap();

    let entry = fx.store.get(&target).unwrap();
    svidlet::renew::renew_one(&fx.publisher, &entry);

    let after = std::fs::read_to_string(target.join(CERT_FILE)).unwrap();
    let key_after = std::fs::read_to_string(target.join(KEY_FILE)).unwrap();
    assert_ne!(before, after, "renewal did not replace the certificate");
    assert_ne!(key_before, key_after, "renewal reused the private key");
    assert_eq!(
        published_spiffe_id(&target),
        "spiffe://example.org/cluster/a/ns/default/sa/web"
    );
    assert_eq!(fx.ca.signed_ids().len(), 2);

    // The store now tracks the new certificate: a later expiry, a deadline
    // re-drawn inside the jitter window, and no failures recorded. The new
    // deadline is not necessarily later than the old one — jitter is redrawn
    // each time, and asserting otherwise would be flaky.
    let renewed = fx.store.get(&target).unwrap();
    assert!(renewed.not_after >= entry.not_after);
    let lifetime = renewed.not_after - renewed.not_before;
    let offset = renewed.renew_at - renewed.not_before;
    assert!(
        offset >= lifetime / 2 && offset <= lifetime * 7 / 10,
        "renewal at {offset}s into a {lifetime}s lifetime"
    );
    assert!(renewed.renew_at > svidlet::log::unix_now());
    assert_eq!(renewed.failures, 0);

    std::fs::remove_dir_all(&fx.root).unwrap();
}

#[tokio::test]
async fn a_failed_renewal_keeps_the_existing_certificate() {
    let fx = fixture("outage", 3600);
    let target = fx.root.join("mount");
    fx.node
        .node_publish_volume(Request::new(publish_request(&target, "default", "web")))
        .await
        .unwrap();
    let before = std::fs::read_to_string(target.join(CERT_FILE)).unwrap();

    fx.ca.break_signing("vault is sealed");
    let entry = fx.store.get(&target).unwrap();
    svidlet::renew::renew_one(&fx.publisher, &entry);

    // The workload keeps a valid certificate; only the deadline moved.
    assert_eq!(
        std::fs::read_to_string(target.join(CERT_FILE)).unwrap(),
        before
    );
    let after = fx.store.get(&target).unwrap();
    assert_eq!(after.failures, 1);
    assert!(after.renew_at > svidlet::log::unix_now());
    assert_eq!(after.not_after, entry.not_after);

    std::fs::remove_dir_all(&fx.root).unwrap();
}

#[tokio::test]
async fn restart_recovery_adopts_without_re_issuing() {
    let fx = fixture("recover", 3600);
    // Publish into the path the kubelet would use, so discovery can find it.
    let target = fx
        .root
        .join("pods/11111111-2222-3333-4444-555555555555/volumes/kubernetes.io~csi/svid/mount");
    std::fs::create_dir_all(target.parent().unwrap()).unwrap();
    std::fs::write(
        target.parent().unwrap().join("vol_data.json"),
        r#"{"driverName":"csi.svidlet.io","specVolID":"svid","volumeHandle":"csi-abcdef","volumeLifecycleMode":"Ephemeral"}"#,
    )
    .unwrap();

    fx.node
        .node_publish_volume(Request::new(publish_request(&target, "payments", "api")))
        .await
        .unwrap();
    let cert = std::fs::read_to_string(target.join(CERT_FILE)).unwrap();
    let original = fx.store.get(&target).unwrap();

    // Restart: a brand-new store, same node, same disk.
    let restarted = Store::new();
    let adopted = svidlet::recover::adopt(
        &fx.publisher.cfg,
        &fx.publisher.policy,
        &restarted,
        &fx.publisher.metrics,
    );

    assert_eq!(adopted, 1);
    assert_eq!(
        fx.ca.signed_ids().len(),
        1,
        "restart re-issued; a rolling upgrade would become a signing storm"
    );
    assert_eq!(
        std::fs::read_to_string(target.join(CERT_FILE)).unwrap(),
        cert
    );

    let recovered = restarted.get(&target).unwrap();
    assert_eq!(recovered.spiffe_id, original.spiffe_id);
    assert_eq!(recovered.not_after, original.not_after);
    assert_eq!(recovered.volume_id, "csi-abcdef");

    std::fs::remove_dir_all(&fx.root).unwrap();
}

#[tokio::test]
async fn recovery_spreads_certificates_that_are_already_due() {
    // A certificate this old is past its renewal point the moment it is
    // adopted. Every node in a fleet upgrading at once would otherwise renew
    // in the same tick.
    let fx = fixture("spread", 2);
    let target = fx
        .root
        .join("pods/aaaa/volumes/kubernetes.io~csi/svid/mount");
    std::fs::create_dir_all(target.parent().unwrap()).unwrap();
    std::fs::write(
        target.parent().unwrap().join("vol_data.json"),
        r#"{"driverName":"csi.svidlet.io","specVolID":"svid","volumeHandle":"csi-x"}"#,
    )
    .unwrap();
    fx.node
        .node_publish_volume(Request::new(publish_request(&target, "default", "web")))
        .await
        .unwrap();

    let now = svidlet::log::unix_now();
    let store = Store::new();
    assert_eq!(
        svidlet::recover::adopt(
            &fx.publisher.cfg,
            &fx.publisher.policy,
            &store,
            &fx.publisher.metrics
        ),
        1
    );

    let entry = store.get(&target).unwrap();
    assert!(
        entry.renew_at >= now,
        "an overdue certificate renewed immediately"
    );
    assert!(
        entry.renew_at <= now + fx.publisher.cfg.startup_spread.as_secs() as i64,
        "renewal pushed beyond the startup spread window"
    );

    std::fs::remove_dir_all(&fx.root).unwrap();
}

#[tokio::test]
async fn a_changed_trust_bundle_reaches_running_pods() {
    let fx = fixture("ca-refresh", 3600);
    let target = fx.root.join("mount");
    fx.node
        .node_publish_volume(Request::new(publish_request(&target, "default", "web")))
        .await
        .unwrap();
    let cert_before = std::fs::read_to_string(target.join(CERT_FILE)).unwrap();

    // The trust domain adds a root: ca.crt must change without re-issuing.
    let rotated = Arc::new(TestCa::new(3600));
    let publisher = Arc::new(Publisher::new(
        fx.publisher.cfg.clone(),
        fx.publisher.policy.clone(),
        rotated.clone(),
        fx.store.clone(),
        Arc::new(Metrics::default()),
        fx.policy.clone(),
    ));
    assert_eq!(publisher.refresh_ca().unwrap(), 1);

    assert_eq!(
        std::fs::read_to_string(target.join(CA_FILE)).unwrap(),
        rotated.ca_pem
    );
    assert_eq!(
        std::fs::read_to_string(target.join(CERT_FILE)).unwrap(),
        cert_before,
        "ca.crt refresh must not disturb the leaf certificate"
    );
    assert!(rotated.signed_ids().is_empty());

    // A second refresh with an unchanged bundle rewrites nothing.
    assert_eq!(publisher.refresh_ca().unwrap(), 0);

    std::fs::remove_dir_all(&fx.root).unwrap();
}

#[tokio::test]
async fn unpublish_removes_the_volume_and_stops_renewal() {
    let fx = fixture("unpublish", 3600);
    let target = fx.root.join("mount");
    fx.node
        .node_publish_volume(Request::new(publish_request(&target, "default", "web")))
        .await
        .unwrap();
    assert_eq!(fx.store.len(), 1);

    let request = || {
        Request::new(NodeUnpublishVolumeRequest {
            volume_id: "csi-abcdef".into(),
            target_path: target.display().to_string(),
        })
    };
    fx.node.node_unpublish_volume(request()).await.unwrap();

    assert!(!target.exists());
    assert_eq!(fx.store.len(), 0);

    // The kubelet retries until it gets an OK, so this must be idempotent.
    fx.node.node_unpublish_volume(request()).await.unwrap();

    std::fs::remove_dir_all(&fx.root).unwrap();
}

// ------------------------------------------------------ customisable identity

#[tokio::test]
async fn a_custom_template_changes_the_shape_of_the_identity() {
    // The SPIRE / csi-driver-spiffe shape: no cluster segment.
    let fx = fixture_with(
        "template",
        3600,
        "spiffe://{trust_domain}/ns/{namespace}/sa/{service_account}",
        None,
        policy_settings(None),
    );
    let target = fx.root.join("mount");
    fx.node
        .node_publish_volume(Request::new(publish_request(&target, "payments", "api")))
        .await
        .unwrap();

    assert_eq!(
        published_spiffe_id(&target),
        "spiffe://example.org/ns/payments/sa/api"
    );
    std::fs::remove_dir_all(&fx.root).unwrap();
}

#[tokio::test]
async fn a_template_can_pin_the_identity_to_the_node_and_pod() {
    let fx = fixture_with(
        "template-node",
        3600,
        "spiffe://{trust_domain}/node/{node_name}/ns/{namespace}/pod/{pod_name}",
        None,
        policy_settings(None),
    );
    let target = fx.root.join("mount");
    fx.node
        .node_publish_volume(Request::new(publish_request(&target, "payments", "api")))
        .await
        .unwrap();

    assert_eq!(
        published_spiffe_id(&target),
        "spiffe://example.org/node/node-1/ns/payments/pod/web-0"
    );
    std::fs::remove_dir_all(&fx.root).unwrap();
}

#[tokio::test]
async fn a_template_needing_a_field_the_kubelet_did_not_send_fails_loudly() {
    let fx = fixture_with(
        "template-missing",
        3600,
        "spiffe://{trust_domain}/pod/{pod_name}/sa/{service_account}",
        None,
        policy_settings(None),
    );
    let target = fx.root.join("mount");

    let mut req = publish_request(&target, "payments", "api");
    req.volume_context.remove(vc::POD_NAME);
    let err = fx
        .node
        .node_publish_volume(Request::new(req))
        .await
        .unwrap_err();

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains(vc::POD_NAME), "{}", err.message());
    assert!(err.message().contains("podInfoOnMount"));
    assert!(fx.ca.signed_ids().is_empty());

    std::fs::remove_dir_all(&fx.root).unwrap();
}

#[tokio::test]
async fn an_id_pattern_refuses_identities_the_operator_disallows() {
    let fx = fixture_with(
        "pattern",
        3600,
        IdTemplate::DEFAULT,
        Some(r"spiffe://example\.org/cluster/a/ns/(payments|billing)/sa/.+"),
        policy_settings(None),
    );

    let allowed = fx.root.join("allowed");
    fx.node
        .node_publish_volume(Request::new(publish_request(&allowed, "payments", "api")))
        .await
        .unwrap();
    assert_eq!(
        published_spiffe_id(&allowed),
        "spiffe://example.org/cluster/a/ns/payments/sa/api"
    );

    // A namespace outside the pattern is refused, and nothing is signed for it.
    let denied = fx.root.join("denied");
    let err = fx
        .node
        .node_publish_volume(Request::new(publish_request(
            &denied,
            "kube-system",
            "admin",
        )))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    assert!(err.message().contains("spiffe_id_pattern"));
    assert_eq!(fx.ca.signed_ids().len(), 1);
    assert!(!denied.exists(), "a refused volume leaves nothing behind");

    std::fs::remove_dir_all(&fx.root).unwrap();
}

#[tokio::test]
async fn recovery_ignores_certificates_the_current_template_would_not_issue() {
    // Publish under one template...
    let fx = fixture_with(
        "recover-template",
        3600,
        "spiffe://{trust_domain}/ns/{namespace}/sa/{service_account}",
        None,
        policy_settings(None),
    );
    let target = fx
        .root
        .join("pods/aaaa/volumes/kubernetes.io~csi/svid/mount");
    std::fs::create_dir_all(target.parent().unwrap()).unwrap();
    std::fs::write(
        target.parent().unwrap().join("vol_data.json"),
        r#"{"driverName":"csi.svidlet.io","specVolID":"svid","volumeHandle":"csi-x"}"#,
    )
    .unwrap();
    fx.node
        .node_publish_volume(Request::new(publish_request(&target, "payments", "api")))
        .await
        .unwrap();

    // ...then restart with the default template, which has a cluster segment.
    let cfg = config(&fx.root);
    let policy = cfg.id_policy().unwrap();
    let store = Store::new();
    let metrics = Metrics::default();
    assert_eq!(svidlet::recover::adopt(&cfg, &policy, &store, &metrics), 0);
    assert_eq!(store.len(), 0);
    assert_eq!(
        metrics
            .adoption_skipped
            .load(std::sync::atomic::Ordering::Relaxed),
        1,
        "the skip is counted so an operator can see the re-issue coming"
    );

    std::fs::remove_dir_all(&fx.root).unwrap();
}

// ------------------------------------------------------------ policy bundles

fn policy_bundle(revision: &str, docs: &[(&str, &str)]) -> PolicyBundle {
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

fn policy_fixture(name: &str, required: bool) -> Fixture {
    let mut settings = policy_settings(Some("http://policy.invalid:9000"));
    settings.required = required;
    fixture_with(name, 3600, IdTemplate::DEFAULT, None, settings)
}

#[tokio::test]
async fn policy_is_published_next_to_the_certificate() {
    let fx = policy_fixture("policy-publish", false);
    let target = fx.root.join("mount");
    let id = "spiffe://example.org/cluster/a/ns/payments/sa/api";

    // The backend already has a bundle when the pod starts.
    fx.policy.subscribe(id);
    fx.policy.apply(
        id,
        policy_bundle(
            "git-abc123",
            &[("authz.rego", "allow := true"), ("peers.json", "[]")],
        ),
    );

    fx.node
        .node_publish_volume(Request::new(publish_request(&target, "payments", "api")))
        .await
        .unwrap();

    assert_eq!(
        std::fs::read_to_string(target.join("policy/authz.rego")).unwrap(),
        "allow := true"
    );
    assert_eq!(
        std::fs::read_to_string(target.join("policy/peers.json")).unwrap(),
        "[]"
    );
    // The revision is a single file to stat, so an application can notice a
    // change without walking the directory.
    assert_eq!(
        std::fs::read_to_string(target.join(REVISION_FILE)).unwrap(),
        "git-abc123\n"
    );
    // The certificate is there too, and unaffected.
    assert_eq!(published_spiffe_id(&target), id);

    std::fs::remove_dir_all(&fx.root).unwrap();
}

#[tokio::test]
async fn publishing_subscribes_and_unpublishing_stops_following() {
    let fx = policy_fixture("policy-subscribe", false);
    let target = fx.root.join("mount");
    let id = "spiffe://example.org/cluster/a/ns/payments/sa/api";

    fx.node
        .node_publish_volume(Request::new(publish_request(&target, "payments", "api")))
        .await
        .unwrap();
    assert_eq!(fx.policy.wanted(), vec![(id.to_string(), String::new())]);

    fx.node
        .node_unpublish_volume(Request::new(NodeUnpublishVolumeRequest {
            volume_id: "csi-abcdef".into(),
            target_path: target.display().to_string(),
        }))
        .await
        .unwrap();
    assert_eq!(fx.policy.subscription_count(), 0);

    std::fs::remove_dir_all(&fx.root).unwrap();
}

#[tokio::test]
async fn a_policy_update_rewrites_the_volume_and_leaves_the_certificate_alone() {
    let fx = policy_fixture("policy-update", false);
    let target = fx.root.join("mount");
    let id = "spiffe://example.org/cluster/a/ns/payments/sa/api";

    fx.policy.subscribe(id);
    fx.policy
        .apply(id, policy_bundle("r1", &[("authz.rego", "v1")]));
    fx.node
        .node_publish_volume(Request::new(publish_request(&target, "payments", "api")))
        .await
        .unwrap();
    let cert_before = std::fs::read_to_string(target.join(CERT_FILE)).unwrap();

    // Upstream moves.
    assert!(fx.policy.apply(
        id,
        policy_bundle("r2", &[("authz.rego", "v2"), ("extra.json", "{}")])
    ));
    assert_eq!(fx.policy.take_dirty(), vec![id.to_string()]);

    let entry = fx.store.get(&target).unwrap();
    assert!(fx
        .publisher
        .apply_policy(&entry.spiffe_id, &target)
        .unwrap());

    assert_eq!(
        std::fs::read_to_string(target.join("policy/authz.rego")).unwrap(),
        "v2"
    );
    assert_eq!(
        std::fs::read_to_string(target.join("policy/extra.json")).unwrap(),
        "{}"
    );
    assert_eq!(
        std::fs::read_to_string(target.join(REVISION_FILE)).unwrap(),
        "r2\n"
    );
    assert_eq!(
        std::fs::read_to_string(target.join(CERT_FILE)).unwrap(),
        cert_before,
        "a policy update must not disturb the certificate"
    );
    assert_eq!(
        fx.ca.signed_ids().len(),
        1,
        "no re-issue for a policy change"
    );

    // Applying the same bundle again rewrites nothing.
    assert!(!fx
        .publisher
        .apply_policy(&entry.spiffe_id, &target)
        .unwrap());

    std::fs::remove_dir_all(&fx.root).unwrap();
}

#[tokio::test]
async fn a_removed_document_disappears_from_the_volume() {
    let fx = policy_fixture("policy-shrink", false);
    let target = fx.root.join("mount");
    let id = "spiffe://example.org/cluster/a/ns/payments/sa/api";

    fx.policy.subscribe(id);
    fx.policy
        .apply(id, policy_bundle("r1", &[("a.rego", "1"), ("b.rego", "2")]));
    fx.node
        .node_publish_volume(Request::new(publish_request(&target, "payments", "api")))
        .await
        .unwrap();
    assert!(target.join("policy/b.rego").exists());

    fx.policy.apply(id, policy_bundle("r2", &[("a.rego", "1")]));
    let entry = fx.store.get(&target).unwrap();
    fx.publisher
        .apply_policy(&entry.spiffe_id, &target)
        .unwrap();

    // The whole directory is rebuilt each time, so a document deleted upstream
    // is really gone rather than lingering from the previous revision.
    assert!(target.join("policy/a.rego").exists());
    assert!(!target.join("policy/b.rego").exists());

    std::fs::remove_dir_all(&fx.root).unwrap();
}

#[tokio::test]
async fn a_certificate_renewal_keeps_the_policy_it_already_published() {
    let fx = policy_fixture("policy-renew", false);
    let target = fx.root.join("mount");
    let id = "spiffe://example.org/cluster/a/ns/payments/sa/api";

    fx.policy.subscribe(id);
    fx.policy
        .apply(id, policy_bundle("r1", &[("authz.rego", "v1")]));
    fx.node
        .node_publish_volume(Request::new(publish_request(&target, "payments", "api")))
        .await
        .unwrap();

    // The policy backend goes away and the plugin forgets its cache, as it
    // would across a restart. A renewal must not clear the policy directory.
    fx.policy.unsubscribe(id);
    fx.policy.subscribe(id);
    assert!(fx.policy.bundle(id).is_none());

    let entry = fx.store.get(&target).unwrap();
    svidlet::renew::renew_one(&fx.publisher, &entry);

    assert_eq!(
        std::fs::read_to_string(target.join("policy/authz.rego")).unwrap(),
        "v1"
    );
    assert_eq!(
        std::fs::read_to_string(target.join(REVISION_FILE)).unwrap(),
        "r1\n"
    );
    assert_eq!(fx.ca.signed_ids().len(), 2, "the certificate did renew");

    std::fs::remove_dir_all(&fx.root).unwrap();
}

#[tokio::test]
async fn a_policy_outage_does_not_stop_a_certificate_being_issued() {
    let fx = policy_fixture("policy-optional", false);
    let target = fx.root.join("mount");

    // Nothing has ever arrived from the backend.
    fx.node
        .node_publish_volume(Request::new(publish_request(&target, "payments", "api")))
        .await
        .unwrap();

    assert_eq!(
        published_spiffe_id(&target),
        "spiffe://example.org/cluster/a/ns/payments/sa/api"
    );
    // No policy directory is created, so a workload can tell "no policy yet"
    // from "an empty policy".
    assert!(!target.join("policy").exists());
    assert!(!target.join(REVISION_FILE).exists());

    std::fs::remove_dir_all(&fx.root).unwrap();
}

#[tokio::test]
async fn policy_required_refuses_to_publish_when_none_arrives() {
    let fx = policy_fixture("policy-required", true);
    let target = fx.root.join("mount");

    let err = fx
        .node
        .node_publish_volume(Request::new(publish_request(&target, "payments", "api")))
        .await
        .unwrap_err();

    assert_eq!(err.code(), tonic::Code::Unavailable);
    assert!(err.message().contains("SVIDLET_POLICY_REQUIRED"));
    assert!(fx.ca.signed_ids().is_empty(), "no certificate is minted");
    assert_eq!(fx.store.len(), 0);
    // The subscription is dropped again, so a pod that never started is not
    // left being tracked.
    assert_eq!(fx.policy.subscription_count(), 0);

    std::fs::remove_dir_all(&fx.root).unwrap();
}

#[tokio::test]
async fn policy_required_publishes_as_soon_as_the_bundle_lands() {
    let fx = policy_fixture("policy-required-ok", true);
    let target = fx.root.join("mount");
    let id = "spiffe://example.org/cluster/a/ns/payments/sa/api";

    // Deliver the bundle shortly after the publish call starts waiting.
    let policy = fx.policy.clone();
    let deliver = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        policy.apply(id, policy_bundle("r1", &[("authz.rego", "allow")]));
    });

    fx.node
        .node_publish_volume(Request::new(publish_request(&target, "payments", "api")))
        .await
        .unwrap();
    deliver.await.unwrap();

    assert_eq!(
        std::fs::read_to_string(target.join("policy/authz.rego")).unwrap(),
        "allow"
    );
    std::fs::remove_dir_all(&fx.root).unwrap();
}

// ------------------------------------------------- policy over a real stream

mod policy_stream {
    //! The policy client against a real gRPC server.
    //!
    //! Everything else in this file drives [`PolicyManager`] directly. This
    //! runs the generated client against the generated server over a real
    //! socket, which is the only way to exercise connecting, subscribing,
    //! streaming and reconnecting.

    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::mpsc;
    use tokio_stream::wrappers::{TcpListenerStream, UnboundedReceiverStream};
    use tokio_stream::StreamExt;
    use tonic::{Response, Status, Streaming};

    use svidlet::policy::proto::policy_service_server::{PolicyService, PolicyServiceServer};
    use svidlet::policy::proto::{
        watch_request, PolicyDocument as ProtoDocument, PolicyUpdate, WatchRequest,
    };

    /// A policy backend that answers each Subscribe with one bundle.
    #[derive(Default, Clone)]
    struct Backend {
        subscribes: Arc<AtomicUsize>,
        /// The revision handed out, which a test can change under the client.
        revision: Arc<Mutex<String>>,
        /// End the stream after answering, as a backend recycling connections
        /// or being restarted behind a load balancer would.
        end_after_first: bool,
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
            let end_after_first = self.end_after_first;

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
                    if tx.send(Ok(update)).is_err() || end_after_first {
                        return;
                    }
                }
            });

            Ok(Response::new(UnboundedReceiverStream::new(rx)))
        }
    }

    async fn serve(backend: Backend) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        let handle = tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(PolicyServiceServer::new(backend))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await;
        });
        (addr, handle)
    }

    async fn eventually<F: Fn() -> bool>(what: &str, check: F) {
        for _ in 0..100 {
            if check() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!("timed out waiting for {what}");
    }

    #[tokio::test]
    async fn a_pod_starting_pulls_its_policy_over_the_stream() {
        let subscribes = Arc::new(AtomicUsize::new(0));
        let (addr, server) = serve(Backend {
            subscribes: subscribes.clone(),
            revision: Arc::new(Mutex::new("git-r1".into())),
            end_after_first: false,
        })
        .await;

        let mut settings = policy_settings(Some(&addr));
        settings.initial_timeout = std::time::Duration::from_secs(10);
        settings.required = true;
        let fx = fixture_with("stream", 3600, IdTemplate::DEFAULT, None, settings);

        // The real client, connecting over a real socket.
        let watcher = tokio::spawn(svidlet::policy::grpc::watch_loop(
            fx.policy.clone(),
            "node-1".into(),
        ));

        let target = fx.root.join("mount");
        // Policy is required, so this call blocks until the bundle streams in.
        fx.node
            .node_publish_volume(Request::new(publish_request(&target, "payments", "api")))
            .await
            .unwrap();

        assert_eq!(
            std::fs::read_to_string(target.join("policy/authz.rego")).unwrap(),
            "allow := true"
        );
        assert_eq!(
            std::fs::read_to_string(target.join(REVISION_FILE)).unwrap(),
            "git-r1\n"
        );
        assert_eq!(subscribes.load(Ordering::SeqCst), 1);
        assert!(fx
            .policy
            .metrics
            .connected
            .load(std::sync::atomic::Ordering::Relaxed));

        watcher.abort();
        server.abort();
        std::fs::remove_dir_all(&fx.root).unwrap();
    }

    #[tokio::test]
    async fn the_stream_reconnects_and_picks_up_what_changed_while_it_was_down() {
        let subscribes = Arc::new(AtomicUsize::new(0));
        let revision = Arc::new(Mutex::new("git-r1".to_string()));
        // This backend hangs up after every answer, so the client has to
        // reconnect and resubscribe to keep receiving anything.
        let (addr, server) = serve(Backend {
            subscribes: subscribes.clone(),
            revision: revision.clone(),
            end_after_first: true,
        })
        .await;

        let fx = fixture_with(
            "stream-reconnect",
            3600,
            IdTemplate::DEFAULT,
            None,
            policy_settings(Some(&addr)),
        );
        let watcher = tokio::spawn(svidlet::policy::grpc::watch_loop(
            fx.policy.clone(),
            "node-1".into(),
        ));

        let target = fx.root.join("mount");
        fx.node
            .node_publish_volume(Request::new(publish_request(&target, "payments", "api")))
            .await
            .unwrap();

        let id = "spiffe://example.org/cluster/a/ns/payments/sa/api";
        eventually("the first bundle", || {
            fx.policy
                .bundle(id)
                .map(|b| b.revision == "git-r1")
                .unwrap_or(false)
        })
        .await;

        // Upstream moves while the node is between connections.
        *revision.lock().unwrap() = "git-r2".to_string();

        eventually("the resubscribe", || subscribes.load(Ordering::SeqCst) >= 2).await;
        eventually("the new revision", || {
            fx.policy
                .bundle(id)
                .map(|b| b.revision == "git-r2")
                .unwrap_or(false)
        })
        .await;
        assert!(
            fx.policy
                .metrics
                .stream_reconnects
                .load(std::sync::atomic::Ordering::Relaxed)
                > 0
                || subscribes.load(Ordering::SeqCst) >= 2
        );

        // The apply loop writes the new revision into the mounted volume,
        // without re-issuing the certificate.
        assert_eq!(
            svidlet::renew::apply_dirty_policy(fx.publisher.clone()).await,
            1
        );
        assert_eq!(
            std::fs::read_to_string(target.join(REVISION_FILE)).unwrap(),
            "git-r2\n"
        );
        assert_eq!(fx.ca.signed_ids().len(), 1);

        watcher.abort();
        server.abort();
        std::fs::remove_dir_all(&fx.root).unwrap();
    }
}

// --------------------------------------------------------- background passes

#[tokio::test]
async fn the_renewal_pass_renews_everything_that_is_due() {
    let fx = fixture("renew-pass", 3600);
    let target = fx.root.join("mount");
    fx.node
        .node_publish_volume(Request::new(publish_request(&target, "default", "web")))
        .await
        .unwrap();

    // Nothing is due yet.
    assert_eq!(svidlet::renew::renew_due(fx.publisher.clone()).await, 0);
    assert_eq!(fx.ca.signed_ids().len(), 1);

    // Bring the deadline forward, as the passage of time would.
    let mut entry = fx.store.get(&target).unwrap();
    entry.renew_at = svidlet::log::unix_now() - 1;
    fx.store.insert(entry);

    assert_eq!(svidlet::renew::renew_due(fx.publisher.clone()).await, 1);
    assert_eq!(fx.ca.signed_ids().len(), 2);
    // Renewing moved the deadline back into the future.
    assert_eq!(svidlet::renew::renew_due(fx.publisher.clone()).await, 0);

    std::fs::remove_dir_all(&fx.root).unwrap();
}

#[tokio::test]
async fn the_reaper_drops_volumes_the_kubelet_removed_while_we_were_down() {
    let fx = fixture("reaper", 3600);
    let target = fx.root.join("mount");
    fx.node
        .node_publish_volume(Request::new(publish_request(&target, "default", "web")))
        .await
        .unwrap();
    assert_eq!(svidlet::renew::reap_orphans(&fx.publisher), 0);

    // The kubelet tore the pod down without an unpublish reaching us.
    std::fs::remove_dir_all(&target).unwrap();

    assert_eq!(svidlet::renew::reap_orphans(&fx.publisher), 1);
    assert_eq!(fx.store.len(), 0);
    assert_eq!(svidlet::renew::reap_orphans(&fx.publisher), 0);

    std::fs::remove_dir_all(&fx.root).unwrap();
}

#[tokio::test]
async fn the_ca_refresh_pass_survives_a_backend_outage() {
    let fx = fixture("ca-pass", 3600);
    let target = fx.root.join("mount");
    fx.node
        .node_publish_volume(Request::new(publish_request(&target, "default", "web")))
        .await
        .unwrap();
    let ca_before = std::fs::read_to_string(target.join(CA_FILE)).unwrap();

    fx.ca.break_signing("vault is sealed");
    svidlet::renew::refresh_ca_once(fx.publisher.clone()).await;

    // ca_chain() still works on the test CA, so nothing changed; the point is
    // that the pass does not panic or clear ca.crt.
    assert_eq!(
        std::fs::read_to_string(target.join(CA_FILE)).unwrap(),
        ca_before
    );

    std::fs::remove_dir_all(&fx.root).unwrap();
}

#[tokio::test]
async fn the_policy_flag_turns_the_whole_feature_off() {
    // An endpoint is configured — and unreachable — but the flag is off. This
    // is the local-testing shape: the ConfigMap stays as it is in production
    // and one variable takes the policy backend out of the picture.
    let mut settings = policy_settings(Some("http://policy.invalid:9000"));
    settings.enabled = false;
    // Even `required` must not make publishing wait once the flag is off,
    // or turning it off would still block every pod.
    settings.required = true;
    settings.initial_timeout = std::time::Duration::from_secs(30);

    let fx = fixture_with("policy-off", 3600, IdTemplate::DEFAULT, None, settings);
    let target = fx.root.join("mount");

    // No stream, no waiting: this returns immediately rather than after 30s.
    let started = std::time::Instant::now();
    fx.node
        .node_publish_volume(Request::new(publish_request(&target, "payments", "api")))
        .await
        .unwrap();
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "publishing waited for a policy backend that is switched off"
    );

    assert_eq!(
        published_spiffe_id(&target),
        "spiffe://example.org/cluster/a/ns/payments/sa/api"
    );
    assert!(!target.join("policy").exists());
    assert!(!target.join(REVISION_FILE).exists());
    assert_eq!(fx.policy.subscription_count(), 0);

    // And the watcher returns instead of retrying an endpoint it must ignore.
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        svidlet::policy::grpc::watch_loop(fx.policy.clone(), "node-1".into()),
    )
    .await
    .expect("the watch loop returns rather than connecting");

    std::fs::remove_dir_all(&fx.root).unwrap();
}
