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
    volume_context as vc, AuthSettings, Config, PolicyGate, VaultSettings, CA_FILE, CERT_FILE,
    KEY_FILE, REVISION_FILE,
};
use svidlet::csi::node::NodeService;
use svidlet::csi::proto::csi::node_server::Node;
use svidlet::csi::proto::csi::{NodePublishVolumeRequest, NodeUnpublishVolumeRequest};
use svidlet::issue::Publisher;
use svidlet::metrics::Metrics;
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
    config_with(kubelet_root, IdTemplate::DEFAULT, None, gate(false))
}

/// Whether a pod may start before its policy arrives. Off unless a test says so.
fn gate(required: bool) -> PolicyGate {
    PolicyGate {
        required,
        initial_timeout: std::time::Duration::from_millis(300),
    }
}

fn config_with(
    kubelet_root: &Path,
    template: &str,
    pattern: Option<&str>,
    policy: PolicyGate,
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
        policy_gid: None,
        cert_ttl: std::time::Duration::from_secs(3600),
        renew_fraction: (0.5, 0.7),
        renew_check_interval: std::time::Duration::from_secs(30),
        startup_spread: std::time::Duration::from_secs(300),
        ca_refresh_interval: std::time::Duration::from_secs(3600),
        tmpfs_size: "1m".into(),
        key_mode: 0o640,
        key_gid: None,
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
    root: PathBuf,
}

fn fixture(name: &str, lifetime_secs: i64) -> Fixture {
    fixture_with(name, lifetime_secs, IdTemplate::DEFAULT, None, gate(false))
}

fn fixture_with(
    name: &str,
    lifetime_secs: i64,
    template: &str,
    pattern: Option<&str>,
    policy: PolicyGate,
) -> Fixture {
    svidlet::rand::seed();
    let root = scratch(name);
    let ca = Arc::new(TestCa::new(lifetime_secs));
    let store = Arc::new(Store::new());
    let cfg = config_with(&root, template, pattern, policy);
    let id_policy = Arc::new(cfg.id_policy().expect("the template compiles"));
    let publisher = Arc::new(Publisher::new(
        Arc::new(cfg),
        id_policy,
        ca.clone(),
        store.clone(),
        Arc::new(Metrics::default()),
    ));
    publisher.prime_ca().unwrap();
    Fixture {
        node: NodeService::new(publisher.clone()),
        publisher,
        ca,
        store,
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
        gate(false),
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
        gate(false),
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
        gate(false),
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
        gate(false),
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
        gate(false),
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

// ------------------------------------------------- the policy gate, if enabled

#[tokio::test]
async fn policy_required_refuses_to_publish_when_the_daemon_writes_nothing() {
    // svidlet does not talk to a policy backend any more. All it does is look
    // for the revision file svidlet-policy would have written beside the
    // certificate — one direction, through the volume, no shared credential.
    let fx = fixture_with("gate-timeout", 3600, IdTemplate::DEFAULT, None, gate(true));
    let target = fx.root.join("mount");

    let err = fx
        .node
        .node_publish_volume(Request::new(publish_request(&target, "payments", "api")))
        .await
        .unwrap_err();

    assert_eq!(err.code(), tonic::Code::Unavailable);
    assert!(err.message().contains("SVIDLET_POLICY_REQUIRED"));
    assert!(err.message().contains("svidlet-policy"));
    // Nothing is left behind for the kubelet's retry to trip over.
    assert!(!target.exists());
    assert_eq!(fx.store.len(), 0);

    std::fs::remove_dir_all(&fx.root).unwrap();
}

#[tokio::test]
async fn policy_required_succeeds_once_the_daemon_publishes() {
    let fx = fixture_with("gate-ok", 3600, IdTemplate::DEFAULT, None, gate(true));
    let target = fx.root.join("mount");

    // Stand in for svidlet-policy: wait for the certificate to appear, then
    // write the policy chain, exactly as the daemon does.
    let writer_target = target.clone();
    let writer = tokio::spawn(async move {
        for _ in 0..100 {
            if writer_target.join(CERT_FILE).exists() {
                let bundle = svidlet::policy::PolicyBundle::build(
                    "git-r1".into(),
                    vec![svidlet::policy::PolicyDocument {
                        name: "authz.rego".into(),
                        content: b"allow := true".to_vec(),
                    }],
                )
                .unwrap();
                svidlet::volume::publish_policy(&writer_target, &bundle, 0o644).unwrap();
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("the certificate never appeared");
    });

    fx.node
        .node_publish_volume(Request::new(publish_request(&target, "payments", "api")))
        .await
        .unwrap();
    writer.await.unwrap();

    assert_eq!(
        std::fs::read_to_string(target.join(REVISION_FILE)).unwrap(),
        "git-r1\n"
    );
    assert_eq!(
        published_spiffe_id(&target),
        "spiffe://example.org/cluster/a/ns/payments/sa/api"
    );

    std::fs::remove_dir_all(&fx.root).unwrap();
}

#[tokio::test]
async fn a_certificate_renewal_never_disturbs_the_policy_chain() {
    // Structural, not careful coding: the two writers own different names.
    let fx = fixture("chains", 3600);
    let target = fx.root.join("mount");
    fx.node
        .node_publish_volume(Request::new(publish_request(&target, "payments", "api")))
        .await
        .unwrap();

    let bundle = svidlet::policy::PolicyBundle::build(
        "git-r1".into(),
        vec![svidlet::policy::PolicyDocument {
            name: "authz.rego".into(),
            content: b"allow := true".to_vec(),
        }],
    )
    .unwrap();
    svidlet::volume::publish_policy(&target, &bundle, 0o644).unwrap();

    let entry = fx.store.get(&target).unwrap();
    for _ in 0..3 {
        svidlet::renew::renew_one(&fx.publisher, &entry);
    }
    svidlet::renew::refresh_ca_once(fx.publisher.clone()).await;

    assert_eq!(
        std::fs::read_to_string(target.join("policy/authz.rego")).unwrap(),
        "allow := true"
    );
    assert_eq!(
        svidlet::volume::published_revision(&target).as_deref(),
        Some("git-r1")
    );
    assert_eq!(fx.ca.signed_ids().len(), 4);

    std::fs::remove_dir_all(&fx.root).unwrap();
}
