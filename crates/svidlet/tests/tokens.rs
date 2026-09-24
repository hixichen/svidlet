//! JWT-SVIDs end to end: svidlet publishing a volume that declares audiences,
//! against a token issuer over mutual TLS, with the node certificate node
//! bootstrap would have left in `/node`.
//!
//! The issuer is its own project (svidlet-token-issuer). The one here is a
//! stand-in that holds svidlet to the interface from the issuer's side: it
//! accepts only node certificates, checks the proof of possession exactly as
//! `svidlet_token::pop` specifies, and grants one audience to one namespace.

#[expect(dead_code, reason = "shared helpers; this suite uses remove_tree only")]
mod common;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use svidlet::config::{volume_context as vc, Config, JWT_DIR};
use svidlet::csi::node::NodeService;
use svidlet::csi::proto::csi::node_server::Node;
use svidlet::csi::proto::csi::NodePublishVolumeRequest;
use svidlet::issue::Publisher;
use svidlet::metrics::Metrics;
use svidlet::store::Store;
use svidlet_issue::{IssuedBundle, SignRequest};
use svidlet_token::proto::token_issuer_server::{TokenIssuer, TokenIssuerServer};
use svidlet_token::proto::{MintRequest, MintResponse};
use svidlet_token::{pop, Claims};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};

const AZURE: &str = "api://AzureADTokenExchange";
const ISSUER: &str = "https://tokens.example.org";
/// The one grant the stand-in issuer holds.
const GRANTED: &str = "spiffe://example.org/cluster/a/ns/payments/";

struct Ca {
    pem: String,
    issuer: Issuer<'static, KeyPair>,
}

fn ca(name: &str) -> Ca {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, name);
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let pem = params.self_signed(&key).unwrap().pem();
    Ca {
        issuer: Issuer::from_ca_cert_pem(&pem, key).unwrap(),
        pem,
    }
}

fn eku(params: &mut CertificateParams, hours: i64) {
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::minutes(1);
    params.not_after = now + time::Duration::hours(hours);
}

/// Vault PKI, as the node sees it: signs CSRs like the documented role.
struct PodCa(Ca);

impl std::fmt::Debug for PodCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PodCa")
    }
}

impl svidlet_issue::Issuer for PodCa {
    fn sign(&self, request: &SignRequest<'_>) -> svidlet_issue::Result<IssuedBundle> {
        let mut csr = CertificateSigningRequestParams::from_pem(request.csr_pem)
            .map_err(|e| svidlet_issue::Error::Protocol(e.to_string()))?;
        eku(&mut csr.params, 6);
        let chain = csr
            .signed_by(&self.0.issuer)
            .map_err(|e| svidlet_issue::Error::Protocol(e.to_string()))?
            .pem();
        let facts = svidlet_issue::assert_identity(&chain, request.spiffe_id)?;
        Ok(IssuedBundle {
            cert_chain_pem: chain,
            ca_pem: self.0.pem.clone(),
            not_before: facts.not_before,
            not_after: facts.not_after,
        })
    }

    fn ca_chain(&self) -> svidlet_issue::Result<String> {
        Ok(self.0.pem.clone())
    }

    fn name(&self) -> &'static str {
        "test-ca"
    }
}

struct Fixture {
    node: NodeService,
    publisher: Arc<Publisher>,
    root: PathBuf,
}

/// What node bootstrap leaves in /node.
fn write_node_certificate(root: &Path, node_ca: &Ca) {
    let node_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut node_params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "node-1");
    node_params.distinguished_name = dn;
    node_params.subject_alt_names = vec![SanType::URI(
        "spiffe://example.org/cluster/a/node/node-1"
            .try_into()
            .unwrap(),
    )];
    eku(&mut node_params, 24);
    let node_cert = node_params.signed_by(&node_key, &node_ca.issuer).unwrap();
    std::fs::write(root.join("node.crt"), node_cert.pem()).unwrap();
    std::fs::write(root.join("node.key"), node_key.serialize_pem()).unwrap();
}

/// The first URI SAN of a DER certificate, and its public key.
fn san_and_key(der: &[u8]) -> Option<(String, Vec<u8>)> {
    use x509_parser::extensions::GeneralName;
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let san = cert.subject_alternative_name().ok()??;
    let uri = san.value.general_names.iter().find_map(|n| match n {
        GeneralName::URI(u) => Some((*u).to_string()),
        _ => None,
    })?;
    Some((uri, cert.public_key().subject_public_key.data.to_vec()))
}

/// The issuer's side of the interface, minus key management: every check
/// svidlet's request must pass, then an unsigned-in-spirit token (svidlet
/// never verifies signatures; relying parties do).
struct StandIn;

#[tonic::async_trait]
impl TokenIssuer for StandIn {
    async fn mint(&self, request: Request<MintRequest>) -> Result<Response<MintResponse>, Status> {
        let node_der = request
            .peer_certs()
            .and_then(|c| c.first().map(|c| c.as_ref().to_vec()))
            .ok_or_else(|| Status::unauthenticated("no node certificate"))?;
        let (node_id, _) = san_and_key(&node_der)
            .filter(|(id, _)| id.starts_with("spiffe://example.org/cluster/a/node/"))
            .ok_or_else(|| Status::unauthenticated("not a node of cluster a"))?;
        let req = request.into_inner();

        let (_, pod_pem) = x509_parser::pem::parse_x509_pem(req.pod_cert_chain_pem.as_bytes())
            .map_err(|e| Status::invalid_argument(format!("no pod certificate: {e}")))?;
        let (pod_id, pod_key) = san_and_key(&pod_pem.contents)
            .ok_or_else(|| Status::invalid_argument("pod certificate has no URI SAN"))?;
        let not_after = svidlet_issue::inspect(&req.pod_cert_chain_pem)
            .map_err(|e| Status::invalid_argument(e.to_string()))?
            .not_after;

        let now = svidlet::log::unix_now();
        if !pop::is_fresh(req.proof_time, now) {
            return Err(Status::unauthenticated("stale proof"));
        }
        pop::verify(
            &pod_key,
            &pop::message(&node_id, &pod_id, &req.audience, req.proof_time),
            &req.proof,
        )
        .map_err(|e| Status::unauthenticated(format!("proof: {e}")))?;
        if !(pod_id.starts_with(GRANTED) && req.audience == AZURE) {
            return Err(Status::permission_denied(format!(
                "no grant for {pod_id} to {}",
                req.audience
            )));
        }

        let claims = Claims {
            iss: ISSUER.into(),
            sub: pod_id,
            aud: req.audience,
            iat: now,
            nbf: now,
            exp: (now + 21_600).min(not_after),
            jti: format!("{now}-{}", svidlet::rand::next_u64()),
        };
        let b64 = |v: &[u8]| {
            use base64::Engine as _;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v)
        };
        let token = format!(
            "{}.{}.{}",
            b64(br#"{"alg":"ES256","typ":"JWT","kid":"stand-in"}"#),
            b64(&serde_json::to_vec(&claims).unwrap()),
            b64(b"not-a-signature")
        );
        Ok(Response::new(MintResponse {
            token,
            expires_at: claims.exp,
        }))
    }
}

/// The stand-in issuer, serving with a certificate from the Vault CA and
/// accepting only the node CA's certificates. Returns its port.
async fn start_issuer(pod_ca: &Ca, node_ca: &Ca) -> u16 {
    let server_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut server_params = CertificateParams::default();
    server_params.subject_alt_names = vec![SanType::DnsName("localhost".try_into().unwrap())];
    eku(&mut server_params, 24);
    let server_cert = server_params
        .signed_by(&server_key, &pod_ca.issuer)
        .unwrap()
        .pem();
    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(server_cert, server_key.serialize_pem()))
        .client_ca_root(Certificate::from_pem(&node_ca.pem));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = Server::builder()
        .tls_config(tls)
        .unwrap()
        .add_service(TokenIssuerServer::new(StandIn));
    tokio::spawn(server.serve_with_incoming(TcpListenerStream::new(listener)));
    port
}

/// Start an issuer and a svidlet that uses it. `issuer_url` overrides where
/// svidlet looks, to model an issuer that is down.
async fn fixture(name: &str, issuer_url: Option<&str>, with_issuer: bool) -> Fixture {
    svidlet::rand::seed();
    let root = std::env::temp_dir().join(format!(
        "svidlet-tokens-{name}-{}-{}",
        std::process::id(),
        svidlet::log::unix_now()
    ));
    std::fs::create_dir_all(root.join("kubelet")).unwrap();

    let pod_ca = ca("vault pki");
    let node_ca = ca("step-ca");

    write_node_certificate(&root, &node_ca);
    let port = start_issuer(&pod_ca, &node_ca).await;

    let url = issuer_url.map_or_else(|| format!("https://localhost:{port}"), str::to_string);
    let mut env: HashMap<String, String> = HashMap::from([
        ("NODE_NAME".into(), "node-1".into()),
        ("SVIDLET_CLUSTER".into(), "a".into()),
        ("SVIDLET_TRUST_DOMAIN".into(), "example.org".into()),
        ("VAULT_ADDR".into(), "https://vault.invalid".into()),
        ("SVIDLET_VAULT_AUTH".into(), "cert".into()),
        (
            "SVIDLET_NODE_CERT_FILE".into(),
            root.join("node.crt").display().to_string(),
        ),
        (
            "SVIDLET_NODE_KEY_FILE".into(),
            root.join("node.key").display().to_string(),
        ),
        (
            "SVIDLET_KUBELET_ROOT".into(),
            root.join("kubelet").display().to_string(),
        ),
        ("SVIDLET_TOKEN_TIMEOUT".into(), "3s".into()),
    ]);
    if with_issuer {
        env.insert("SVIDLET_TOKEN_ISSUER".into(), url);
    }
    let cfg = Config::from_source(&move |k| env.get(k).cloned()).unwrap();
    let id_policy = Arc::new(cfg.id_policy().unwrap());
    let publisher = Arc::new(Publisher::new(
        Arc::new(cfg),
        id_policy,
        Arc::new(PodCa(pod_ca)),
        Arc::new(Store::new()),
        Arc::new(Metrics::default()),
    ));
    // The issuer's certificate is verified with this trust bundle: no
    // SVIDLET_TOKEN_ISSUER_CACERT is set.
    publisher.prime_ca().unwrap();
    Fixture {
        node: NodeService::new(Arc::clone(&publisher)),
        publisher,
        root,
    }
}

fn publish(target: &Path, namespace: &str, audiences: &str) -> NodePublishVolumeRequest {
    let mut ctx = HashMap::new();
    ctx.insert(vc::EPHEMERAL.into(), "true".into());
    ctx.insert(vc::POD_NAME.into(), "api-0".into());
    ctx.insert(vc::POD_NAMESPACE.into(), namespace.into());
    ctx.insert(vc::POD_UID.into(), "uid-1".into());
    ctx.insert(vc::SERVICE_ACCOUNT.into(), "api".into());
    ctx.insert(vc::AUDIENCES.into(), audiences.into());
    NodePublishVolumeRequest {
        volume_id: "csi-tokens".into(),
        target_path: target.display().to_string(),
        readonly: true,
        volume_context: ctx,
    }
}

fn token(target: &Path, name: &str) -> Claims {
    let jwt = std::fs::read_to_string(target.join(JWT_DIR).join(name)).unwrap();
    Claims::read_unverified(&jwt).unwrap()
}

#[tokio::test]
async fn a_declared_audience_arrives_as_a_file_beside_the_certificate() {
    let fx = fixture("publish", None, true).await;
    let target = fx.root.join("mount");
    fx.node
        .node_publish_volume(Request::new(publish(
            &target,
            "payments",
            &format!("azure={AZURE}"),
        )))
        .await
        .expect("published with its token");

    let claims = token(&target, "azure");
    assert_eq!(
        claims.sub,
        "spiffe://example.org/cluster/a/ns/payments/sa/api"
    );
    assert_eq!(claims.aud, AZURE);
    assert_eq!(claims.iss, ISSUER);
    // Never beyond the certificate in the same volume.
    let cert = std::fs::read_to_string(target.join("tls.crt")).unwrap();
    assert!(claims.exp <= svidlet_issue::inspect(&cert).unwrap().not_after);

    let entry = fx.publisher.store.get(&target).unwrap();
    assert_eq!(entry.audiences.len(), 1);
    assert_eq!(entry.tokens_expire_at, Some(claims.exp));
    common::remove_tree(&fx.root);
}

#[tokio::test]
async fn renewal_re_mints_the_tokens_for_the_new_certificate() {
    let fx = fixture("renew", None, true).await;
    let target = fx.root.join("mount");
    fx.node
        .node_publish_volume(Request::new(publish(
            &target,
            "payments",
            &format!("azure={AZURE}"),
        )))
        .await
        .unwrap();
    let first = token(&target, "azure");

    let entry = fx.publisher.store.get(&target).unwrap();
    let publisher = Arc::clone(&fx.publisher);
    tokio::task::spawn_blocking(move || svidlet::renew::renew_one(&publisher, &entry))
        .await
        .unwrap();
    // The certificate was renewed and the old token carried over unchanged...
    assert_eq!(token(&target, "azure").jti, first.jti);
    // ...until the token pass re-mints it.
    assert_eq!(svidlet::renew::mint_due(&fx.publisher).await, 1);
    let second = token(&target, "azure");
    assert_ne!(second.jti, first.jti);
    assert!(fx.publisher.store.tokens_due(i64::MAX).is_empty());
    common::remove_tree(&fx.root);
}

#[tokio::test]
async fn restart_recovers_the_audiences_from_the_published_tokens() {
    let fx = fixture("recover", None, true).await;
    let target = fx
        .root
        .join("kubelet/pods/uid-1/volumes/kubernetes.io~csi/svid/mount");
    std::fs::create_dir_all(target.parent().unwrap()).unwrap();
    std::fs::write(
        target.parent().unwrap().join("vol_data.json"),
        r#"{"driverName":"csi.svidlet.io","volumeHandle":"csi-tokens"}"#,
    )
    .unwrap();
    fx.node
        .node_publish_volume(Request::new(publish(
            &target,
            "payments",
            &format!("azure={AZURE}"),
        )))
        .await
        .unwrap();

    let restarted = Store::new();
    svidlet::recover::adopt(
        &fx.publisher.cfg,
        &fx.publisher.policy,
        &restarted,
        &fx.publisher.metrics,
    );
    let entry = restarted.get(&target).expect("adopted");
    assert_eq!(entry.audiences.len(), 1);
    assert_eq!(entry.audiences[0].name(), "azure");
    assert_eq!(entry.audiences[0].value(), AZURE);
    assert_eq!(entry.tokens_expire_at, Some(token(&target, "azure").exp));
    common::remove_tree(&fx.root);
}

#[tokio::test]
async fn an_audience_without_a_grant_keeps_the_pod_from_starting() {
    let fx = fixture("no-grant", None, true).await;
    let target = fx.root.join("mount");
    let status = fx
        .node
        .node_publish_volume(Request::new(publish(&target, "payments", "snowflake")))
        .await
        .expect_err("no grant for snowflake");
    assert_eq!(status.code(), tonic::Code::PermissionDenied, "{status}");
    assert!(fx.publisher.store.get(&target).is_none());
    assert!(!target.join("tls.crt").exists(), "nothing half-published");
    common::remove_tree(&fx.root);
}

#[tokio::test]
async fn an_unreachable_issuer_delays_the_pod_and_says_so() {
    let fx = fixture("down", Some("https://localhost:1"), true).await;
    let target = fx.root.join("mount");
    let status = fx
        .node
        .node_publish_volume(Request::new(publish(
            &target,
            "payments",
            &format!("azure={AZURE}"),
        )))
        .await
        .expect_err("the issuer is down");
    // Retryable: the kubelet tries again, as it does when Vault is down.
    assert_eq!(status.code(), tonic::Code::Unavailable, "{status}");
    common::remove_tree(&fx.root);
}

#[tokio::test]
async fn audiences_on_a_node_without_an_issuer_are_refused_up_front() {
    let fx = fixture("no-issuer", None, false).await;
    let target = fx.root.join("mount");
    let status = fx
        .node
        .node_publish_volume(Request::new(publish(&target, "payments", "azure=x")))
        .await
        .expect_err("no issuer configured");
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);

    // Without audiences the same node publishes as it always has.
    fx.node
        .node_publish_volume(Request::new(publish(&target, "payments", "")))
        .await
        .unwrap();
    assert!(!target.join(JWT_DIR).exists());
    common::remove_tree(&fx.root);
}

#[tokio::test]
async fn a_malformed_audiences_attribute_is_the_pods_error() {
    let fx = fixture("malformed", None, true).await;
    let status = fx
        .node
        .node_publish_volume(Request::new(publish(
            &fx.root.join("mount"),
            "payments",
            "api://needs-a-name",
        )))
        .await
        .expect_err("a URI is not a file name");
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    common::remove_tree(&fx.root);
}
