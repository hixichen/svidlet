//! The issuer over its real transport: gRPC with mutual TLS, and HTTP.

use std::sync::Arc;
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use svidlet_token::pop;
use svidlet_token::proto::token_issuer_client::TokenIssuerClient;
use svidlet_token::proto::MintRequest;
use svidlet_token::Claims;
use svidlet_token_issuer::grants::{Grant, Grants};
use svidlet_token_issuer::keys::{Key, KeyPool};
use svidlet_token_issuer::mint::Minter;
use svidlet_token_issuer::server::{self, Metrics, Service};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

const NODE: &str = "spiffe://example.org/cluster/a/node/n1";
const POD: &str = "spiffe://example.org/cluster/a/ns/payments/sa/api";

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

fn leaf(by: &Ca, sans: Vec<SanType>) -> (String, String) {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::default();
    params.subject_alt_names = sans;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::minutes(5);
    params.not_after = now + time::Duration::hours(6);
    (
        params.signed_by(&key, &by.issuer).unwrap().pem(),
        key.serialize_pem(),
    )
}

fn uri(u: &str) -> SanType {
    SanType::URI(u.try_into().unwrap())
}

struct Running {
    grpc: String,
    http: String,
    pod_ca: Ca,
    node_ca: Ca,
}

async fn start() -> Running {
    let pod_ca = ca("vault pki");
    let node_ca = ca("step-ca");
    // The issuer's own serving certificate comes from the Vault CA, so nodes
    // verify it with the ca.crt they already hold.
    let (server_cert, server_key) = leaf(
        &pod_ca,
        vec![SanType::DnsName("localhost".try_into().unwrap())],
    );

    let der = ring::signature::EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &ring::rand::SystemRandom::new(),
    )
    .unwrap();
    let minter = Minter::new(
        "https://tokens.example.org",
        "example.org",
        Duration::from_secs(21_600),
        &pod_ca.pem,
        KeyPool::new(vec![Key::from_pkcs8(der.as_ref(), true).unwrap()]).unwrap(),
        Grants::new(
            "example.org",
            vec![Grant {
                prefix: "spiffe://example.org/cluster/a/ns/payments/".into(),
                audiences: vec!["api://AzureADTokenExchange".into()],
            }],
        )
        .unwrap(),
    )
    .unwrap();
    let minter = Arc::new(minter);
    let metrics = Arc::new(Metrics::default());

    let grpc = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let grpc_addr = grpc.local_addr().unwrap();
    let node_ca_pem = node_ca.pem.clone();
    let service = Service::new(Arc::clone(&minter), Arc::clone(&metrics));
    tokio::spawn(async move {
        server::serve_grpc(grpc, &server_cert, &server_key, &node_ca_pem, service)
            .await
            .unwrap();
    });
    let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http.local_addr().unwrap();
    tokio::spawn(server::serve_http(http, true, minter, metrics));

    Running {
        grpc: format!("https://localhost:{}", grpc_addr.port()),
        http: http_addr.to_string(),
        pod_ca,
        node_ca,
    }
}

fn client(run: &Running, identity: Option<(&str, &str)>) -> TokenIssuerClient<Channel> {
    let mut tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(&run.pod_ca.pem))
        .domain_name("localhost");
    if let Some((cert, key)) = identity {
        tls = tls.identity(Identity::from_pem(cert, key));
    }
    let channel = Channel::from_shared(run.grpc.clone())
        .unwrap()
        .tls_config(tls)
        .unwrap()
        .connect_lazy();
    TokenIssuerClient::new(channel)
}

const AZURE: &str = "api://AzureADTokenExchange";

fn request(chain: &str, key: &str, aud: &str) -> MintRequest {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    MintRequest {
        pod_cert_chain_pem: chain.into(),
        audience: aud.into(),
        proof_time: now,
        proof: pop::sign(key, &pop::message(NODE, POD, aud, now)).unwrap(),
    }
}

async fn get(addr: &str, path: &str) -> String {
    let mut conn = TcpStream::connect(addr).await.unwrap();
    conn.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut out = String::new();
    conn.read_to_string(&mut out).await.unwrap();
    out
}

#[tokio::test]
async fn a_node_mints_over_mutual_tls() {
    let run = start().await;
    let (node_cert, node_key) = leaf(&run.node_ca, vec![uri(NODE)]);
    let (pod_chain, pod_key) = leaf(&run.pod_ca, vec![uri(POD)]);

    let mut client = client(&run, Some((&node_cert, &node_key)));
    let response = client
        .mint(request(&pod_chain, &pod_key, AZURE))
        .await
        .expect("the issuer mints")
        .into_inner();
    let claims = Claims::read_unverified(&response.token).unwrap();
    assert_eq!(claims.sub, POD);
    assert_eq!(claims.aud, "api://AzureADTokenExchange");
    assert_eq!(claims.exp, response.expires_at);

    // The same connection serves the next request: one channel per node.
    client
        .mint(request(&pod_chain, &pod_key, AZURE))
        .await
        .unwrap();
}

#[tokio::test]
async fn a_refusal_is_a_grpc_status_that_says_why() {
    let run = start().await;
    let (node_cert, node_key) = leaf(&run.node_ca, vec![uri(NODE)]);
    let (pod_chain, pod_key) = leaf(&run.pod_ca, vec![uri(POD)]);
    // Signed correctly for an audience the identity has no grant for.
    let req = request(&pod_chain, &pod_key, "snowflake");
    let status = client(&run, Some((&node_cert, &node_key)))
        .mint(req)
        .await
        .expect_err("no grant for this audience");
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
    assert!(status.message().contains("grant"), "{}", status.message());
}

#[tokio::test]
async fn without_a_node_certificate_there_is_no_connection() {
    let run = start().await;
    let (pod_chain, pod_key) = leaf(&run.pod_ca, vec![uri(POD)]);

    // No client certificate at all.
    let status = client(&run, None)
        .mint(request(&pod_chain, &pod_key, AZURE))
        .await
        .expect_err("the handshake requires a client certificate");
    assert_ne!(status.code(), tonic::Code::Ok);

    // A client certificate, but from the pod CA rather than the node CA: a
    // workload cannot call the issuer with its own SVID.
    let (pod_as_client, key) = leaf(&run.pod_ca, vec![uri(NODE)]);
    let status = client(&run, Some((&pod_as_client, &key)))
        .mint(request(&pod_chain, &pod_key, AZURE))
        .await
        .expect_err("only the node CA may call");
    assert_ne!(status.code(), tonic::Code::Ok);
}

#[tokio::test]
async fn discovery_and_the_jwks_are_served_publicly() {
    let run = start().await;
    let discovery = get(&run.http, "/.well-known/openid-configuration").await;
    assert!(discovery.starts_with("HTTP/1.1 200"), "{discovery}");
    assert!(discovery.contains(r#""jwks_uri":"https://tokens.example.org/.well-known/jwks.json""#));
    let jwks = get(&run.http, "/.well-known/jwks.json").await;
    assert!(jwks.contains(r#""alg":"ES256""#), "{jwks}");
    // Metrics are not on the public listener.
    assert!(get(&run.http, "/metrics").await.starts_with("HTTP/1.1 404"));
}
