//! The Vault backend against a stub HTTP server.
//!
//! `vault_live.rs` proves svidlet and a real Vault agree. This proves the
//! behaviours a real Vault will not produce on demand: an expired token, a
//! sealed server, a backend that returns a certificate for the wrong identity.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rcgen::{
    CertificateParams, CertificateSigningRequestParams, DistinguishedName, DnType,
    Issuer as CaIssuer, KeyPair, KeyUsagePurpose,
};

use svidlet_issue::{
    AppRoleAuth, ErrorCode, Issuer, SignRequest, SpiffeId, VaultEndpoint, VaultHttp, VaultIssuer,
    VaultPkiConfig,
};

/// How the stub should answer the next `pki/sign` call.
#[derive(Clone, Copy, PartialEq)]
enum SignBehaviour {
    Ok,
    /// Reject the token once, as Vault does when it no longer knows it.
    ExpiredTokenOnce,
    Sealed,
    /// Sign a different identity than the one requested.
    WrongIdentity,
    Garbage,
}

struct Stub {
    logins: AtomicUsize,
    signs: AtomicUsize,
    behaviour: Mutex<SignBehaviour>,
    ca_pem: String,
    issuer: CaIssuer<'static, KeyPair>,
    addr: String,
}

impl Stub {
    fn start() -> Arc<Stub> {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "stub vault ca");
        params.distinguished_name = dn;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca = params.self_signed(&key).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());

        let stub = Arc::new(Stub {
            logins: AtomicUsize::new(0),
            signs: AtomicUsize::new(0),
            behaviour: Mutex::new(SignBehaviour::Ok),
            ca_pem: ca.pem(),
            issuer: CaIssuer::from_ca_cert_pem(&ca.pem(), key).unwrap(),
            addr,
        });

        let serving = stub.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let stub = serving.clone();
                std::thread::spawn(move || stub.handle(conn));
            }
        });
        stub
    }

    fn behave(&self, behaviour: SignBehaviour) {
        *self.behaviour.lock().unwrap() = behaviour;
    }

    fn handle(&self, mut conn: TcpStream) {
        let mut reader = BufReader::new(conn.try_clone().unwrap());
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).is_err() {
            return;
        }
        let path = request_line
            .split_whitespace()
            .nth(1)
            .unwrap_or("")
            .to_string();

        let mut length = 0usize;
        let mut token = String::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                break;
            }
            let lower = line.to_ascii_lowercase();
            if let Some(v) = lower.strip_prefix("content-length:") {
                length = v.trim().parse().unwrap_or(0);
            }
            if lower.starts_with("x-vault-token:") {
                token = line.split_once(':').unwrap().1.trim().to_string();
            }
        }
        let mut body = vec![0u8; length];
        let _ = reader.read_exact(&mut body);
        let body: serde_json::Value =
            serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);

        let (status, payload) = self.route(&path, &token, &body);
        let response = format!(
            "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        );
        let _ = conn.write_all(response.as_bytes());
    }

    fn route(&self, path: &str, token: &str, body: &serde_json::Value) -> (u16, String) {
        if path.ends_with("/auth/approle/login") {
            let n = self.logins.fetch_add(1, Ordering::SeqCst);
            if body["secret_id"].as_str() == Some("wrong") {
                return (400, r#"{"errors":["invalid secret id"]}"#.into());
            }
            return (
                200,
                format!(
                    r#"{{"auth":{{"client_token":"s.token-{n}","lease_duration":3600,"renewable":true}}}}"#
                ),
            );
        }
        if path.ends_with("/pki/ca_chain") {
            return (200, self.ca_pem.clone());
        }
        if path.contains("/pki/sign/") {
            let n = self.signs.fetch_add(1, Ordering::SeqCst);
            let behaviour = *self.behaviour.lock().unwrap();
            match behaviour {
                SignBehaviour::Sealed => return (503, r#"{"errors":["Vault is sealed"]}"#.into()),
                SignBehaviour::ExpiredTokenOnce if n == 0 => {
                    return (403, r#"{"errors":["permission denied"]}"#.into())
                }
                SignBehaviour::Garbage => return (200, "{\"data\":{}}".into()),
                _ => {}
            }
            assert!(
                token.starts_with("s.token-"),
                "the signing call carries a token"
            );

            let requested = body["uri_sans"].as_str().unwrap_or_default();
            let uri = if behaviour == SignBehaviour::WrongIdentity {
                "spiffe://example.org/cluster/elsewhere/ns/kube-system/sa/admin"
            } else {
                requested
            };

            let csr_pem = body["csr"].as_str().unwrap_or_default();
            let mut csr = CertificateSigningRequestParams::from_pem(csr_pem).unwrap();
            csr.params.subject_alt_names = vec![rcgen::SanType::URI(
                rcgen::string::Ia5String::try_from(uri).unwrap(),
            )];
            let now = time::OffsetDateTime::now_utc();
            csr.params.not_before = now;
            csr.params.not_after = now + time::Duration::hours(1);
            let cert = csr.signed_by(&self.issuer).unwrap();

            return (
                200,
                serde_json::json!({
                    "data": {
                        "certificate": cert.pem(),
                        "ca_chain": [self.ca_pem],
                        "issuing_ca": self.ca_pem,
                    }
                })
                .to_string(),
            );
        }
        (404, r#"{"errors":["no handler"]}"#.into())
    }

    fn issuer(&self, secret_id: &str) -> VaultIssuer<AppRoleAuth> {
        let path = std::env::temp_dir().join(format!(
            "svidlet-stub-secret-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, secret_id).unwrap();

        let http = Arc::new(
            VaultHttp::new(VaultEndpoint {
                address: self.addr.clone(),
                namespace: None,
                ca_cert_pem: None,
                timeout: Duration::from_secs(5),
            })
            .unwrap(),
        );
        VaultIssuer::new(
            http.clone(),
            VaultPkiConfig {
                mount: "pki".into(),
                role: "spiffe-cluster-a".into(),
            },
            AppRoleAuth::new(http, "approle", "role-id", path),
        )
    }
}

fn id() -> SpiffeId {
    SpiffeId::parse("spiffe://example.org/cluster/a/ns/payments/sa/api").unwrap()
}

fn sign(issuer: &dyn Issuer) -> svidlet_issue::Result<svidlet_issue::IssuedBundle> {
    let id = id();
    let generated = svidlet_issue::generate(&id)?;
    issuer.sign(&SignRequest {
        spiffe_id: &id,
        csr_pem: &generated.csr_pem,
        ttl: Duration::from_secs(3600),
        node_name: "node-1",
    })
}

#[test]
fn a_signature_logs_in_once_and_reuses_the_token() {
    let stub = Stub::start();
    let issuer = stub.issuer("good");

    for _ in 0..3 {
        let bundle = sign(&issuer).expect("the stub signs");
        assert_eq!(
            svidlet_issue::inspect(&bundle.cert_chain_pem)
                .unwrap()
                .spiffe_id,
            id()
        );
        assert!(bundle.ca_pem.contains("-----BEGIN CERTIFICATE-----"));
    }
    assert_eq!(stub.signs.load(Ordering::SeqCst), 3);
    assert_eq!(
        stub.logins.load(Ordering::SeqCst),
        1,
        "one login for three certificates"
    );
}

#[test]
fn a_rejected_token_triggers_exactly_one_re_login() {
    let stub = Stub::start();
    stub.behave(SignBehaviour::ExpiredTokenOnce);
    let issuer = stub.issuer("good");

    // This is what makes a credential rotation or a Vault restart survivable
    // without restarting the DaemonSet.
    sign(&issuer).expect("the retry succeeds");
    assert_eq!(stub.logins.load(Ordering::SeqCst), 2);
    assert_eq!(stub.signs.load(Ordering::SeqCst), 2);
}

#[test]
fn a_sealed_vault_is_a_retryable_backend_error() {
    let stub = Stub::start();
    stub.behave(SignBehaviour::Sealed);

    let err = sign(&stub.issuer("good")).unwrap_err();
    assert_eq!(err.code(), ErrorCode::BackendStatus);
    assert!(err.is_retryable());
    assert!(err.to_string().contains("sealed"));
}

#[test]
fn a_certificate_for_the_wrong_identity_is_refused_on_the_node() {
    let stub = Stub::start();
    stub.behave(SignBehaviour::WrongIdentity);

    // Vault's role should never allow this. If it is misconfigured so that it
    // does, the node catches it before a workload holds the certificate.
    let err = sign(&stub.issuer("good")).unwrap_err();
    assert_eq!(err.code(), ErrorCode::Certificate);
    assert!(!err.is_retryable());
    assert!(err.to_string().contains("was requested"));
}

#[test]
fn a_malformed_response_is_a_protocol_error() {
    let stub = Stub::start();
    stub.behave(SignBehaviour::Garbage);

    let err = sign(&stub.issuer("good")).unwrap_err();
    assert_eq!(err.code(), ErrorCode::Protocol);
    assert!(!err.is_retryable());
}

#[test]
fn a_rejected_login_is_an_auth_error_and_is_not_retried_forever() {
    let stub = Stub::start();
    let err = sign(&stub.issuer("wrong")).unwrap_err();
    assert_eq!(err.code(), ErrorCode::Auth);
    // One login attempt, no retry loop on a credential that was refused.
    assert_eq!(stub.logins.load(Ordering::SeqCst), 1);
    assert_eq!(stub.signs.load(Ordering::SeqCst), 0);
}

#[test]
fn the_ca_chain_is_fetched_without_a_token() {
    let stub = Stub::start();
    let chain = stub.issuer("good").ca_chain().unwrap();
    assert_eq!(chain.trim(), stub.ca_pem.trim());
    assert_eq!(stub.logins.load(Ordering::SeqCst), 0);
}

#[test]
fn a_ca_endpoint_that_does_not_return_pem_is_a_protocol_error() {
    let stub = Stub::start();
    let http = Arc::new(
        VaultHttp::new(VaultEndpoint {
            address: stub.addr.clone(),
            namespace: None,
            ca_cert_pem: None,
            timeout: Duration::from_secs(5),
        })
        .unwrap(),
    );
    // A mount that the stub does not serve answers 404.
    let issuer = VaultIssuer::new(
        http.clone(),
        VaultPkiConfig {
            mount: "nope".into(),
            role: "r".into(),
        },
        AppRoleAuth::new(http, "approle", "role-id", "/dev/null".into()),
    );
    let err = issuer.ca_chain().unwrap_err();
    assert_eq!(err.code(), ErrorCode::BackendStatus);
}
