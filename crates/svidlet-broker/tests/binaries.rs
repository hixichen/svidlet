//! Smoke tests of the shipped binaries as separate processes: configuration
//! from the environment, TLS files on disk, and the real Kubernetes and Vault
//! clients speaking HTTP to wire-level stubs. What the in-process tests cannot
//! show — that `main` wires everything together — is what these are for.

mod common;

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use svidlet_issue::{
    BrokerClient, BrokerEndpoint, Issuer, JwtMinter, PodContext, SignRequest, SpiffeId,
};

// ------------------------------------------------------------ HTTP stubs

type Handler = dyn Fn(&str, &str, &HashMap<String, String>, &[u8]) -> (u16, String) + Send + Sync;

/// A tiny HTTP/1.1 server: one thread per connection, one request each.
fn serve(handler: Arc<Handler>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            let h = handler.clone();
            std::thread::spawn(move || answer(conn, &*h));
        }
    });
    addr
}

fn answer(mut conn: TcpStream, h: &Handler) {
    let mut reader = BufReader::new(conn.try_clone().unwrap());
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }
    let mut parts = line.split_whitespace();
    let (method, path) = (
        parts.next().unwrap_or("").to_string(),
        parts.next().unwrap_or("").to_string(),
    );
    let mut headers = HashMap::new();
    loop {
        let mut l = String::new();
        if reader.read_line(&mut l).unwrap_or(0) == 0 || l == "\r\n" {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let len: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    let _ = reader.read_exact(&mut body);
    let (status, payload) = h(&method, &path, &headers, &body);
    let _ = conn.write_all(
        format!(
            "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        )
        .as_bytes(),
    );
}

const KUBE_SA_TOKEN: &str = "broker-own-kube-token";
const VAULT_LOGIN_JWT: &str = "broker-projected-vault-token";

/// The API server, as far as the broker uses it.
fn kube_stub(kube: Arc<FakeKube>) -> String {
    serve(Arc::new(move |method, path, headers, body| {
        // HttpKube must authenticate with its own ServiceAccount token.
        if headers.get("authorization").map(String::as_str)
            != Some(&format!("Bearer {KUBE_SA_TOKEN}"))
        {
            return (401, r#"{"kind":"Status","code":401}"#.into());
        }
        if method == "POST" && path == "/apis/authentication.k8s.io/v1/tokenreviews" {
            let req: serde_json::Value = serde_json::from_slice(body).unwrap();
            let token = req["spec"]["token"].as_str().unwrap_or_default();
            let aud = req["spec"]["audiences"][0].as_str().unwrap_or_default();
            let status = match kube.reviews.lock().unwrap().get(token) {
                Some(r) => serde_json::json!({
                    "authenticated": true,
                    "audiences": [aud],
                    "user": {
                        "username": r.username,
                        "extra": {
                            "authentication.kubernetes.io/pod-name": [r.pod_name.clone().unwrap_or_default()],
                            "authentication.kubernetes.io/pod-uid": [r.pod_uid.clone().unwrap_or_default()],
                            "authentication.kubernetes.io/node-name": [r.node_name.clone().unwrap_or_default()],
                        }
                    }
                }),
                None => serde_json::json!({ "authenticated": false, "error": "invalid token" }),
            };
            return (
                201,
                serde_json::json!({ "kind": "TokenReview", "status": status }).to_string(),
            );
        }
        if let Some(rest) = path.strip_prefix("/api/v1/namespaces/") {
            let segs: Vec<&str> = rest.split('/').collect();
            if let [ns, "pods", name] = segs.as_slice() {
                return match kube.pods.lock().unwrap().get(&(ns.to_string(), name.to_string())) {
                    Some(p) => (
                        200,
                        serde_json::json!({
                            "metadata": {
                                "name": p.name, "namespace": p.namespace, "uid": p.uid,
                                "deletionTimestamp": if p.terminating { Some("2026-10-26T00:00:00Z") } else { None },
                                "ownerReferences": p.owners.iter().map(|(k, n)| serde_json::json!({"kind": k, "name": n})).collect::<Vec<_>>(),
                            },
                            "spec": {
                                "nodeName": p.node_name,
                                "serviceAccountName": p.service_account,
                                "containers": p.images.iter().map(|i| serde_json::json!({"image": i})).collect::<Vec<_>>(),
                            }
                        })
                        .to_string(),
                    ),
                    None => (404, r#"{"kind":"Status","code":404}"#.into()),
                };
            }
        }
        (404, "{}".into())
    }))
}

/// Vault, as far as the broker and the publisher use it: JWT auth, the PKI
/// role, and the SPIFFE engine.
fn vault_stub(ca: Arc<TestCa>, minter: Arc<FakeMinter>, issuer: &'static str) -> String {
    serve(Arc::new(move |method, path, headers, body| {
        let req: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
        let authed = headers.get("x-vault-token").map(String::as_str) == Some("s.broker");
        match (method, path) {
            ("POST", "/v1/auth/k8s-gpu-a/login") => {
                if req["role"] != "svidlet-broker" || req["jwt"] != VAULT_LOGIN_JWT {
                    return (400, r#"{"errors":["invalid role or jwt"]}"#.into());
                }
                (200, r#"{"auth":{"client_token":"s.broker","lease_duration":3600,"renewable":true}}"#.into())
            }
            ("POST", "/v1/pki_int/sign/spiffe-gpu-a") if authed => {
                let id = SpiffeId::parse(req["uri_sans"].as_str().unwrap()).unwrap();
                let ttl: u64 = req["ttl"].as_str().unwrap().trim_end_matches('s').parse().unwrap();
                let signed = ca
                    .sign(&SignRequest {
                        spiffe_id: &id,
                        csr_pem: req["csr"].as_str().unwrap(),
                        ttl: Duration::from_secs(ttl),
                        node_name: "n1",
                        pod: None,
                    })
                    .unwrap();
                (
                    200,
                    serde_json::json!({ "data": {
                        "certificate": signed.cert_chain_pem, "ca_chain": [ca.pem], "issuing_ca": ca.pem,
                    }})
                    .to_string(),
                )
            }
            ("POST", p) if authed && p.starts_with("/v1/spiffe/role/") && p.ends_with("/mintjwt") => {
                let role = p.trim_start_matches("/v1/spiffe/role/").trim_end_matches("/mintjwt");
                let token = minter.mint(role, req["audience"].as_str().unwrap()).unwrap();
                (200, serde_json::json!({ "data": { "token": token } }).to_string())
            }
            ("GET", "/v1/spiffe/.well-known/keys") => (200, minter.jwks_json()),
            ("GET", "/v1/spiffe/.well-known/openid-configuration") => (
                200,
                serde_json::json!({ "issuer": issuer, "jwks_uri": format!("{issuer}/.well-known/keys") }).to_string(),
            ),
            _ => (403, r#"{"errors":["permission denied"]}"#.into()),
        }
    }))
}

// -------------------------------------------------------------- processes

fn free_addr() -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().to_string()
}

struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_healthy(url: &str, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if let Ok(Some(status)) = child.try_wait() {
            let mut err = String::new();
            let _ = child.stderr.take().unwrap().read_to_string(&mut err);
            panic!("svidlet-broker exited early ({status}):\n{err}");
        }
        if ureq::get(url).call().is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("svidlet-broker did not become healthy");
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("svidlet-bin-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(dir: &Path, name: &str, body: &str) -> String {
    let p = dir.join(name);
    std::fs::write(&p, body).unwrap();
    p.display().to_string()
}

#[test]
fn the_broker_binary_issues_certificates_and_tokens_end_to_end() {
    let dir = scratch("broker");
    let ca = Arc::new(TestCa::new());
    let kube = FakeKube::cluster();
    let minter = FakeMinter::new();
    let kube_url = kube_stub(kube.clone());
    let vault_url = vault_stub(
        ca.clone(),
        minter.clone(),
        "https://oidc.corp.example/v1/spiffe",
    );

    let (cert, key) = ca.server();
    let (sign_addr, token_addr, metrics_addr) = (free_addr(), free_addr(), free_addr());
    let env: Vec<(&str, String)> = vec![
        ("SVIDLET_CLUSTER", CLUSTER.into()),
        ("SVIDLET_TRUST_DOMAIN", TD.into()),
        ("SVIDLET_BROKER_SIGN_ADDR", sign_addr.clone()),
        ("SVIDLET_BROKER_TOKEN_ADDR", token_addr.clone()),
        ("SVIDLET_BROKER_METRICS_ADDR", metrics_addr.clone()),
        ("SVIDLET_BROKER_TLS_CERT", write(&dir, "tls.crt", &cert)),
        ("SVIDLET_BROKER_TLS_KEY", write(&dir, "tls.key", &key)),
        ("SVIDLET_BROKER_CLIENT_CA", write(&dir, "ca.crt", &ca.pem)),
        ("SVIDLET_CATALOG", write(&dir, "catalog.toml", CATALOG)),
        ("SVIDLET_KUBE_API", kube_url),
        // Read at start-up; the stub is plain HTTP, so it is only parsed.
        (
            "SVIDLET_KUBE_CACERT",
            dir.join("ca.crt").display().to_string(),
        ),
        (
            "SVIDLET_KUBE_TOKEN_FILE",
            write(&dir, "kube-token", KUBE_SA_TOKEN),
        ),
        ("VAULT_ADDR", vault_url),
        ("SVIDLET_BROKER_VAULT_AUTH", "jwt".into()),
        (
            "SVIDLET_BROKER_VAULT_TOKEN_FILE",
            write(&dir, "vault-token", VAULT_LOGIN_JWT),
        ),
        ("SVIDLET_LOG_LEVEL", "debug".into()),
    ];
    let mut child = Command::new(env!("CARGO_BIN_EXE_svidlet-broker"))
        .env_clear()
        .envs(env)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_healthy(&format!("http://{metrics_addr}/healthz"), &mut child);
    let proc = Proc(child);

    // The node's own client, exactly as the plugin builds it.
    let client = BrokerClient::new(BrokerEndpoint {
        sign_url: format!(
            "https://localhost:{}",
            sign_addr.rsplit(':').next().unwrap()
        ),
        token_url: format!(
            "https://localhost:{}",
            token_addr.rsplit(':').next().unwrap()
        ),
        ca_cert_pem: ca.pem.clone(),
        node_token_path: PathBuf::from(write(&dir, "node-token", NODE_TOKEN)),
        timeout: Duration::from_secs(5),
    })
    .unwrap();
    let spiffe_id = SpiffeId::parse(&id("payments", "api")).unwrap();
    let generated = svidlet_issue::generate(&spiffe_id).unwrap();
    let bundle = client
        .sign(&SignRequest {
            spiffe_id: &spiffe_id,
            csr_pem: &generated.csr_pem,
            ttl: Duration::from_secs(3600),
            node_name: "n1",
            pod: Some(PodContext {
                namespace: "payments",
                name: "api-0",
                uid: "uid-api-0",
                service_account: "api",
                token: Some(POD_TOKEN),
            }),
        })
        .unwrap();
    assert_eq!(
        svidlet_issue::inspect(&bundle.cert_chain_pem)
            .unwrap()
            .spiffe_id,
        spiffe_id
    );
    // I11: the broker's 48 h, not the node's request.
    assert!(
        bundle.lifetime_secs() > 47 * 3600,
        "{}",
        bundle.lifetime_secs()
    );
    assert_eq!(client.ca_chain().unwrap(), ca.pem);

    let tokens = client
        .fetch_tokens(&bundle.cert_chain_pem, &generated.key_pem)
        .unwrap();
    assert_eq!(
        tokens.iter().map(|t| t.alias.as_str()).collect::<Vec<_>>(),
        vec!["aws", "vault"]
    );

    let metrics = ureq::get(&format!("http://{metrics_addr}/metrics"))
        .call()
        .unwrap()
        .body_mut()
        .read_to_string()
        .unwrap();
    assert!(
        metrics.contains(r#"svidlet_broker_requests_total{path="sign",outcome="ok",rule=""} 1"#),
        "{metrics}"
    );
    assert!(
        metrics.contains(r#"svidlet_broker_vault_seconds_count{op="mintjwt"} 2"#),
        "{metrics}"
    );

    // SIGINT shuts it down cleanly.
    let mut child = proc;
    let pid = child.0.id().to_string();
    assert!(Command::new("kill")
        .args(["-INT", &pid])
        .status()
        .unwrap()
        .success());
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(s) = child.0.try_wait().unwrap() {
            break s;
        }
        assert!(Instant::now() < deadline, "did not exit on SIGINT");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(status.success(), "{status}");
    let mut log = String::new();
    child
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut log)
        .unwrap();
    // I12/T8: decisions are audited, token values never logged.
    assert!(log.contains("certificate issued"), "{log}");
    assert!(log.contains("token issued"), "{log}");
    for secret in [
        POD_TOKEN,
        NODE_TOKEN,
        VAULT_LOGIN_JWT,
        KUBE_SA_TOKEN,
        tokens[0].token.as_str(),
    ] {
        assert!(!log.contains(secret), "{secret} appears in the log");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_broker_binary_refuses_to_start_on_bad_configuration() {
    let dir = scratch("badcfg");
    for (env, expect) in [
        (vec![("SVIDLET_TRUST_DOMAIN", "td")], "SVIDLET_CLUSTER"),
        (
            vec![
                ("SVIDLET_CLUSTER", "c"),
                ("SVIDLET_TRUST_DOMAIN", "td"),
                ("VAULT_ADDR", "http://127.0.0.1:1"),
                (
                    "SVIDLET_SPIFFE_ID_TEMPLATE",
                    "spiffe://{trust_domain}/ns/{namespace}/sa/{service_account}",
                ),
            ],
            "{cluster}",
        ),
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_svidlet-broker"))
            .env_clear()
            .envs(env)
            .current_dir(&dir)
            .output()
            .unwrap();
        assert!(!out.status.success());
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains(expect), "{err}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn oidc_publisher_writes_only_what_it_can_vouch_for() {
    let ca = Arc::new(TestCa::new());
    let minter = FakeMinter::new();
    let good = vault_stub(
        ca.clone(),
        minter.clone(),
        "https://oidc.corp.example/v1/spiffe",
    );
    let lying = vault_stub(ca, minter, "https://evil.example/v1/spiffe");

    let run = |vault: &str, out: &Path| {
        Command::new(env!("CARGO_BIN_EXE_oidc-publisher"))
            .env_clear()
            .env("VAULT_ADDR", vault)
            .env("OIDC_ISSUER", "https://oidc.corp.example/v1/spiffe")
            .env("OIDC_OUT_DIR", out)
            .env("OIDC_INTERVAL", "0")
            .output()
            .unwrap()
    };

    let out = scratch("oidc-good");
    let r = run(&good, &out);
    assert!(r.status.success(), "{}", String::from_utf8_lossy(&r.stderr));
    let keys = std::fs::read_to_string(out.join("v1/spiffe/.well-known/keys")).unwrap();
    assert!(svidlet_issue::jwt::Jwks::parse(&keys)
        .unwrap()
        .contains("k1"));
    assert!(out
        .join("v1/spiffe/.well-known/openid-configuration")
        .exists());

    let bad = scratch("oidc-bad");
    let r = run(&lying, &bad);
    assert!(
        !r.status.success(),
        "a mismatched issuer must fail a run-once publish"
    );
    assert!(!bad.join("v1").exists(), "nothing written");
    std::fs::remove_dir_all(&out).unwrap();
    std::fs::remove_dir_all(&bad).unwrap();
}

#[test]
fn svidlet_catalog_lints_and_renders() {
    let dir = scratch("catalog");
    let good = write(&dir, "good.toml", CATALOG);
    let bad = write(&dir, "bad.toml", "schema = 2\ntrust_domain = \"td\"\n");
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_svidlet-catalog"))
            .args(args)
            .output()
            .unwrap()
    };

    assert!(run(&["lint", &good]).status.success());
    assert_eq!(run(&["lint", &bad]).status.code(), Some(1));
    assert_eq!(run(&["frobnicate", &good]).status.code(), Some(2));
    assert_eq!(
        run(&["policy", &good]).status.code(),
        Some(2),
        "policy needs a cluster"
    );

    let policy = String::from_utf8(run(&["policy", &good, "gpu-a"]).stdout).unwrap();
    assert!(
        policy.contains(r#"path "pki_int/sign/spiffe-gpu-a""#),
        "{policy}"
    );
    assert!(
        policy.contains(r#"path "spiffe/role/gpu-a__payments__api/mintjwt""#),
        "{policy}"
    );
    let roles = String::from_utf8(run(&["roles", &good, "gpu-b"]).stdout).unwrap();
    assert!(
        !roles.contains("payments"),
        "gpu-a's identity is not rendered for gpu-b: {roles}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
