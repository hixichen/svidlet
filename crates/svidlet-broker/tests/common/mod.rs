//! Fixtures shared by the broker's integration tests: a CA standing in for
//! Vault PKI, a minter standing in for Vault's SPIFFE engine, and an API
//! server that answers TokenReviews and Pod reads from tables.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use time::OffsetDateTime;

use svidlet_broker::catalog::CatalogHandle;
use svidlet_broker::config::Config;
use svidlet_broker::kube::{Kube, KubeError, Pod, Review};
use svidlet_broker::sign::Signer;
use svidlet_broker::tokens::{JwksSource, Tokens};
use svidlet_issue::{Catalog, IssuedBundle, JwtMinter, SignRequest};

pub const CLUSTER: &str = "gpu-a";
pub const TD: &str = "corp.internal";
pub const NODE_TOKEN: &str = "node-token-n1";
pub const NODE_TOKEN_N2: &str = "node-token-n2";
pub const POD_TOKEN: &str = "pod-token-api";

pub fn now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

pub fn id(ns: &str, sa: &str) -> String {
    format!("spiffe://{TD}/cluster/{CLUSTER}/ns/{ns}/sa/{sa}")
}

// --------------------------------------------------------------------- PKI

pub struct TestCa {
    pub issuer: Issuer<'static, KeyPair>,
    pub pem: String,
    pub signed: Mutex<Vec<String>>,
    pub fail: Mutex<Option<svidlet_issue::Error>>,
}

impl TestCa {
    pub fn new() -> TestCa {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "test intermediate");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let cert = params.self_signed(&key).unwrap();
        TestCa {
            pem: cert.pem(),
            issuer: Issuer::from_ca_cert_pem(&cert.pem(), key).unwrap(),
            signed: Mutex::new(Vec::new()),
            fail: Mutex::new(None),
        }
    }

    /// An SVID leaf for `uris`, valid from `nb` to `na` (Unix seconds).
    pub fn leaf(&self, uris: &[&str], nb: i64, na: i64, ca: bool) -> (String, String) {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.subject_alt_names = uris
            .iter()
            .map(|u| SanType::URI(rcgen::string::Ia5String::try_from(*u).unwrap()))
            .collect();
        params.not_before = OffsetDateTime::from_unix_timestamp(nb).unwrap();
        params.not_after = OffsetDateTime::from_unix_timestamp(na).unwrap();
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        if ca {
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        }
        let cert = params.signed_by(&key, &self.issuer).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    pub fn leaf_der(&self, uris: &[&str], nb: i64, na: i64, ca: bool) -> Vec<u8> {
        let (pem, _) = self.leaf(uris, nb, na, ca);
        let (_, block) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();
        block.contents
    }

    /// A serving certificate for `localhost`.
    pub fn server(&self) -> (String, String) {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let cert = params.signed_by(&key, &self.issuer).unwrap();
        (cert.pem(), key.serialize_pem())
    }
}

impl svidlet_issue::Issuer for TestCa {
    fn sign(&self, request: &SignRequest<'_>) -> svidlet_issue::Result<IssuedBundle> {
        if let Some(e) = self.fail.lock().unwrap().take() {
            return Err(e);
        }
        let mut csr = CertificateSigningRequestParams::from_pem(request.csr_pem)
            .map_err(|e| svidlet_issue::Error::Protocol(e.to_string()))?;
        // As the Vault role does: the URI SAN is the requested one, nothing
        // from the CSR survives.
        csr.params.subject_alt_names = vec![SanType::URI(
            rcgen::string::Ia5String::try_from(request.spiffe_id.as_str()).unwrap(),
        )];
        let now = OffsetDateTime::now_utc();
        csr.params.not_before = now;
        csr.params.not_after = now + time::Duration::seconds(request.ttl.as_secs() as i64);
        csr.params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ];
        let cert = csr
            .signed_by(&self.issuer)
            .map_err(|e| svidlet_issue::Error::Protocol(e.to_string()))?;
        self.signed
            .lock()
            .unwrap()
            .push(request.spiffe_id.to_string());
        let facts = svidlet_issue::assert_identity(&cert.pem(), request.spiffe_id)?;
        Ok(IssuedBundle {
            cert_chain_pem: cert.pem(),
            ca_pem: self.pem.clone(),
            not_after: facts.not_after,
            not_before: facts.not_before,
        })
    }

    fn ca_chain(&self) -> svidlet_issue::Result<String> {
        Ok(self.pem.clone())
    }

    fn name(&self) -> &'static str {
        "test-ca"
    }
}

// ----------------------------------------------------------------- minter

pub struct FakeMinter {
    pub mints: AtomicUsize,
    pub kid: Mutex<String>,
    pub ttl: Mutex<i64>,
    pub denied_audiences: Mutex<Vec<String>>,
    pub down: Mutex<bool>,
    pub published: Mutex<Vec<String>>,
}

impl FakeMinter {
    pub fn new() -> Arc<FakeMinter> {
        Arc::new(FakeMinter {
            mints: AtomicUsize::new(0),
            kid: Mutex::new("k1".into()),
            ttl: Mutex::new(6 * 3600),
            denied_audiences: Mutex::new(Vec::new()),
            down: Mutex::new(false),
            published: Mutex::new(vec!["k1".into()]),
        })
    }

    pub fn mints(&self) -> usize {
        self.mints.load(Ordering::SeqCst)
    }

    pub fn jwks_json(&self) -> String {
        let keys: Vec<String> = self
            .published
            .lock()
            .unwrap()
            .iter()
            .map(|k| format!(r#"{{"kid":"{k}","kty":"EC","crv":"P-256","x":"AAAA","y":"AAAA"}}"#))
            .collect();
        format!(r#"{{"keys":[{}]}}"#, keys.join(","))
    }
}

impl JwtMinter for FakeMinter {
    fn mint(&self, role: &str, audience: &str) -> svidlet_issue::Result<String> {
        if *self.down.lock().unwrap() {
            return Err(svidlet_issue::Error::Transport("vault down".into()));
        }
        if self
            .denied_audiences
            .lock()
            .unwrap()
            .iter()
            .any(|a| a == audience)
        {
            return Err(svidlet_issue::Error::Backend {
                status: 403,
                body: "permission denied".into(),
            });
        }
        let n = self.mints.fetch_add(1, Ordering::SeqCst) as i64;
        // gpu-a__payments__api → the identity Vault's role template fixes.
        let parts: Vec<&str> = role.split("__").collect();
        let sub = format!(
            "spiffe://{TD}/cluster/{}/ns/{}/sa/{}",
            parts[0], parts[1], parts[2]
        );
        let iat = now();
        let ttl = *self.ttl.lock().unwrap();
        let token = svidlet_issue::jwt::test_token(
            &self.kid.lock().unwrap(),
            &sub,
            audience,
            iat,
            iat + ttl,
        );
        // A distinct signature per mint, so two tokens never compare equal.
        Ok(format!("{token}{n}"))
    }

    fn jwks(&self) -> svidlet_issue::Result<String> {
        Ok(self.jwks_json())
    }
}

// --------------------------------------------------------------- kube

#[derive(Default)]
pub struct FakeKube {
    pub reviews: Mutex<HashMap<String, Review>>,
    pub pods: Mutex<HashMap<(String, String), Pod>>,
    pub down: Mutex<bool>,
    pub calls: AtomicUsize,
}

impl Kube for FakeKube {
    fn token_review(&self, token: &str, audience: &str) -> Result<Option<Review>, KubeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if *self.down.lock().unwrap() {
            return Err(KubeError::Unavailable("connection refused".into()));
        }
        assert_eq!(audience, "svidlet-broker");
        Ok(self.reviews.lock().unwrap().get(token).cloned())
    }

    fn pod(&self, namespace: &str, name: &str) -> Result<Option<Pod>, KubeError> {
        if *self.down.lock().unwrap() {
            return Err(KubeError::Unavailable("connection refused".into()));
        }
        Ok(self
            .pods
            .lock()
            .unwrap()
            .get(&(namespace.to_string(), name.to_string()))
            .cloned())
    }
}

impl FakeKube {
    /// Node n1 and n2 each run a svidlet-node pod; pod payments/api runs on n1.
    pub fn cluster() -> Arc<FakeKube> {
        let k = FakeKube::default();
        for (token, pod, uid, node) in [
            (NODE_TOKEN, "svidlet-node-aaaaa", "uid-node-1", "n1"),
            (NODE_TOKEN_N2, "svidlet-node-bbbbb", "uid-node-2", "n2"),
        ] {
            k.reviews.lock().unwrap().insert(
                token.into(),
                Review {
                    username: "system:serviceaccount:svidlet-system:svidlet-node".into(),
                    pod_name: Some(pod.into()),
                    pod_uid: Some(uid.into()),
                    node_name: Some(node.into()),
                },
            );
            k.pods.lock().unwrap().insert(
                ("svidlet-system".into(), pod.into()),
                Pod {
                    namespace: "svidlet-system".into(),
                    name: pod.into(),
                    uid: uid.into(),
                    node_name: node.into(),
                    service_account: "svidlet-node".into(),
                    terminating: false,
                    images: vec!["registry.corp.example/svidlet@sha256:00".into()],
                    owners: vec![("DaemonSet".into(), "svidlet-node".into())],
                },
            );
        }
        k.add_pod(POD_TOKEN, "payments", "api", "api-0", "uid-api-0", "n1");
        Arc::new(k)
    }

    pub fn add_pod(&self, token: &str, ns: &str, sa: &str, name: &str, uid: &str, node: &str) {
        self.reviews.lock().unwrap().insert(
            token.into(),
            Review {
                username: format!("system:serviceaccount:{ns}:{sa}"),
                pod_name: Some(name.into()),
                pod_uid: Some(uid.into()),
                node_name: Some(node.into()),
            },
        );
        self.pods.lock().unwrap().insert(
            (ns.into(), name.into()),
            Pod {
                namespace: ns.into(),
                name: name.into(),
                uid: uid.into(),
                node_name: node.into(),
                service_account: sa.into(),
                terminating: false,
                images: vec!["registry.corp.example/payments@sha256:abc".into()],
                owners: vec![("ReplicaSet".into(), format!("{name}-rs"))],
            },
        );
    }

    pub fn edit_pod(&self, ns: &str, name: &str, f: impl FnOnce(&mut Pod)) {
        f(self
            .pods
            .lock()
            .unwrap()
            .get_mut(&(ns.to_string(), name.to_string()))
            .unwrap());
    }
}

// ------------------------------------------------------------ assembly

pub const CATALOG: &str = r#"
schema = 1
trust_domain = "corp.internal"

[sensitive]
registries = ["registry.corp.example/"]

[[identity]]
cluster = "gpu-a"
namespace = "payments"
service_account = "api"
sensitive = true
audiences = [
  { alias = "aws", audience = "sts.amazonaws.com" },
  { alias = "vault", audience = "vault" },
]

[[identity]]
cluster = "*"
namespace = "batch"
service_account = "runner"
"#;

pub fn config(extra: &[(&str, &str)]) -> Config {
    let mut vars: HashMap<String, String> = HashMap::from([
        ("SVIDLET_CLUSTER".into(), CLUSTER.into()),
        ("SVIDLET_TRUST_DOMAIN".into(), TD.into()),
        ("VAULT_ADDR".into(), "https://vault.invalid".into()),
        ("SVIDLET_NODE_RATE_PER_MINUTE".into(), "1000".into()),
    ]);
    for (k, v) in extra {
        vars.insert(k.to_string(), v.to_string());
    }
    Config::from_source(&|k| vars.get(k).cloned()).unwrap()
}

pub struct Fx {
    pub cfg: Arc<Config>,
    pub ca: Arc<TestCa>,
    pub kube: Arc<FakeKube>,
    pub minter: Arc<FakeMinter>,
    pub catalog: CatalogHandle,
    pub signer: Signer,
    pub tokens: Tokens,
}

pub fn fixture_with(catalog: &str, extra: &[(&str, &str)]) -> Fx {
    let cfg = Arc::new(config(extra));
    let policy = Arc::new(cfg.id_policy().unwrap());
    let ca = Arc::new(TestCa::new());
    let kube = FakeKube::cluster();
    let minter = FakeMinter::new();
    let catalog = CatalogHandle::fixed(Catalog::parse(catalog).unwrap());
    let m = minter.clone();
    let jwks = Arc::new(JwksSource::new(Box::new(move || Ok(m.jwks_json()))));
    jwks.refresh().unwrap();
    Fx {
        signer: Signer::new(
            cfg.clone(),
            policy.clone(),
            kube.clone(),
            ca.clone(),
            catalog.clone(),
        ),
        tokens: Tokens::new(cfg.clone(), policy, minter.clone(), catalog.clone(), jwks),
        cfg,
        ca,
        kube,
        minter,
        catalog,
    }
}

pub fn fixture() -> Fx {
    fixture_with(CATALOG, &[])
}

pub fn csr_for(spiffe_id: &str) -> String {
    let id = svidlet_issue::SpiffeId::parse(spiffe_id).unwrap();
    svidlet_issue::generate(&id).unwrap().csr_pem
}

pub fn sign_body(pod_token: &str) -> svidlet_issue::broker::SignBody {
    svidlet_issue::broker::SignBody {
        pod_token: pod_token.into(),
        namespace: "payments".into(),
        pod_name: "api-0".into(),
        pod_uid: "uid-api-0".into(),
        service_account: "api".into(),
        csr: csr_for(&id("payments", "api")),
        spiffe_id: id("payments", "api"),
    }
}

pub fn wait() {
    std::thread::sleep(Duration::from_millis(1));
}
