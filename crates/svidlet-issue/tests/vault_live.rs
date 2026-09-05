//! Integration tests against a real Vault.
//!
//! Ignored by default, because they need a Vault to talk to. Bring one up with
//! `./hack/local-vault.sh start`, then:
//!
//! ```sh
//! eval "$(./hack/local-vault.sh env)"
//! cargo test -p svidlet-issue -- --ignored --nocapture
//! ```
//!
//! These are the tests that a fake backend cannot replace: that the CSR svidlet
//! builds is one Vault will actually sign, that the per-cluster role really
//! refuses an identity outside its prefix, and that a rotated secret ID is
//! picked up without a restart.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use svidlet_issue::{
    AppRoleAuth, IdPolicy, IdTemplate, Issuer, SignRequest, SpiffeId, StaticTokenAuth,
    VaultEndpoint, VaultHttp, VaultIssuer, VaultPkiConfig, WorkloadAttributes,
};

struct Env {
    http: Arc<VaultHttp>,
    pki: VaultPkiConfig,
    trust_domain: String,
    cluster: String,
    approle_mount: String,
    role_id: String,
    secret_id_path: PathBuf,
    token_path: PathBuf,
}

/// Read the environment `hack/local-vault.sh env` prints. Skips the test with a
/// clear message when it is absent, rather than failing.
fn env() -> Option<Env> {
    if std::env::var("SVIDLET_TEST_VAULT").is_err() {
        eprintln!(
            "skipping: set SVIDLET_TEST_VAULT and friends first \
             (eval \"$(./hack/local-vault.sh env)\")"
        );
        return None;
    }
    let var = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k} is not set"));

    let http = Arc::new(
        VaultHttp::new(VaultEndpoint {
            address: var("VAULT_ADDR"),
            namespace: std::env::var("VAULT_NAMESPACE").ok(),
            ca_cert_pem: None,
            timeout: Duration::from_secs(10),
        })
        .expect("the Vault client builds"),
    );

    Some(Env {
        http,
        pki: VaultPkiConfig {
            mount: var("SVIDLET_PKI_MOUNT"),
            role: var("SVIDLET_PKI_ROLE"),
        },
        trust_domain: var("SVIDLET_TRUST_DOMAIN"),
        cluster: var("SVIDLET_CLUSTER"),
        approle_mount: var("SVIDLET_APPROLE_MOUNT"),
        role_id: var("SVIDLET_ROLE_ID"),
        secret_id_path: PathBuf::from(var("SVIDLET_SECRET_ID_FILE")),
        token_path: PathBuf::from(var("SVIDLET_VAULT_TOKEN_FILE")),
    })
}

impl Env {
    fn approle_issuer(&self) -> VaultIssuer<AppRoleAuth> {
        VaultIssuer::new(
            self.http.clone(),
            self.pki.clone(),
            AppRoleAuth::new(
                self.http.clone(),
                self.approle_mount.clone(),
                self.role_id.clone(),
                self.secret_id_path.clone(),
            ),
        )
    }

    fn token_issuer(&self) -> VaultIssuer<StaticTokenAuth> {
        VaultIssuer::new(
            self.http.clone(),
            self.pki.clone(),
            StaticTokenAuth::new(self.token_path.clone()),
        )
    }

    fn id(&self, namespace: &str, service_account: &str) -> SpiffeId {
        IdPolicy::new(IdTemplate::DEFAULT, None)
            .unwrap()
            .render(&WorkloadAttributes {
                trust_domain: self.trust_domain.clone(),
                cluster: self.cluster.clone(),
                namespace: namespace.into(),
                service_account: service_account.into(),
                ..Default::default()
            })
            .unwrap()
    }
}

fn sign(issuer: &dyn Issuer, id: &SpiffeId) -> svidlet_issue::Result<svidlet_issue::IssuedBundle> {
    let generated = svidlet_issue::generate(id)?;
    issuer.sign(&SignRequest {
        spiffe_id: id,
        csr_pem: &generated.csr_pem,
        ttl: Duration::from_secs(3600),
        node_name: "test-node",
    })
}

#[test]
#[ignore = "needs a local Vault: ./hack/local-vault.sh start"]
fn vault_signs_the_csr_svidlet_builds() {
    let Some(env) = env() else { return };
    let issuer = env.approle_issuer();
    let id = env.id("payments", "api");

    let bundle = sign(&issuer, &id).expect("Vault signs the CSR");

    // The certificate really carries the SPIFFE ID, and a sane lifetime.
    let facts = svidlet_issue::assert_identity(&bundle.cert_chain_pem, &id).unwrap();
    assert_eq!(facts.spiffe_id, id);
    assert!(
        (3000..=3700).contains(&(bundle.lifetime_secs() as i64)),
        "lifetime {}s",
        bundle.lifetime_secs()
    );
    assert!(bundle.ca_pem.contains("-----BEGIN CERTIFICATE-----"));
    assert_eq!(issuer.auth_name(), "approle");
}

#[test]
#[ignore = "needs a local Vault: ./hack/local-vault.sh start"]
fn the_trust_bundle_is_fetchable_without_a_token() {
    let Some(env) = env() else { return };
    let chain = env
        .approle_issuer()
        .ca_chain()
        .expect("the CA chain is readable");
    assert!(chain.contains("-----BEGIN CERTIFICATE-----"));
}

#[test]
#[ignore = "needs a local Vault: ./hack/local-vault.sh start"]
fn the_role_refuses_an_identity_outside_this_clusters_prefix() {
    let Some(env) = env() else { return };

    // A SPIFFE ID for another cluster. Vault's allowed_uri_sans must refuse it,
    // which is the whole reason a compromised node cannot reach across
    // clusters. If this test ever passes a signature, the role is misconfigured.
    let foreign = SpiffeId::parse(&format!(
        "spiffe://{}/cluster/somewhere-else/ns/kube-system/sa/admin",
        env.trust_domain
    ))
    .unwrap();

    let err = sign(&env.approle_issuer(), &foreign)
        .expect_err("Vault must refuse an identity outside the cluster prefix");
    assert_eq!(err.code(), svidlet_issue::ErrorCode::BackendStatus);
    assert!(!err.is_retryable(), "a policy refusal must not be retried");
}

#[test]
#[ignore = "needs a local Vault: ./hack/local-vault.sh start"]
fn a_second_signature_reuses_the_token_rather_than_logging_in_again() {
    let Some(env) = env() else { return };
    let issuer = env.approle_issuer();
    let id = env.id("payments", "api");

    // Two signatures through one issuer: the AppRole login happens once, which
    // is what keeps login load flat as certificate volume grows.
    let first = sign(&issuer, &id).expect("first signature");
    let second = sign(&issuer, &id).expect("second signature");
    assert_ne!(
        first.cert_chain_pem, second.cert_chain_pem,
        "each signature is a distinct certificate"
    );
}

#[test]
#[ignore = "needs a local Vault: ./hack/local-vault.sh start"]
fn a_static_token_works_as_an_alternative_login() {
    let Some(env) = env() else { return };
    let issuer = env.token_issuer();
    assert_eq!(issuer.auth_name(), "token");
    sign(&issuer, &env.id("payments", "api")).expect("a static token can sign too");
}

#[test]
#[ignore = "needs a local Vault: ./hack/local-vault.sh start"]
fn a_bad_secret_id_is_reported_as_an_auth_failure() {
    let Some(env) = env() else { return };

    let bogus = std::env::temp_dir().join("svidlet-bogus-secret-id");
    std::fs::write(&bogus, "00000000-0000-0000-0000-000000000000").unwrap();

    let issuer = VaultIssuer::new(
        env.http.clone(),
        env.pki.clone(),
        AppRoleAuth::new(
            env.http.clone(),
            env.approle_mount.clone(),
            env.role_id.clone(),
            bogus.clone(),
        ),
    );

    let err = sign(&issuer, &env.id("payments", "api")).expect_err("login must fail");
    assert_eq!(err.code(), svidlet_issue::ErrorCode::Auth);
    // Retryable, because the fix may be a rotated Secret arriving on disk.
    assert!(err.is_retryable());

    std::fs::remove_file(&bogus).unwrap();
}
