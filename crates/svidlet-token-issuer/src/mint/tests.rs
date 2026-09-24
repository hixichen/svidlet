use super::*;
use crate::grants::Grant;
use crate::keys::{tests::pkcs8, Key};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};

const TD: &str = "example.org";
const NODE: &str = "spiffe://example.org/cluster/a/node/n1";
const POD: &str = "spiffe://example.org/cluster/a/ns/payments/sa/api";
const HOUR: i64 = 3600;

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
    let now = ::time::OffsetDateTime::now_utc();
    params.not_before = now - ::time::Duration::days(1);
    params.not_after = now + ::time::Duration::days(365);
    let pem = params.self_signed(&key).unwrap().pem();
    Ca {
        issuer: Issuer::from_ca_cert_pem(&pem, key).unwrap(),
        pem,
    }
}

/// A leaf the way Vault's role signs one: client and server use, one URI SAN.
fn leaf(by: &Ca, uris: &[&str], lifetime: ::time::Duration) -> (String, String) {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::default();
    params.subject_alt_names = uris
        .iter()
        .map(|u| SanType::URI((*u).try_into().unwrap()))
        .collect();
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let now = ::time::OffsetDateTime::now_utc();
    params.not_before = now - ::time::Duration::minutes(5);
    params.not_after = now + lifetime;
    let cert = params.signed_by(&key, &by.issuer).unwrap();
    (cert.pem(), key.serialize_pem())
}

fn node_der(by: &Ca, id: &str) -> Vec<u8> {
    let (pem, _) = leaf(by, &[id], ::time::Duration::days(1));
    let (_, parsed) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();
    parsed.contents
}

fn now() -> i64 {
    ::time::OffsetDateTime::now_utc().unix_timestamp()
}

struct Fixture {
    pod_ca: Ca,
    node_ca: Ca,
    minter: Minter,
}

fn fixture() -> Fixture {
    let pod_ca = ca("pod CA");
    let node_ca = ca("node CA");
    let pool = KeyPool::new(vec![Key::from_pkcs8(&pkcs8(), true).unwrap()]).unwrap();
    let grants = Grants::new(
        TD,
        vec![Grant {
            prefix: "spiffe://example.org/cluster/a/ns/payments/".into(),
            audiences: vec!["azure".into()],
        }],
    )
    .unwrap();
    let minter = Minter::new(
        "https://tokens.example.org",
        TD,
        Duration::from_secs(6 * 3600),
        &pod_ca.pem,
        pool,
        grants,
    )
    .unwrap();
    Fixture {
        pod_ca,
        node_ca,
        minter,
    }
}

fn request(chain: &str, key: &str, node: &str, pod: &str, aud: &str, time: i64) -> MintRequest {
    MintRequest {
        pod_cert_chain_pem: chain.into(),
        audience: aud.into(),
        proof_time: time,
        proof: pop::sign(key, &pop::message(node, pod, aud, time)).unwrap(),
    }
}

fn denied(result: Result<Minted, Denied>) -> &'static str {
    let label = result.expect_err("the request must be refused").label();
    // Every refusal must land in a pre-declared metric series.
    assert!(DENIAL_LABELS.contains(&label), "undeclared label {label}");
    label
}

/// Verify a token the way a relying party does: kid from the header, key from
/// the JWKS, ES256 over the signing input.
fn verify_with_jwks(token: &str, jwks: &serde_json::Value) -> Claims {
    let b64 = |s: &str| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s)
            .unwrap()
    };
    let parts: Vec<&str> = token.split('.').collect();
    let header: serde_json::Value = serde_json::from_slice(&b64(parts[0])).unwrap();
    assert_eq!(header["alg"], "ES256");
    let jwk = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["kid"] == header["kid"])
        .expect("the header's kid is in the JWKS");
    let mut point = vec![4u8];
    point.extend(b64(jwk["x"].as_str().unwrap()));
    point.extend(b64(jwk["y"].as_str().unwrap()));
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &point)
        .verify(
            format!("{}.{}", parts[0], parts[1]).as_bytes(),
            &b64(parts[2]),
        )
        .expect("the signature verifies against the published key");
    Claims::read_unverified(token).unwrap()
}

#[test]
fn a_granted_request_yields_a_token_a_relying_party_can_verify() {
    let fx = fixture();
    let (chain, key) = leaf(&fx.pod_ca, &[POD], ::time::Duration::days(1));
    let now = now();
    let minted = fx
        .minter
        .mint(
            &node_der(&fx.node_ca, NODE),
            &request(&chain, &key, NODE, POD, "azure", now),
            now,
        )
        .unwrap();
    let claims = verify_with_jwks(&minted.token, &fx.minter.jwks());
    assert_eq!(claims, minted.claims);
    assert_eq!(claims.iss, "https://tokens.example.org");
    assert_eq!(claims.sub, POD);
    assert_eq!(claims.aud, "azure");
    assert_eq!(claims.iat, now);
    assert_eq!(claims.exp, now + 6 * HOUR);
    assert_eq!(claims.jti.len(), 22, "16 random bytes, base64url");
}

#[test]
fn a_token_never_outlives_the_pod_certificate() {
    let fx = fixture();
    let (chain, key) = leaf(&fx.pod_ca, &[POD], ::time::Duration::hours(1));
    let now = now();
    let minted = fx
        .minter
        .mint(
            &node_der(&fx.node_ca, NODE),
            &request(&chain, &key, NODE, POD, "azure", now),
            now,
        )
        .unwrap();
    assert!(minted.claims.exp <= now + HOUR, "{}", minted.claims.exp);
    assert!(minted.claims.exp > now + HOUR - 5);
}

#[test]
fn each_token_gets_its_own_jti() {
    let fx = fixture();
    let (chain, key) = leaf(&fx.pod_ca, &[POD], ::time::Duration::days(1));
    let node = node_der(&fx.node_ca, NODE);
    let now = now();
    let req = request(&chain, &key, NODE, POD, "azure", now);
    let a = fx.minter.mint(&node, &req, now).unwrap();
    let b = fx.minter.mint(&node, &req, now).unwrap();
    assert_ne!(a.claims.jti, b.claims.jti);
}

#[test]
fn the_caller_must_be_a_node_of_this_trust_domain() {
    let fx = fixture();
    let (chain, key) = leaf(&fx.pod_ca, &[POD], ::time::Duration::days(1));
    let now = now();
    for caller in [
        // A workload certificate is not a node certificate.
        POD,
        "spiffe://other.org/cluster/a/node/n1",
        "spiffe://example.org/cluster/a/node/",
        "spiffe://example.org/cluster/a/node/n1/extra",
        "spiffe://example.org/node/n1",
    ] {
        let req = request(&chain, &key, caller, POD, "azure", now);
        assert_eq!(
            denied(fx.minter.mint(&node_der(&fx.node_ca, caller), &req, now)),
            "node_identity",
            "{caller}"
        );
    }
}

#[test]
fn a_pod_certificate_from_another_ca_is_refused() {
    let fx = fixture();
    let rogue = ca("rogue");
    let (chain, key) = leaf(&rogue, &[POD], ::time::Duration::days(1));
    let now = now();
    let req = request(&chain, &key, NODE, POD, "azure", now);
    assert_eq!(
        denied(fx.minter.mint(&node_der(&fx.node_ca, NODE), &req, now)),
        "pod_certificate"
    );
}

#[test]
fn an_expired_pod_certificate_is_refused() {
    let fx = fixture();
    let (chain, key) = leaf(&fx.pod_ca, &[POD], ::time::Duration::hours(1));
    let later = now() + 2 * HOUR;
    let req = request(&chain, &key, NODE, POD, "azure", later);
    assert_eq!(
        denied(fx.minter.mint(&node_der(&fx.node_ca, NODE), &req, later)),
        "pod_certificate"
    );
}

#[test]
fn a_pod_certificate_needs_exactly_one_spiffe_id() {
    let fx = fixture();
    let (chain, key) = leaf(
        &fx.pod_ca,
        &[POD, "spiffe://example.org/cluster/a/ns/other/sa/x"],
        ::time::Duration::days(1),
    );
    let now = now();
    let req = request(&chain, &key, NODE, POD, "azure", now);
    assert_eq!(
        denied(fx.minter.mint(&node_der(&fx.node_ca, NODE), &req, now)),
        "pod_identity"
    );
}

#[test]
fn a_node_cannot_mint_for_another_clusters_pod() {
    let fx = fixture();
    let other = "spiffe://example.org/cluster/b/ns/payments/sa/api";
    let (chain, key) = leaf(&fx.pod_ca, &[other], ::time::Duration::days(1));
    let now = now();
    let req = request(&chain, &key, NODE, other, "azure", now);
    assert_eq!(
        denied(fx.minter.mint(&node_der(&fx.node_ca, NODE), &req, now)),
        "cluster"
    );
}

#[test]
fn the_certificate_alone_is_not_enough_without_the_key() {
    let fx = fixture();
    let (chain, _) = leaf(&fx.pod_ca, &[POD], ::time::Duration::days(1));
    // Someone who saw the certificate in a handshake, signing with their own key.
    let (_, other_key) = leaf(&fx.pod_ca, &[POD], ::time::Duration::days(1));
    let now = now();
    let req = request(&chain, &other_key, NODE, POD, "azure", now);
    assert_eq!(
        denied(fx.minter.mint(&node_der(&fx.node_ca, NODE), &req, now)),
        "proof"
    );
}

#[test]
fn a_proof_made_for_another_node_does_not_work_through_this_one() {
    let fx = fixture();
    let (chain, key) = leaf(&fx.pod_ca, &[POD], ::time::Duration::days(1));
    let now = now();
    let captured = request(
        &chain,
        &key,
        "spiffe://example.org/cluster/a/node/n2",
        POD,
        "azure",
        now,
    );
    assert_eq!(
        denied(fx.minter.mint(&node_der(&fx.node_ca, NODE), &captured, now)),
        "proof"
    );
}

#[test]
fn a_stale_proof_is_refused() {
    let fx = fixture();
    let (chain, key) = leaf(&fx.pod_ca, &[POD], ::time::Duration::days(1));
    let now = now();
    let old = request(&chain, &key, NODE, POD, "azure", now - pop::WINDOW_SECS - 1);
    assert_eq!(
        denied(fx.minter.mint(&node_der(&fx.node_ca, NODE), &old, now)),
        "proof_stale"
    );
}

#[test]
fn an_audience_needs_a_grant_for_this_identity() {
    let fx = fixture();
    let now = now();
    // Granted identity, audience outside the grant.
    let (chain, key) = leaf(&fx.pod_ca, &[POD], ::time::Duration::days(1));
    let req = request(&chain, &key, NODE, POD, "snowflake", now);
    assert_eq!(
        denied(fx.minter.mint(&node_der(&fx.node_ca, NODE), &req, now)),
        "grant"
    );
    // Granted audience, identity in a namespace the grant does not cover.
    let other = "spiffe://example.org/cluster/a/ns/batch/sa/job";
    let (chain, key) = leaf(&fx.pod_ca, &[other], ::time::Duration::days(1));
    let req = request(&chain, &key, NODE, other, "azure", now);
    assert_eq!(
        denied(fx.minter.mint(&node_der(&fx.node_ca, NODE), &req, now)),
        "grant"
    );
}
