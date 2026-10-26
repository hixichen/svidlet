//! The certificate path: each invariant of docs/DESIGN.md §5.3 that the
//! broker enforces, one refusal at a time, against a fake API server.

mod common;

use common::*;
use svidlet_broker::refusal::Refusal;

fn rule_of(r: Result<svidlet_broker::sign::Signed, Refusal>) -> (u16, &'static str) {
    let e = r.expect_err("expected a refusal");
    (e.status(), e.rule())
}

#[test]
fn a_pod_on_the_calling_node_gets_its_certificate() {
    let fx = fixture();
    let signed = fx
        .signer
        .sign(NODE_TOKEN, &sign_body(POD_TOKEN), now())
        .unwrap();
    assert_eq!(signed.spiffe_id.as_str(), id("payments", "api"));
    assert_eq!(signed.node, "n1");
    assert_eq!(signed.pod_uid, "uid-api-0");
    assert_eq!(*fx.ca.signed.lock().unwrap(), vec![id("payments", "api")]);
    // I11: 48 h by default, as requested of Vault.
    let life = signed.bundle.not_after - signed.bundle.not_before;
    assert!((48 * 3600 - 5..=48 * 3600 + 5).contains(&life), "{life}");
}

#[test]
fn i3_a_node_cannot_obtain_identities_for_pods_on_other_nodes() {
    let fx = fixture();
    assert_eq!(
        rule_of(fx.signer.sign(NODE_TOKEN_N2, &sign_body(POD_TOKEN), now())),
        (403, "I3")
    );
    assert!(
        fx.ca.signed.lock().unwrap().is_empty(),
        "Vault was never asked"
    );
}

#[test]
fn i1_the_node_token_must_be_svidlet_node_on_a_daemonset_pod() {
    let fx = fixture();
    // Unknown token.
    assert_eq!(
        rule_of(fx.signer.sign("forged", &sign_body(POD_TOKEN), now())),
        (401, "I1")
    );
    assert_eq!(
        rule_of(fx.signer.sign("", &sign_body(POD_TOKEN), now())),
        (401, "I1")
    );
    // A pod token presented as the node token: wrong ServiceAccount.
    assert_eq!(
        rule_of(fx.signer.sign(POD_TOKEN, &sign_body(POD_TOKEN), now())),
        (403, "I1")
    );
    // A svidlet-node token whose pod is not owned by the DaemonSet.
    fx.kube
        .edit_pod("svidlet-system", "svidlet-node-aaaaa", |p| {
            p.owners = vec![("ReplicaSet".into(), "impostor".into())]
        });
    assert_eq!(
        rule_of(fx.signer.sign(NODE_TOKEN, &sign_body(POD_TOKEN), now())),
        (403, "I1")
    );
}

#[test]
fn i1_a_replaced_or_terminating_node_pod_is_not_trusted() {
    let fx = fixture();
    fx.kube
        .edit_pod("svidlet-system", "svidlet-node-aaaaa", |p| {
            p.uid = "new".into()
        });
    assert_eq!(
        rule_of(fx.signer.sign(NODE_TOKEN, &sign_body(POD_TOKEN), now())),
        (403, "I1")
    );
    let fx = fixture();
    fx.kube
        .edit_pod("svidlet-system", "svidlet-node-aaaaa", |p| {
            p.terminating = true
        });
    assert_eq!(
        rule_of(fx.signer.sign(NODE_TOKEN, &sign_body(POD_TOKEN), now())),
        (403, "I1")
    );
}

#[test]
fn i4_the_pod_must_be_live_and_match_its_token() {
    for edit in [
        (|p: &mut svidlet_broker::kube::Pod| p.uid = "replaced".into()) as fn(&mut _),
        |p| p.terminating = true,
        |p| p.service_account = "other".into(),
    ] {
        let fx = fixture();
        fx.kube.edit_pod("payments", "api-0", edit);
        assert_eq!(
            rule_of(fx.signer.sign(NODE_TOKEN, &sign_body(POD_TOKEN), now())),
            (403, "I4")
        );
    }
    let fx = fixture();
    fx.kube
        .pods
        .lock()
        .unwrap()
        .remove(&("payments".into(), "api-0".into()));
    assert_eq!(
        rule_of(fx.signer.sign(NODE_TOKEN, &sign_body(POD_TOKEN), now())),
        (403, "I4")
    );
}

#[test]
fn i5_every_issuance_needs_a_pod_token_that_authenticates() {
    let fx = fixture();
    assert_eq!(
        rule_of(fx.signer.sign(NODE_TOKEN, &sign_body(""), now())),
        (401, "I5")
    );
    assert_eq!(
        rule_of(fx.signer.sign(NODE_TOKEN, &sign_body("expired"), now())),
        (401, "I5")
    );
}

#[test]
fn i1_names_in_the_request_are_hints_and_must_agree() {
    let fx = fixture();
    let mut body = sign_body(POD_TOKEN);
    body.service_account = "admin".into();
    assert_eq!(
        rule_of(fx.signer.sign(NODE_TOKEN, &body, now())),
        (400, "I1")
    );
    // Empty hints are fine: the pod token decides.
    let mut body = sign_body(POD_TOKEN);
    body.namespace.clear();
    body.pod_name.clear();
    body.pod_uid.clear();
    body.service_account.clear();
    fx.signer.sign(NODE_TOKEN, &body, now()).unwrap();
}

#[test]
fn i6_the_csr_must_be_a_self_signed_p256_request() {
    let fx = fixture();
    let mut body = sign_body(POD_TOKEN);
    body.csr =
        "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n".into();
    assert_eq!(
        rule_of(fx.signer.sign(NODE_TOKEN, &body, now())),
        (400, "I6")
    );

    // A P-384 key.
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let mut body = sign_body(POD_TOKEN);
    body.csr = rcgen::CertificateParams::default()
        .serialize_request(&key)
        .unwrap()
        .pem()
        .unwrap();
    assert_eq!(
        rule_of(fx.signer.sign(NODE_TOKEN, &body, now())),
        (400, "I6")
    );

    // A request for a CA certificate.
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let mut body = sign_body(POD_TOKEN);
    body.csr = params.serialize_request(&key).unwrap().pem().unwrap();
    assert_eq!(
        rule_of(fx.signer.sign(NODE_TOKEN, &body, now())),
        (400, "I6")
    );
}

#[test]
fn i6_names_in_the_csr_are_ignored() {
    let fx = fixture();
    let mut body = sign_body(POD_TOKEN);
    // The CSR asks for another identity; the certificate carries the pod's.
    body.csr = csr_for("spiffe://corp.internal/cluster/gpu-b/ns/kube-system/sa/admin");
    let signed = fx.signer.sign(NODE_TOKEN, &body, now()).unwrap();
    assert_eq!(signed.spiffe_id.as_str(), id("payments", "api"));
}

#[test]
fn i7_a_node_expecting_a_different_id_is_told_so() {
    let fx = fixture();
    let mut body = sign_body(POD_TOKEN);
    body.spiffe_id = "spiffe://corp.internal/ns/payments/sa/api".into();
    assert_eq!(
        rule_of(fx.signer.sign(NODE_TOKEN, &body, now())),
        (400, "I7")
    );
    // And the pattern is a second gate on what the broker will render.
    let fx = fixture_with(
        CATALOG,
        &[(
            "SVIDLET_SPIFFE_ID_PATTERN",
            "spiffe://corp\\.internal/cluster/gpu-a/ns/batch/sa/.+",
        )],
    );
    assert_eq!(
        rule_of(fx.signer.sign(NODE_TOKEN, &sign_body(POD_TOKEN), now())),
        (403, "I7")
    );
}

#[test]
fn i8_system_namespaces_and_default_service_accounts_get_nothing() {
    let fx = fixture();
    fx.kube
        .add_pod("t-sys", "kube-system", "coredns", "dns-0", "u1", "n1");
    let mut body = sign_body("t-sys");
    body.namespace = "kube-system".into();
    body.service_account = "coredns".into();
    body.pod_name = "dns-0".into();
    body.pod_uid = "u1".into();
    body.spiffe_id.clear();
    assert_eq!(
        rule_of(fx.signer.sign(NODE_TOKEN, &body, now())),
        (403, "I8")
    );

    fx.kube
        .add_pod("t-def", "web", "default", "web-0", "u2", "n1");
    let mut body = sign_body("t-def");
    body.namespace = "web".into();
    body.service_account = "default".into();
    body.pod_name = "web-0".into();
    body.pod_uid = "u2".into();
    body.spiffe_id.clear();
    assert_eq!(
        rule_of(fx.signer.sign(NODE_TOKEN, &body, now())),
        (403, "I8")
    );
}

#[test]
fn i8_allowlist_mode_refuses_identities_outside_the_catalog() {
    let allow = CATALOG.replace("[sensitive]", "[mode]\nallowlist = true\n\n[sensitive]");
    let fx = fixture_with(&allow, &[]);
    fx.kube
        .add_pod("t-web", "web", "frontend", "web-0", "u3", "n1");
    let body = svidlet_issue::broker::SignBody {
        pod_token: "t-web".into(),
        namespace: String::new(),
        pod_name: String::new(),
        pod_uid: String::new(),
        service_account: String::new(),
        csr: csr_for(&id("web", "frontend")),
        spiffe_id: String::new(),
    };
    assert_eq!(
        rule_of(fx.signer.sign(NODE_TOKEN, &body, now())),
        (403, "I8")
    );
    // The catalogued identity still works.
    fx.signer
        .sign(NODE_TOKEN, &sign_body(POD_TOKEN), now())
        .unwrap();
}

#[test]
fn i9_sensitive_identities_need_pinned_images_from_approved_registries() {
    for image in [
        "registry.corp.example/payments:latest",
        "docker.io/payments@sha256:abc",
        "registry.corp.example.evil.net/payments@sha256:abc",
    ] {
        let fx = fixture();
        fx.kube
            .edit_pod("payments", "api-0", |p| p.images.push(image.into()));
        assert_eq!(
            rule_of(fx.signer.sign(NODE_TOKEN, &sign_body(POD_TOKEN), now())),
            (403, "I9"),
            "{image}"
        );
    }
}

#[test]
fn i10_a_node_is_rate_limited_but_renewals_of_known_identities_pass_the_distinct_cap() {
    let fx = fixture_with(
        CATALOG,
        &[
            ("SVIDLET_NODE_RATE_PER_MINUTE", "2"),
            ("SVIDLET_NODE_IDENTITIES_PER_HOUR", "1"),
        ],
    );
    let t = now();
    fx.signer
        .sign(NODE_TOKEN, &sign_body(POD_TOKEN), t)
        .unwrap();
    // Same identity again: within the distinct cap.
    fx.signer
        .sign(NODE_TOKEN, &sign_body(POD_TOKEN), t)
        .unwrap();
    assert_eq!(
        rule_of(fx.signer.sign(NODE_TOKEN, &sign_body(POD_TOKEN), t)),
        (429, "I10")
    );
    // A minute later the rate allows it again.
    fx.signer
        .sign(NODE_TOKEN, &sign_body(POD_TOKEN), t + 61)
        .unwrap();

    // A second identity on the same node exceeds the distinct cap.
    fx.kube
        .add_pod("t-run", "batch", "runner", "run-0", "u4", "n1");
    let body = svidlet_issue::broker::SignBody {
        pod_token: "t-run".into(),
        namespace: "batch".into(),
        pod_name: "run-0".into(),
        pod_uid: "u4".into(),
        service_account: "runner".into(),
        csr: csr_for(&id("batch", "runner")),
        spiffe_id: id("batch", "runner"),
    };
    assert_eq!(
        rule_of(fx.signer.sign(NODE_TOKEN, &body, t + 62)),
        (429, "I10")
    );
}

#[test]
fn i10_refused_requests_do_not_consume_the_nodes_budget() {
    let fx = fixture_with(CATALOG, &[("SVIDLET_NODE_RATE_PER_MINUTE", "1")]);
    let t = now();
    for _ in 0..5 {
        let _ = fx.signer.sign(NODE_TOKEN, &sign_body("bogus"), t);
    }
    fx.signer
        .sign(NODE_TOKEN, &sign_body(POD_TOKEN), t)
        .unwrap();
}

#[test]
fn i11_the_ttl_is_clamped_to_the_role_maximum() {
    let fx = fixture_with(
        CATALOG,
        &[("SVIDLET_CERT_TTL", "72h"), ("SVIDLET_CERT_MAX_TTL", "24h")],
    );
    let signed = fx
        .signer
        .sign(NODE_TOKEN, &sign_body(POD_TOKEN), now())
        .unwrap();
    let life = signed.bundle.not_after - signed.bundle.not_before;
    assert!((24 * 3600 - 5..=24 * 3600 + 5).contains(&life), "{life}");
}

#[test]
fn outages_are_503_and_vault_denials_are_403() {
    let fx = fixture();
    *fx.kube.down.lock().unwrap() = true;
    let e = fx
        .signer
        .sign(NODE_TOKEN, &sign_body(POD_TOKEN), now())
        .unwrap_err();
    assert_eq!(e.status(), 503);

    let fx = fixture();
    *fx.ca.fail.lock().unwrap() = Some(svidlet_issue::Error::Backend {
        status: 503,
        body: "sealed".into(),
    });
    assert_eq!(
        fx.signer
            .sign(NODE_TOKEN, &sign_body(POD_TOKEN), now())
            .unwrap_err()
            .status(),
        503
    );

    *fx.ca.fail.lock().unwrap() = Some(svidlet_issue::Error::Backend {
        status: 403,
        body: "denied".into(),
    });
    assert_eq!(
        rule_of(fx.signer.sign(NODE_TOKEN, &sign_body(POD_TOKEN), now())),
        (403, "vault")
    );
}
