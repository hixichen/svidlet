//! End to end over real TLS: the node's `BrokerClient` against the broker's
//! two HTTPS ports, with fake Kubernetes and Vault behind them.

mod common;

use std::time::Duration;

use common::*;
use svidlet_issue::{BrokerClient, BrokerEndpoint, Issuer, PodContext, SignRequest, SpiffeId};

fn client(r: &Running) -> BrokerClient {
    BrokerClient::new(BrokerEndpoint {
        sign_url: r.sign_url.clone(),
        token_url: r.token_url.clone(),
        ca_cert_pem: r.ca_pem.clone(),
        node_token_path: r.dir.join("node-token"),
        timeout: Duration::from_secs(5),
    })
    .unwrap()
}

fn sign_with(
    c: &BrokerClient,
    pod_token: Option<&str>,
) -> svidlet_issue::Result<(svidlet_issue::IssuedBundle, String)> {
    let spiffe_id = SpiffeId::parse(&id("payments", "api")).unwrap();
    let generated = svidlet_issue::generate(&spiffe_id).unwrap();
    let bundle = c.sign(&SignRequest {
        spiffe_id: &spiffe_id,
        csr_pem: &generated.csr_pem,
        ttl: Duration::from_secs(3600),
        node_name: "n1",
        pod: Some(PodContext {
            namespace: "payments",
            name: "api-0",
            uid: "uid-api-0",
            service_account: "api",
            token: pod_token,
        }),
    })?;
    Ok((bundle, generated.key_pem))
}

#[tokio::test]
async fn a_node_gets_a_certificate_and_then_tokens_with_it() {
    let r = start_broker("full", fixture()).await;
    let c = client(&r);
    let out = tokio::task::spawn_blocking(move || {
        let ca = c.ca_chain().unwrap();
        let (bundle, key) = sign_with(&c, Some(POD_TOKEN)).unwrap();
        let tokens = c.fetch_tokens(&bundle.cert_chain_pem, &key).unwrap();
        (ca, bundle, tokens)
    })
    .await
    .unwrap();
    let (ca, bundle, tokens) = out;
    assert!(ca.contains("BEGIN CERTIFICATE"));
    assert_eq!(bundle.ca_pem, r.ca_pem);
    assert_eq!(
        svidlet_issue::inspect(&bundle.cert_chain_pem)
            .unwrap()
            .spiffe_id
            .as_str(),
        id("payments", "api")
    );
    let aliases: Vec<_> = tokens.iter().map(|t| t.alias.as_str()).collect();
    assert_eq!(aliases, vec!["aws", "vault"]);
    assert_eq!(r.minter.mints(), 2);

    // Off the runtime thread: the server answering it runs there.
    let url = format!("{}/metrics", r.metrics_url);
    let metrics = tokio::task::spawn_blocking(move || {
        ureq::get(&url)
            .call()
            .unwrap()
            .body_mut()
            .read_to_string()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        metrics.contains(r#"svidlet_broker_requests_total{path="sign",outcome="ok",rule=""} 1"#),
        "{metrics}"
    );
    assert!(
        metrics.contains(r#"svidlet_broker_token_cache_total{result="mint"} 2"#),
        "{metrics}"
    );
    std::fs::remove_dir_all(&r.dir).unwrap();
}

#[tokio::test]
async fn refusals_reach_the_node_as_the_right_errors() {
    let r = start_broker("refusals", fixture()).await;
    r.kube
        .add_pod("t-elsewhere", "payments", "api", "api-1", "uid-api-1", "n2");
    let c = client(&r);
    let errs = tokio::task::spawn_blocking(move || {
        (
            sign_with(&c, None).unwrap_err(),
            sign_with(&c, Some("bogus")).unwrap_err(),
            sign_with(&c, Some("t-elsewhere")).unwrap_err(),
        )
    })
    .await
    .unwrap();
    use svidlet_issue::ErrorCode;
    // No pod token yet (after a restart): retryable, never sent.
    assert_eq!(errs.0.code(), ErrorCode::Auth);
    assert_eq!(errs.1.code(), ErrorCode::Auth);
    // A pod on another node: refused, naming the invariant.
    assert_eq!(errs.2.code(), ErrorCode::Policy);
    assert!(errs.2.to_string().contains("(I3)"), "{}", errs.2);
    std::fs::remove_dir_all(&r.dir).unwrap();
}

#[tokio::test]
async fn direct_mode_serves_one_approved_audience_and_requires_a_client_certificate() {
    let r = start_broker("direct", fixture()).await;
    let c = client(&r);
    let (bundle, key) =
        tokio::task::spawn_blocking(move || sign_with(&c, Some(POD_TOKEN)).unwrap())
            .await
            .unwrap();
    let ca_pem = r.ca_pem.clone();
    let url = format!("{}/v1/token", r.token_url);
    let results = tokio::task::spawn_blocking(move || {
        use ureq::tls::{Certificate, ClientCert, PrivateKey, RootCerts, TlsConfig};
        let roots = vec![Certificate::from_pem(ca_pem.as_bytes()).unwrap()];
        let agent = |client: Option<ClientCert>| -> ureq::Agent {
            ureq::Agent::config_builder()
                .http_status_as_error(false)
                .tls_config(
                    TlsConfig::builder()
                        .root_certs(RootCerts::new_with_certs(&roots))
                        .client_cert(client)
                        .build(),
                )
                .build()
                .into()
        };
        let cert = ClientCert::new_with_certs(
            &[Certificate::from_pem(bundle.cert_chain_pem.as_bytes()).unwrap()],
            PrivateKey::from_pem(key.as_bytes()).unwrap(),
        );
        let with = agent(Some(cert));
        let ok = with
            .post(&url)
            .send_json(serde_json::json!({ "audience": "vault" }))
            .unwrap()
            .body_mut()
            .read_json::<serde_json::Value>()
            .unwrap();
        let unapproved = with
            .post(&url)
            .send_json(serde_json::json!({ "audience": "https://elsewhere" }))
            .unwrap();
        let anonymous = agent(None)
            .post(&url)
            .send_json(serde_json::json!({ "audience": "vault" }));
        (ok, unapproved.status().as_u16(), anonymous.is_err())
    })
    .await
    .unwrap();
    assert_eq!(results.0["alias"], "vault");
    assert!(results.0["token"].as_str().unwrap().contains('.'));
    assert_eq!(results.1, 403);
    assert!(results.2, "no client certificate, no TLS session");
    std::fs::remove_dir_all(&r.dir).unwrap();
}
