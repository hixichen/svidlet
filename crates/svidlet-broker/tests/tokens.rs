//! The token path: rules T1–T7 of docs/DESIGN.md §6.4 against a fake minter.

mod common;

use common::*;
use svidlet_broker::refusal::Refusal;

fn caller_der(fx: &Fx, uri: &str) -> Vec<u8> {
    fx.ca.leaf_der(&[uri], now() - 60, now() + 48 * 3600, false)
}

fn refusal(r: Result<impl std::fmt::Debug, Refusal>) -> (u16, &'static str) {
    let e = r.expect_err("expected a refusal");
    (e.status(), e.rule())
}

#[test]
fn every_approved_audience_is_served_and_the_subject_is_the_san() {
    let fx = fixture();
    let caller = fx
        .tokens
        .caller(&caller_der(&fx, &id("payments", "api")), now())
        .unwrap();
    assert_eq!(caller.namespace, "payments");
    assert_eq!(caller.service_account, "api");
    let grants = fx.tokens.all(&caller, now()).unwrap();
    let aliases: Vec<_> = grants.iter().map(|g| g.alias.as_str()).collect();
    assert_eq!(aliases, vec!["aws", "vault"]);
    for g in &grants {
        let u = svidlet_issue::jwt::decode_unverified(&g.token).unwrap();
        assert_eq!(u.claims.sub, id("payments", "api"));
        assert_eq!(u.claims.aud, vec![g.audience.clone()]);
        assert!(g.minted);
    }
    assert_eq!(fx.minter.mints(), 2);
}

#[test]
fn replicas_share_one_token_per_audience() {
    let fx = fixture();
    let a = fx
        .tokens
        .caller(&caller_der(&fx, &id("payments", "api")), now())
        .unwrap();
    let b = fx
        .tokens
        .caller(&caller_der(&fx, &id("payments", "api")), now())
        .unwrap();
    assert_ne!(a.serial, b.serial, "two pods, two certificates");
    let first = fx.tokens.all(&a, now()).unwrap();
    let second = fx.tokens.all(&b, now()).unwrap();
    assert_eq!(first[0].token, second[0].token);
    assert!(!second[0].minted && !second[1].minted);
    assert_eq!(
        fx.minter.mints(),
        2,
        "Vault sees one mint per identity and audience"
    );
}

#[test]
fn t5_a_token_past_half_life_is_minted_again() {
    let fx = fixture();
    let caller = fx
        .tokens
        .caller(&caller_der(&fx, &id("payments", "api")), now())
        .unwrap();
    let first = fx.tokens.single(&caller, "vault", now()).unwrap();
    let later = now() + 3 * 3600 + 1; // past half of 6 h
    let again = fx.tokens.single(&caller, "vault", later).unwrap();
    assert!(again.minted);
    assert_ne!(first.token, again.token);
}

#[test]
fn t5_a_token_never_outlives_the_certificate_that_obtained_it() {
    let fx = fixture();
    // A certificate with 2 h left asks for a 6 h token.
    let der = fx
        .ca
        .leaf_der(&[&id("payments", "api")], now() - 60, now() + 7200, false);
    let caller = fx.tokens.caller(&der, now()).unwrap();
    assert_eq!(refusal(fx.tokens.single(&caller, "vault", now())).0, 503);
    // And a token cached for a longer-lived certificate is not served to it.
    let long = fx
        .tokens
        .caller(&caller_der(&fx, &id("payments", "api")), now())
        .unwrap();
    fx.tokens.single(&long, "vault", now()).unwrap();
    assert_eq!(refusal(fx.tokens.single(&caller, "vault", now())).0, 503);
}

#[test]
fn t6_a_retired_key_invalidates_cached_tokens() {
    let fx = fixture();
    let caller = fx
        .tokens
        .caller(&caller_der(&fx, &id("payments", "api")), now())
        .unwrap();
    let old = fx.tokens.single(&caller, "vault", now()).unwrap();
    // Emergency rotation: Vault signs with k2, k1 leaves the public JWKS.
    *fx.minter.kid.lock().unwrap() = "k2".into();
    *fx.minter.published.lock().unwrap() = vec!["k2".into()];
    fx.tokens.jwks.refresh().unwrap();
    let new = fx.tokens.single(&caller, "vault", now()).unwrap();
    assert!(new.minted);
    assert_ne!(old.token, new.token);
    let u = svidlet_issue::jwt::decode_unverified(&new.token).unwrap();
    assert_eq!(u.header.kid, "k2");
}

#[test]
fn t6_a_token_from_an_unpublished_key_is_held_back() {
    let fx = fixture();
    *fx.minter.kid.lock().unwrap() = "k-new".into();
    let caller = fx
        .tokens
        .caller(&caller_der(&fx, &id("payments", "api")), now())
        .unwrap();
    assert_eq!(refusal(fx.tokens.single(&caller, "vault", now())).0, 503);
    // Once the publisher catches up, the next request is served.
    fx.minter.published.lock().unwrap().push("k-new".into());
    fx.tokens.jwks.refresh().unwrap();
    fx.tokens.single(&caller, "vault", now()).unwrap();
}

#[test]
fn t1_the_certificate_must_carry_exactly_one_spiffe_uri_and_not_be_a_ca() {
    let fx = fixture();
    let t = now();
    let two = fx.ca.leaf_der(
        &[&id("payments", "api"), &id("batch", "runner")],
        t - 60,
        t + 3600,
        false,
    );
    assert_eq!(refusal(fx.tokens.caller(&two, t)), (401, "T1"));
    let none = fx.ca.leaf_der(&[], t - 60, t + 3600, false);
    assert_eq!(refusal(fx.tokens.caller(&none, t)), (401, "T1"));
    let ca = fx
        .ca
        .leaf_der(&[&id("payments", "api")], t - 60, t + 3600, true);
    assert_eq!(refusal(fx.tokens.caller(&ca, t)), (401, "T1"));
    let expired = fx
        .ca
        .leaf_der(&[&id("payments", "api")], t - 7200, t - 60, false);
    assert_eq!(refusal(fx.tokens.caller(&expired, t)), (401, "T1"));
    let not_spiffe = fx
        .ca
        .leaf_der(&["https://payments.example"], t - 60, t + 3600, false);
    assert_eq!(refusal(fx.tokens.caller(&not_spiffe, t)), (401, "T1"));
    let wrong_shape = fx.ca.leaf_der(
        &["spiffe://corp.internal/ns/payments/sa/api"],
        t - 60,
        t + 3600,
        false,
    );
    assert_eq!(refusal(fx.tokens.caller(&wrong_shape, t)), (403, "T1"));
    assert_eq!(refusal(fx.tokens.caller(b"garbage", t)), (401, "T1"));
}

#[test]
fn t2_another_clusters_identity_is_refused_before_vault() {
    let fx = fixture();
    let other = caller_der(
        &fx,
        "spiffe://corp.internal/cluster/gpu-b/ns/payments/sa/api",
    );
    assert_eq!(refusal(fx.tokens.caller(&other, now())), (403, "T2"));
    assert_eq!(fx.minter.mints(), 0);
}

#[test]
fn t3_only_catalogued_identities_and_approved_audiences() {
    let fx = fixture();
    let unlisted = fx
        .tokens
        .caller(&caller_der(&fx, &id("web", "frontend")), now())
        .unwrap();
    assert_eq!(refusal(fx.tokens.all(&unlisted, now())), (403, "T3"));
    let api = fx
        .tokens
        .caller(&caller_der(&fx, &id("payments", "api")), now())
        .unwrap();
    assert_eq!(
        refusal(fx.tokens.single(&api, "https://api.vendor.example", now())),
        (403, "T3")
    );
    // An identity in the catalog with no audiences gets an empty set.
    let runner = fx
        .tokens
        .caller(&caller_der(&fx, &id("batch", "runner")), now())
        .unwrap();
    assert!(fx.tokens.all(&runner, now()).unwrap().is_empty());
    assert_eq!(fx.minter.mints(), 0);
}

#[test]
fn t7_minting_is_rate_limited_per_identity() {
    let fx = fixture_with(CATALOG, &[("SVIDLET_MINT_RATE_PER_MINUTE", "1")]);
    let caller = fx
        .tokens
        .caller(&caller_der(&fx, &id("payments", "api")), now())
        .unwrap();
    fx.tokens.single(&caller, "vault", now()).unwrap();
    // A cached answer costs nothing against the limit…
    fx.tokens.single(&caller, "vault", now()).unwrap();
    // …but a second mint inside the minute does.
    assert_eq!(
        refusal(fx.tokens.single(&caller, "sts.amazonaws.com", now())),
        (429, "T7")
    );
}

#[test]
fn file_mode_is_all_or_nothing_for_outages_but_skips_vault_denials() {
    let fx = fixture();
    let caller = fx
        .tokens
        .caller(&caller_der(&fx, &id("payments", "api")), now())
        .unwrap();
    // A grant the Vault policy does not carry yet is left out, not fatal.
    fx.minter
        .denied_audiences
        .lock()
        .unwrap()
        .push("sts.amazonaws.com".into());
    let grants = fx.tokens.all(&caller, now()).unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].alias, "vault");
    // An outage fails the whole answer, so the node keeps its current files.
    let fresh = fixture();
    let caller = fresh
        .tokens
        .caller(&caller_der(&fresh, &id("payments", "api")), now())
        .unwrap();
    *fresh.minter.down.lock().unwrap() = true;
    assert_eq!(refusal(fresh.tokens.all(&caller, now())).0, 503);
}

#[test]
fn sweeping_drops_stale_and_retired_tokens() {
    let fx = fixture();
    let caller = fx
        .tokens
        .caller(&caller_der(&fx, &id("payments", "api")), now())
        .unwrap();
    fx.tokens.all(&caller, now()).unwrap();
    assert_eq!(fx.tokens.cached(), 2);
    fx.tokens.sweep(now());
    assert_eq!(fx.tokens.cached(), 2);
    fx.tokens.sweep(now() + 4 * 3600);
    assert_eq!(fx.tokens.cached(), 0);
}
