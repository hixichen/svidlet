//! The policy bundle rollout, end to end against a stub OCI registry.
//!
//! Everything below the socket is the production path: the real registry
//! client, signature verification, tar extraction, version store, ring
//! evaluation and the volume writer. Only the registry is a stub, and the
//! helpers that build its content double as an executable specification of what
//! a release pipeline has to produce.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

use svidlet::config::BundleSettings;
use svidlet::policy::oci::{BundleSource, Error};

// ------------------------------------------------------- the release pipeline
//
// What CI does, in about forty lines. If this and `hack/build-bundle.sh` ever
// disagree, one of them is wrong.

struct Ci {
    pair: Ed25519KeyPair,
}

impl Ci {
    fn new() -> Ci {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Ci {
            pair: Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap(),
        }
    }

    fn public_key(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.pair.public_key().as_ref())
    }

    /// Wrap `rollout.toml` in the signed envelope nodes verify.
    fn sign(&self, payload: &[u8]) -> Vec<u8> {
        let b64 = base64::engine::general_purpose::STANDARD;
        serde_json::json!({
            "svidlet_signature": 1,
            "algorithm": "ed25519",
            "key_id": "ci",
            "payload": b64.encode(payload),
            "signature": b64.encode(self.pair.sign(payload).as_ref()),
        })
        .to_string()
        .into_bytes()
    }
}

/// Package a bundle directory as an uncompressed tar.
fn tar(files: &[(&str, &[u8])]) -> Vec<u8> {
    const BLOCK: usize = 512;
    let mut out = Vec::new();
    for (name, content) in files {
        let mut header = [0u8; BLOCK];
        let bytes = name.as_bytes();
        header[..bytes.len()].copy_from_slice(bytes);
        let octal = |field: &mut [u8], value: usize| {
            let text = format!("{:0width$o}", value, width = field.len() - 1);
            field[..text.len()].copy_from_slice(text.as_bytes());
        };
        octal(&mut header[100..108], 0o644);
        octal(&mut header[108..116], 0);
        octal(&mut header[116..124], 0);
        octal(&mut header[124..136], content.len());
        octal(&mut header[136..148], 0);
        header[156] = b'0';
        header[257..262].copy_from_slice(b"ustar");
        header[263..265].copy_from_slice(b"00");
        header[148..156].fill(b' ');
        let sum: usize = header.iter().map(|b| *b as usize).sum();
        octal(&mut header[148..155], sum);
        header[155] = b' ';

        out.extend_from_slice(&header);
        out.extend_from_slice(content);
        out.extend(std::iter::repeat_n(
            0u8,
            (BLOCK - content.len() % BLOCK) % BLOCK,
        ));
    }
    out.extend(std::iter::repeat_n(0u8, BLOCK * 2));
    out
}

fn digest_of(bytes: &[u8]) -> String {
    let hash = ring::digest::digest(&ring::digest::SHA256, bytes);
    format!(
        "sha256:{}",
        hash.as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

/// A bundle as CI would build it: content plus its manifest.
fn bundle(description: &str, rules: &str) -> Vec<u8> {
    tar(&[
        (
            "bundle.toml",
            format!("schema = 1\ndescription = \"{description}\"\nenforce = true\n").as_bytes(),
        ),
        ("rules/authz.rego", rules.as_bytes()),
    ])
}

// ----------------------------------------------------------- the stub registry

#[derive(Default)]
struct Content {
    /// Tag → the artifact's single layer.
    tags: HashMap<String, Vec<u8>>,
    /// Digest → blob.
    blobs: HashMap<String, Vec<u8>>,
    /// Fail every request, as an unreachable registry would.
    offline: bool,
}

struct Stub {
    content: Mutex<Content>,
    manifest_requests: AtomicUsize,
    blob_requests: AtomicUsize,
    not_modified: AtomicUsize,
    addr: String,
}

impl Stub {
    fn start() -> Arc<Stub> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stub = Arc::new(Stub {
            content: Mutex::new(Content::default()),
            manifest_requests: AtomicUsize::new(0),
            blob_requests: AtomicUsize::new(0),
            not_modified: AtomicUsize::new(0),
            addr: listener.local_addr().unwrap().to_string(),
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

    fn reference(&self) -> String {
        format!("{}/policy/rollout:current", self.addr)
    }

    /// Publish a blob and return its digest, as `oras push` would.
    fn publish_blob(&self, blob: Vec<u8>) -> String {
        let digest = digest_of(&blob);
        self.content
            .lock()
            .unwrap()
            .blobs
            .insert(digest.clone(), blob);
        digest
    }

    /// Point the rollout tag at a signed manifest.
    fn publish_rollout(&self, envelope: Vec<u8>) {
        let digest = self.publish_blob(envelope.clone());
        let mut content = self.content.lock().unwrap();
        content.tags.insert("current".into(), digest.into_bytes());
    }

    fn set_offline(&self, offline: bool) {
        self.content.lock().unwrap().offline = offline;
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

        let mut if_none_match = String::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                break;
            }
            if line.to_ascii_lowercase().starts_with("if-none-match:") {
                if_none_match = line.split_once(':').unwrap().1.trim().to_string();
            }
        }

        let (status, etag, body) = self.route(&path, &if_none_match);
        let mut head = format!(
            "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        );
        if let Some(etag) = etag {
            head.push_str(&format!("ETag: {etag}\r\n"));
        }
        head.push_str("Connection: close\r\n\r\n");
        let _ = conn.write_all(head.as_bytes());
        let _ = conn.write_all(&body);
    }

    fn route(&self, path: &str, if_none_match: &str) -> (u16, Option<String>, Vec<u8>) {
        let content = self.content.lock().unwrap();
        if content.offline {
            return (503, None, b"{\"errors\":[\"offline\"]}".to_vec());
        }

        if let Some(tag) = path.strip_prefix("/v2/policy/rollout/manifests/") {
            self.manifest_requests.fetch_add(1, Ordering::SeqCst);
            let Some(layer_digest) = content.tags.get(tag) else {
                return (404, None, b"{\"errors\":[\"unknown tag\"]}".to_vec());
            };
            let layer_digest = String::from_utf8(layer_digest.clone()).unwrap();
            // The ETag tracks the layer, so a manifest that has not moved is a
            // 304 and costs the node nothing.
            let etag = format!("\"{layer_digest}\"");
            if if_none_match == etag {
                self.not_modified.fetch_add(1, Ordering::SeqCst);
                return (304, Some(etag), Vec::new());
            }
            let manifest = serde_json::json!({
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "layers": [{
                    "mediaType": "application/vnd.svidlet.rollout.v1+json",
                    "digest": layer_digest,
                    "size": content.blobs.get(&layer_digest).map(|b| b.len()).unwrap_or(0),
                }],
            });
            return (200, Some(etag), manifest.to_string().into_bytes());
        }

        if let Some(digest) = path.strip_prefix("/v2/policy/rollout/blobs/") {
            self.blob_requests.fetch_add(1, Ordering::SeqCst);
            return match content.blobs.get(digest) {
                Some(blob) => (200, None, blob.clone()),
                None => (404, None, b"{\"errors\":[\"unknown blob\"]}".to_vec()),
            };
        }

        (404, None, b"{\"errors\":[\"no route\"]}".to_vec())
    }
}

// ------------------------------------------------------------------- fixtures

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "svidlet-rollout-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn settings(stub: &Stub, key: String, dir: PathBuf) -> BundleSettings {
    BundleSettings {
        rollout_ref: Some(stub.reference()),
        bundle_repo: None,
        public_key: Some(key),
        public_key_path: None,
        ca_cert_path: None,
        token_path: None,
        timeout: Duration::from_secs(5),
        poll_interval: Duration::from_secs(60),
        poll_jitter: Duration::from_secs(30),
        directory: dir,
        keep_versions: 2,
        max_bytes: 1024 * 1024,
    }
}

fn source(stub: &Stub, ci: &Ci, dir: PathBuf, cluster: &str, node: &str) -> BundleSource {
    BundleSource::new(
        settings(stub, ci.public_key(), dir),
        cluster.into(),
        node.into(),
    )
    .expect("the source builds")
}

fn manifest(rings: &str) -> String {
    format!("schema = 1\nfreeze = false\n{rings}")
}

fn ring(name: &str, matcher: &str, digest: &str) -> String {
    let matcher = if matcher.is_empty() {
        String::new()
    } else {
        format!("match = {{ {matcher} }}\n")
    };
    format!("\n[[ring]]\nname = \"{name}\"\n{matcher}bundle = \"{digest}\"\n")
}

// ---------------------------------------------------------------------- tests

#[test]
fn a_node_pulls_verifies_and_applies_its_ring_bundle() {
    let stub = Stub::start();
    let ci = Ci::new();
    let dir = scratch("apply");

    let digest = stub.publish_blob(bundle("v1", "allow := true"));
    stub.publish_rollout(ci.sign(manifest(&ring("all", "", &digest)).as_bytes()));

    let source = source(&stub, &ci, dir.clone(), "prod-eu", "node-1");
    let applied = source.poll().unwrap().expect("a bundle is applied");

    assert_eq!(applied.revision, digest);
    let names: Vec<_> = applied.documents.iter().map(|d| d.name.as_str()).collect();
    assert_eq!(names, ["bundle.toml", "rules/authz.rego"]);
    assert_eq!(applied.documents[1].content, b"allow := true");

    // The on-disk layout the design specifies.
    assert!(dir.join("versions").is_dir());
    assert!(dir.join("current").exists());
    assert_eq!(
        std::fs::read_to_string(dir.join("current/rules/authz.rego")).unwrap(),
        "allow := true"
    );
    assert!(dir.join("rollout.toml").exists());
    assert!(dir.join("state.json").exists());

    let current = source.current();
    assert_eq!(current.ring, "all");
    assert_eq!(current.digest, digest);
    assert!(source.age_seconds().unwrap() < 5);

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn an_unchanged_manifest_costs_one_conditional_request() {
    let stub = Stub::start();
    let ci = Ci::new();
    let dir = scratch("etag");

    let digest = stub.publish_blob(bundle("v1", "x"));
    stub.publish_rollout(ci.sign(manifest(&ring("all", "", &digest)).as_bytes()));

    let source = source(&stub, &ci, dir.clone(), "prod-eu", "node-1");
    assert!(source.poll().unwrap().is_some());

    // Nothing changed upstream: the next polls are 304s, and no blob is pulled.
    let blobs_after_first = stub.blob_requests.load(Ordering::SeqCst);
    for _ in 0..3 {
        assert!(source.poll().unwrap().is_none());
    }
    assert_eq!(stub.not_modified.load(Ordering::SeqCst), 3);
    assert_eq!(stub.blob_requests.load(Ordering::SeqCst), blobs_after_first);

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_promotion_moves_the_node_and_a_rollback_needs_no_network() {
    let stub = Stub::start();
    let ci = Ci::new();
    let dir = scratch("promote");

    let v1 = stub.publish_blob(bundle("v1", "allow := false"));
    let v2 = stub.publish_blob(bundle("v2", "allow := true"));

    stub.publish_rollout(ci.sign(manifest(&ring("all", "", &v1)).as_bytes()));
    let source = source(&stub, &ci, dir.clone(), "prod-eu", "node-1");
    assert_eq!(source.poll().unwrap().unwrap().revision, v1);

    // Promotion: the manifest now names v2 for this ring.
    stub.publish_rollout(ci.sign(manifest(&ring("all", "", &v2)).as_bytes()));
    let applied = source.poll().unwrap().expect("the promotion is applied");
    assert_eq!(applied.revision, v2);
    assert_eq!(
        std::fs::read_to_string(dir.join("current/rules/authz.rego")).unwrap(),
        "allow := true"
    );

    // Rollback: the previous version is still unpacked, so no blob is fetched.
    let blobs_before = stub.blob_requests.load(Ordering::SeqCst);
    stub.publish_rollout(ci.sign(manifest(&ring("all", "", &v1)).as_bytes()));
    assert_eq!(source.poll().unwrap().unwrap().revision, v1);
    assert_eq!(
        std::fs::read_to_string(dir.join("current/rules/authz.rego")).unwrap(),
        "allow := false"
    );
    assert_eq!(
        stub.blob_requests.load(Ordering::SeqCst) - blobs_before,
        1,
        "only the rollout manifest's own layer should be fetched on a rollback"
    );

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn rings_stage_the_rollout_across_the_fleet() {
    let stub = Stub::start();
    let ci = Ci::new();

    let old = stub.publish_blob(bundle("old", "old"));
    let new = stub.publish_blob(bundle("new", "new"));

    // The shape from the design document: dev clusters and a 1% canary get the
    // new bundle, everyone else stays on the old one.
    let rollout = manifest(&format!(
        "{}{}{}",
        ring("dev", "clusters = [\"dev-*\"]", &new),
        ring("canary", "node_hash_percent = 1", &new),
        ring("all", "", &old),
    ));
    stub.publish_rollout(ci.sign(rollout.as_bytes()));

    // A dev cluster is on the new bundle whatever its hash.
    let dev_dir = scratch("ring-dev");
    let dev = source(&stub, &ci, dev_dir.clone(), "dev-eu", "node-1");
    assert_eq!(dev.poll().unwrap().unwrap().revision, new);
    assert_eq!(dev.current().ring, "dev");

    // Production nodes split: find one in the canary and one outside it.
    let mut canary = None;
    let mut broad = None;
    for i in 0..500 {
        let node = format!("node-{i}");
        let dir = scratch(&format!("ring-prod-{i}"));
        let s = source(&stub, &ci, dir.clone(), "prod-eu", &node);
        let bucket = s.bucket();
        if bucket < 1 && canary.is_none() {
            canary = Some((s, dir, node.clone()));
        } else if bucket >= 1 && broad.is_none() {
            broad = Some((s, dir, node.clone()));
        }
        if canary.is_some() && broad.is_some() {
            break;
        }
    }

    let (canary_source, canary_dir, canary_node) = canary.expect("some node is in the 1%");
    assert_eq!(canary_source.poll().unwrap().unwrap().revision, new);
    assert_eq!(canary_source.current().ring, "canary", "node {canary_node}");

    let (broad_source, broad_dir, broad_node) = broad.expect("some node is outside the 1%");
    assert_eq!(broad_source.poll().unwrap().unwrap().revision, old);
    assert_eq!(broad_source.current().ring, "all", "node {broad_node}");

    for dir in [dev_dir, canary_dir, broad_dir] {
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[test]
fn freeze_halts_every_change_including_a_rollback() {
    let stub = Stub::start();
    let ci = Ci::new();
    let dir = scratch("freeze");

    let v1 = stub.publish_blob(bundle("v1", "one"));
    let v2 = stub.publish_blob(bundle("v2", "two"));

    stub.publish_rollout(ci.sign(manifest(&ring("all", "", &v1)).as_bytes()));
    let source = source(&stub, &ci, dir.clone(), "prod-eu", "node-1");
    assert_eq!(source.poll().unwrap().unwrap().revision, v1);

    // The kill switch, with a different bundle named at the same time.
    let frozen = format!("schema = 1\nfreeze = true\n{}", ring("all", "", &v2));
    stub.publish_rollout(ci.sign(frozen.as_bytes()));

    assert!(
        source.poll().unwrap().is_none(),
        "freeze must stop the change"
    );
    assert_eq!(source.current().digest, v1);
    assert_eq!(
        std::fs::read_to_string(dir.join("current/rules/authz.rego")).unwrap(),
        "one"
    );

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_manifest_signed_by_the_wrong_key_is_ignored() {
    let stub = Stub::start();
    let ci = Ci::new();
    let attacker = Ci::new();
    let dir = scratch("badsig");

    let good = stub.publish_blob(bundle("good", "allow := false"));
    stub.publish_rollout(ci.sign(manifest(&ring("all", "", &good)).as_bytes()));
    let source = source(&stub, &ci, dir.clone(), "prod-eu", "node-1");
    assert_eq!(source.poll().unwrap().unwrap().revision, good);

    // Someone who can write to the registry but does not hold the fleet's key.
    let evil = stub.publish_blob(bundle("evil", "allow := true"));
    stub.publish_rollout(attacker.sign(manifest(&ring("all", "", &evil)).as_bytes()));

    let err = source.poll().unwrap_err();
    assert!(matches!(err, Error::Signature(_)), "{err}");
    assert_eq!(source.current().digest, good, "the node keeps what it had");
    assert_eq!(
        std::fs::read_to_string(dir.join("current/rules/authz.rego")).unwrap(),
        "allow := false"
    );

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_bundle_that_does_not_match_its_signed_digest_is_refused() {
    let stub = Stub::start();
    let ci = Ci::new();
    let dir = scratch("swapped");

    // The manifest names one digest; the registry serves different bytes under
    // it, as a compromised or buggy registry would.
    let honest = bundle("honest", "allow := false");
    let digest = digest_of(&honest);
    {
        let mut content = stub.content.lock().unwrap();
        content
            .blobs
            .insert(digest.clone(), bundle("tampered", "allow := true"));
    }
    stub.publish_rollout(ci.sign(manifest(&ring("all", "", &digest)).as_bytes()));

    let source = source(&stub, &ci, dir.clone(), "prod-eu", "node-1");
    let err = source.poll().unwrap_err();

    assert!(matches!(err, Error::Signature(_)), "{err}");
    assert!(err.to_string().contains("signed manifest named"));
    assert!(!dir.join("current").exists(), "nothing is published");

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn an_unreachable_registry_leaves_the_node_serving_what_it_has() {
    let stub = Stub::start();
    let ci = Ci::new();
    let dir = scratch("offline");

    let digest = stub.publish_blob(bundle("v1", "allow := true"));
    stub.publish_rollout(ci.sign(manifest(&ring("all", "", &digest)).as_bytes()));
    let source = source(&stub, &ci, dir.clone(), "prod-eu", "node-1");
    assert!(source.poll().unwrap().is_some());

    stub.set_offline(true);
    for _ in 0..3 {
        let err = source.poll().unwrap_err();
        assert!(matches!(err, Error::Fetch(_)), "{err}");
    }

    // Fail stale: the bundle is still there and still served.
    assert_eq!(source.current().digest, digest);
    assert_eq!(
        std::fs::read_to_string(dir.join("current/rules/authz.rego")).unwrap(),
        "allow := true"
    );
    assert!(source.load_current().is_some());

    // And it recovers on its own when the registry comes back.
    stub.set_offline(false);
    assert!(source.poll().is_ok());

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_bundle_that_fails_validation_never_reaches_a_pod() {
    let stub = Stub::start();
    let ci = Ci::new();

    let cases: [(&str, Vec<u8>); 3] = [
        // No bundle.toml at all.
        ("no-manifest", tar(&[("rules/a.rego", b"x")])),
        // A schema this build does not understand.
        (
            "future-schema",
            tar(&[("bundle.toml", b"schema = 99\n"), ("rules/a.rego", b"x")]),
        ),
        // A path that tries to escape the version directory.
        (
            "escape",
            tar(&[
                ("bundle.toml", b"schema = 1\n"),
                ("../../etc/cron.d/evil", b"* * * * * root sh"),
            ]),
        ),
    ];

    for (name, blob) in cases {
        let dir = scratch(name);
        let digest = stub.publish_blob(blob);
        stub.publish_rollout(ci.sign(manifest(&ring("all", "", &digest)).as_bytes()));

        let source = source(&stub, &ci, dir.clone(), "prod-eu", "node-1");
        let err = source.poll().unwrap_err();
        assert!(
            matches!(err, Error::Rejected(_) | Error::Malformed(_)),
            "{name}: {err}"
        );
        assert!(!dir.join("current").exists(), "{name} was published anyway");
        assert!(source.load_current().is_none(), "{name}");

        // Nothing escaped: the version directory holds no such path.
        assert!(!dir.join("versions/etc").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

#[test]
fn a_node_resumes_its_bundle_after_a_restart_without_the_registry() {
    let stub = Stub::start();
    let ci = Ci::new();
    let dir = scratch("restart");

    let digest = stub.publish_blob(bundle("v1", "allow := true"));
    stub.publish_rollout(ci.sign(manifest(&ring("all", "", &digest)).as_bytes()));
    {
        let source = source(&stub, &ci, dir.clone(), "prod-eu", "node-1");
        assert!(source.poll().unwrap().is_some());
    }

    // Restart with the registry down: the node still knows what it is running,
    // so pods are served immediately rather than after the first poll.
    stub.set_offline(true);
    let restarted = source(&stub, &ci, dir.clone(), "prod-eu", "node-1");

    let current = restarted.current();
    assert_eq!(current.digest, digest);
    assert_eq!(current.ring, "all");
    let resumed = restarted.load_current().expect("the bundle is on disk");
    assert_eq!(resumed.revision, digest);
    assert_eq!(resumed.documents[1].content, b"allow := true");

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn superseded_versions_are_pruned_but_the_rollback_target_is_kept() {
    let stub = Stub::start();
    let ci = Ci::new();
    let dir = scratch("prune");

    let source = source(&stub, &ci, dir.clone(), "prod-eu", "node-1");
    let mut digests = Vec::new();
    for i in 0..4 {
        let digest = stub.publish_blob(bundle(&format!("v{i}"), &format!("rule {i}")));
        stub.publish_rollout(ci.sign(manifest(&ring("all", "", &digest)).as_bytes()));
        assert_eq!(source.poll().unwrap().unwrap().revision, digest);
        digests.push(digest);
    }

    let on_disk: Vec<String> = std::fs::read_dir(dir.join("versions"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();

    // Current plus the one before it: enough to roll back without the network.
    assert_eq!(on_disk.len(), 2, "{on_disk:?}");
    assert!(on_disk.contains(&digests[3].replace(':', "-")));
    assert!(on_disk.contains(&digests[2].replace(':', "-")));

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_node_matching_no_ring_changes_nothing() {
    let stub = Stub::start();
    let ci = Ci::new();
    let dir = scratch("no-ring");

    let digest = stub.publish_blob(bundle("v1", "x"));
    stub.publish_rollout(
        ci.sign(manifest(&ring("dev", "clusters = [\"dev-*\"]", &digest)).as_bytes()),
    );

    let source = source(&stub, &ci, dir.clone(), "prod-eu", "node-1");
    assert!(source.poll().unwrap().is_none());
    assert_eq!(source.current().digest, "");
    assert!(!dir.join("current").exists());

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_source_without_a_trusted_key_refuses_to_start() {
    let stub = Stub::start();
    let dir = scratch("nokey");
    let mut settings = settings(&stub, String::new(), dir.clone());
    settings.public_key = None;

    let err = match BundleSource::new(settings, "prod".into(), "node-1".into()) {
        Ok(_) => panic!("a source with no key must not start"),
        Err(e) => e,
    };
    assert!(matches!(err, Error::Config(_)));
    assert!(err.to_string().contains("public key"));
}

// ------------------------------------------------------------- regressions

#[test]
fn a_failed_bundle_fetch_does_not_wedge_the_node_on_a_304() {
    // Regression. The ETag used to be recorded as soon as the manifest
    // verified, before the bundle it names was fetched. If the blob fetch then
    // failed, the next poll sent that ETag, the registry answered 304, and the
    // node concluded there was nothing to do — for ever, with
    // bundle_age_seconds staying green because a 304 is a successful poll.
    let stub = Stub::start();
    let ci = Ci::new();
    let dir = scratch("etag-wedge");

    // A manifest naming a bundle the registry does not actually serve.
    let missing = digest_of(&bundle("never-published", "x"));
    stub.publish_rollout(ci.sign(manifest(&ring("all", "", &missing)).as_bytes()));

    let source = source(&stub, &ci, dir.clone(), "prod-eu", "node-1");
    assert!(source.poll().is_err(), "the blob is missing");
    assert_eq!(source.current().digest, "");

    // Now the bundle appears. The node must notice, which means it must not
    // have cached an ETag for a manifest it never finished applying.
    let real = stub.publish_blob(bundle("v1", "allow := true"));
    stub.publish_rollout(ci.sign(manifest(&ring("all", "", &real)).as_bytes()));

    let applied = source
        .poll()
        .expect("the poll succeeds")
        .expect("and applies the bundle");
    assert_eq!(applied.revision, real);
    assert_eq!(
        std::fs::read_to_string(dir.join("current/rules/authz.rego")).unwrap(),
        "allow := true"
    );

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn an_unchanged_manifest_is_still_answered_from_the_etag_once_applied() {
    // The other half: once a bundle really is on disk, the ETag must be used,
    // or every node re-downloads the manifest on every poll.
    let stub = Stub::start();
    let ci = Ci::new();
    let dir = scratch("etag-works");

    let digest = stub.publish_blob(bundle("v1", "x"));
    stub.publish_rollout(ci.sign(manifest(&ring("all", "", &digest)).as_bytes()));

    let source = source(&stub, &ci, dir.clone(), "prod-eu", "node-1");
    assert!(source.poll().unwrap().is_some());

    for _ in 0..3 {
        assert!(source.poll().unwrap().is_none());
    }
    assert_eq!(stub.not_modified.load(Ordering::SeqCst), 3);

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_node_with_no_bundle_applied_never_short_circuits_on_an_etag() {
    // The conservative half of the ETag rule. Until a bundle is actually on
    // disk, every poll re-reads the manifest, because a 304 would assert
    // "nothing changed" about a bundle this node has never had. It costs one
    // small download per interval and it always makes progress.
    let stub = Stub::start();
    let ci = Ci::new();
    let dir = scratch("etag-no-bundle");

    let digest = stub.publish_blob(bundle("v1", "x"));
    let frozen = format!("schema = 1\nfreeze = true\n{}", ring("all", "", &digest));
    stub.publish_rollout(ci.sign(frozen.as_bytes()));

    let source = source(&stub, &ci, dir.clone(), "prod-eu", "node-1");
    for _ in 0..3 {
        assert!(
            source.poll().unwrap().is_none(),
            "frozen: nothing is applied"
        );
    }
    assert_eq!(
        stub.not_modified.load(Ordering::SeqCst),
        0,
        "a node holding no bundle must not accept a 304"
    );

    // Once the freeze lifts and a bundle lands, the ETag starts being used.
    stub.publish_rollout(ci.sign(manifest(&ring("all", "", &digest)).as_bytes()));
    assert!(source.poll().unwrap().is_some());
    assert!(source.poll().unwrap().is_none());
    assert_eq!(stub.not_modified.load(Ordering::SeqCst), 1);

    std::fs::remove_dir_all(&dir).unwrap();
}
