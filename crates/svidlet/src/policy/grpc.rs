//! The gRPC client that keeps one policy stream open per node.
//!
//! Everything here is transport: connecting, reconnecting, and translating
//! protobuf into [`PolicyBundle`]. The decisions live in [`PolicyManager`].

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tonic::Request;

use super::proto::policy_service_client::PolicyServiceClient;
use super::proto::{watch_request, PolicyUpdate, Subscribe, Unsubscribe, WatchRequest};
use super::{PolicyBundle, PolicyDocument, PolicyManager};
use crate::{debug, info, warn};

/// Longest gap between reconnection attempts.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// Connect, stream, and reconnect for as long as the process runs.
pub async fn watch_loop(manager: Arc<PolicyManager>, node_name: String) {
    if !manager.stream_enabled() {
        debug!("the policy stream is disabled");
        return;
    }
    let Some(endpoint) = manager.settings().stream.endpoint.clone() else {
        return;
    };
    info!("policy backend", endpoint = endpoint, node = node_name);

    let base = manager.settings().stream.reconnect_backoff;
    let mut backoff = base;

    loop {
        match run_stream(&manager, &endpoint, &node_name).await {
            Ok(()) => {
                // A clean end of stream still means we are no longer receiving
                // updates, so reconnect — but without treating it as a fault.
                debug!("policy stream ended; reconnecting");
                backoff = base;
            }
            Err(e) => {
                manager
                    .metrics
                    .stream_reconnects
                    .fetch_add(1, Ordering::Relaxed);
                // Not an error-level event: policy already on disk keeps
                // working, and a backend restart is routine.
                warn!(
                    "policy stream failed; retrying",
                    endpoint = endpoint,
                    retry_in_secs = backoff.as_secs_f64(),
                    error = e,
                );
            }
        }
        manager.set_connected(false);
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

async fn run_stream(
    manager: &Arc<PolicyManager>,
    endpoint: &str,
    node_name: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let channel = connect(manager, endpoint).await?;
    let mut client = PolicyServiceClient::new(channel);

    let (tx, rx) = mpsc::unbounded_channel::<WatchRequest>();

    // A task that keeps the backend's view of our subscriptions in step with
    // the manager's. Re-derived from scratch on every connection, so a
    // reconnect resubscribes everything without extra bookkeeping.
    let sync = tokio::spawn(sync_subscriptions(
        manager.clone(),
        node_name.to_string(),
        tx,
    ));

    let result = pump(manager, &mut client, rx).await;
    sync.abort();
    result
}

async fn connect(
    manager: &Arc<PolicyManager>,
    endpoint: &str,
) -> Result<Channel, Box<dyn std::error::Error + Send + Sync>> {
    let mut builder = Endpoint::from_shared(endpoint.to_string())?
        // A dead connection must be noticed, or the node silently stops
        // receiving policy while believing it is subscribed.
        .keep_alive_while_idle(true)
        .http2_keep_alive_interval(Duration::from_secs(30))
        .keep_alive_timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(10));

    if endpoint.starts_with("https://") {
        let mut tls = ClientTlsConfig::new().with_enabled_roots();
        if let Some(path) = &manager.settings().stream.ca_cert_path {
            let pem =
                std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            tls = tls.ca_certificate(tonic::transport::Certificate::from_pem(pem));
        }
        builder = builder.tls_config(tls)?;
    }

    Ok(builder.connect().await?)
}

/// Send Subscribe and Unsubscribe messages until the wanted set matches what
/// the backend has been told.
async fn sync_subscriptions(
    manager: Arc<PolicyManager>,
    node_name: String,
    tx: mpsc::UnboundedSender<WatchRequest>,
) {
    let mut sent: Vec<String> = Vec::new();
    loop {
        // Register interest before reading the current state, so a change made
        // while this iteration runs still wakes the next one.
        let changed = manager.wanted_changed();

        let wanted = manager.wanted();
        for (spiffe_id, known_revision) in &wanted {
            if !sent.contains(spiffe_id) {
                let message = WatchRequest {
                    node_name: node_name.clone(),
                    request: Some(watch_request::Request::Subscribe(Subscribe {
                        spiffe_id: spiffe_id.clone(),
                        known_revision: known_revision.clone(),
                    })),
                };
                if tx.send(message).is_err() {
                    return; // the stream closed
                }
                sent.push(spiffe_id.clone());
            }
        }

        let wanted_ids: Vec<&String> = wanted.iter().map(|(id, _)| id).collect();
        sent.retain(|id| {
            if wanted_ids.contains(&id) {
                return true;
            }
            let message = WatchRequest {
                node_name: node_name.clone(),
                request: Some(watch_request::Request::Unsubscribe(Unsubscribe {
                    spiffe_id: id.clone(),
                })),
            };
            let _ = tx.send(message);
            false
        });

        changed.await;
    }
}

async fn pump(
    manager: &Arc<PolicyManager>,
    client: &mut PolicyServiceClient<Channel>,
    rx: mpsc::UnboundedReceiver<WatchRequest>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut updates = client
        .watch(Request::new(UnboundedReceiverStream::new(rx)))
        .await?
        .into_inner();

    manager.set_connected(true);

    while let Some(update) = updates.message().await? {
        apply(manager, update);
    }
    Ok(())
}

/// Translate one protobuf update and hand it to the manager.
pub fn apply(manager: &Arc<PolicyManager>, update: PolicyUpdate) {
    if update.spiffe_id.is_empty() {
        manager.reject("<unset>", "the update names no identity");
        return;
    }

    let documents = update
        .documents
        .into_iter()
        .map(|d| PolicyDocument {
            name: d.name,
            content: d.content,
        })
        .collect();

    match PolicyBundle::build(update.revision, documents) {
        Ok(bundle) => {
            if bundle.is_empty() && !update.empty {
                // An update with no documents that is not flagged empty is
                // ambiguous — most likely a backend bug. Refusing it keeps the
                // policy already on disk rather than silently clearing it.
                manager.reject(
                    &update.spiffe_id,
                    "no documents, but the update is not marked empty",
                );
                return;
            }
            manager.apply(&update.spiffe_id, bundle);
        }
        Err(reason) => manager.reject(&update.spiffe_id, &reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::policy::proto::PolicyDocument as ProtoDocument;

    fn manager() -> Arc<PolicyManager> {
        PolicyManager::new(crate::policy::testkit::test_config(Some(
            "http://policy.invalid:9000",
        )))
    }

    fn update(spiffe_id: &str, revision: &str, docs: &[(&str, &str)], empty: bool) -> PolicyUpdate {
        PolicyUpdate {
            spiffe_id: spiffe_id.into(),
            revision: revision.into(),
            documents: docs
                .iter()
                .map(|(n, c)| ProtoDocument {
                    name: (*n).into(),
                    content: c.as_bytes().to_vec(),
                })
                .collect(),
            empty,
        }
    }

    #[test]
    fn a_well_formed_update_is_applied() {
        let m = manager();
        let id = "spiffe://example.org/ns/a/sa/b";
        m.subscribe(id);

        apply(
            &m,
            update(id, "abc123", &[("authz.rego", "allow := true")], false),
        );

        let bundle = m.bundle(id).unwrap();
        assert_eq!(bundle.revision, "abc123");
        assert_eq!(bundle.documents[0].name, "authz.rego");
        assert_eq!(bundle.documents[0].content, b"allow := true");
    }

    #[test]
    fn an_explicitly_empty_update_is_applied() {
        let m = manager();
        let id = "spiffe://example.org/ns/a/sa/b";
        m.subscribe(id);
        apply(&m, update(id, "abc123", &[], true));
        assert!(m.bundle(id).unwrap().is_empty());
        assert_eq!(m.metrics.rejected_updates.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn an_accidentally_empty_update_is_refused_rather_than_clearing_policy() {
        let m = manager();
        let id = "spiffe://example.org/ns/a/sa/b";
        m.subscribe(id);
        apply(&m, update(id, "r1", &[("authz.rego", "allow")], false));

        // No documents and not flagged empty: most likely a backend bug.
        apply(&m, update(id, "r2", &[], false));

        assert_eq!(m.bundle(id).unwrap().revision, "r1");
        assert_eq!(m.metrics.rejected_updates.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn updates_with_unusable_names_or_no_identity_are_refused() {
        let m = manager();
        let id = "spiffe://example.org/ns/a/sa/b";
        m.subscribe(id);

        apply(&m, update(id, "r1", &[("../escape", "x")], false));
        assert!(m.bundle(id).is_none());

        apply(&m, update("", "r1", &[("a", "x")], false));
        assert_eq!(m.metrics.rejected_updates.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn subscription_sync_sends_subscribes_then_unsubscribes() {
        let m = manager();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(sync_subscriptions(m.clone(), "node-1".into(), tx));

        let id = "spiffe://example.org/ns/a/sa/b";
        m.subscribe(id);

        let first = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("a subscribe is sent")
            .unwrap();
        assert_eq!(first.node_name, "node-1");
        match first.request.unwrap() {
            watch_request::Request::Subscribe(s) => {
                assert_eq!(s.spiffe_id, id);
                assert_eq!(s.known_revision, "");
            }
            other => panic!("expected a subscribe, got {other:?}"),
        }

        m.unsubscribe(id);
        let second = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("an unsubscribe is sent")
            .unwrap();
        match second.request.unwrap() {
            watch_request::Request::Unsubscribe(u) => assert_eq!(u.spiffe_id, id),
            other => panic!("expected an unsubscribe, got {other:?}"),
        }

        task.abort();
    }

    #[tokio::test]
    async fn a_resubscribe_reports_the_revision_already_held() {
        let m = manager();
        let id = "spiffe://example.org/ns/a/sa/b";
        m.subscribe(id);
        m.apply(id, PolicyBundle::build("r7".into(), vec![]).unwrap());

        let (tx, mut rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(sync_subscriptions(m.clone(), "node-1".into(), tx));

        let first = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("a subscribe is sent")
            .unwrap();
        match first.request.unwrap() {
            // After a reconnect the backend can skip an identical bundle.
            watch_request::Request::Subscribe(s) => assert_eq!(s.known_revision, "r7"),
            other => panic!("expected a subscribe, got {other:?}"),
        }
        task.abort();
    }

    #[tokio::test]
    async fn the_watch_loop_exits_immediately_when_the_flag_is_off() {
        // An endpoint is configured but the feature is switched off: no
        // connection is attempted, so a local run needs no policy backend.
        let mut settings = manager().settings().clone();
        settings.stream.enabled = false;
        let m = PolicyManager::new(settings);
        tokio::time::timeout(Duration::from_secs(2), watch_loop(m, "node-1".into()))
            .await
            .expect("returns rather than looping");
    }

    #[tokio::test]
    async fn the_watch_loop_exits_immediately_when_policy_is_disabled() {
        let m = PolicyManager::new(crate::policy::testkit::test_config(None));
        tokio::time::timeout(Duration::from_secs(2), watch_loop(m, "node-1".into()))
            .await
            .expect("returns rather than looping");
    }

    #[tokio::test]
    async fn connecting_to_a_bad_endpoint_is_an_error_not_a_panic() {
        let m = manager();
        assert!(connect(&m, "not a url").await.is_err());
    }
}
