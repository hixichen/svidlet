//! The renewal and trust-bundle refresh loops.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::issue::Publisher;
use crate::log::unix_now;
use crate::store::{jittered_renew_at, Entry};
use crate::{debug, error, info, volume, warn};

/// Wake every `renew_check_interval`, renew whatever is due, and go back to
/// sleep.
///
/// Renewals are processed one at a time. Per node the due list is short, and
/// serialising them is a free rate limit on the PKI backend after an outage,
/// when every renewal that failed during the outage comes due at once.
pub async fn renewal_loop(publisher: Arc<Publisher>) {
    let interval = publisher.cfg.renew_check_interval;
    loop {
        tokio::time::sleep(interval).await;
        renew_due(publisher.clone()).await;
    }
}

/// One pass of the renewal loop. Returns how many certificates were attempted.
pub async fn renew_due(publisher: Arc<Publisher>) -> usize {
    let due = publisher.store.due(unix_now());
    if due.is_empty() {
        return 0;
    }
    debug!("renewal tick", due = due.len());
    let count = due.len();

    // The PKI client blocks, so the whole batch runs off the reactor.
    if let Err(e) = tokio::task::spawn_blocking(move || {
        for entry in due {
            renew_one(&publisher, &entry);
        }
    })
    .await
    {
        // Renewal is the one loop whose silent death expires every certificate
        // on the node. It must never fail quietly.
        error!("renewal batch panicked", error = e);
    }
    count
}

/// Renew one certificate in place. Blocking; called from the renewal loop's
/// blocking task, and directly from the integration tests.
pub fn renew_one(publisher: &Publisher, entry: &Entry) {
    let now = unix_now();

    // The pod may have gone away without a NodeUnpublishVolume that reached us.
    // Renewing would recreate the directory tree the kubelet just removed.
    if !entry.target_path.exists() {
        warn!(
            "published volume disappeared; dropping it from the renewal list",
            path = entry.target_path.display(),
            spiffe_id = entry.spiffe_id,
        );
        publisher.store.remove(&entry.target_path);
        return;
    }

    let started = std::time::Instant::now();
    match publisher.issue(&entry.spiffe_id, &entry.target_path) {
        Ok(bundle) => {
            publisher.metrics.observe_renew(started.elapsed());
            let renew_at = jittered_renew_at(
                bundle.not_before,
                bundle.not_after,
                publisher.cfg.renew_fraction,
            );
            publisher.store.record_renewal(
                &entry.target_path,
                bundle.not_before,
                bundle.not_after,
                renew_at,
            );
            publisher.metrics.renewed();
            info!(
                "renewed",
                spiffe_id = entry.spiffe_id,
                pod_uid = entry.pod.uid,
                lifetime_secs = bundle.lifetime_secs(),
                next_renewal_in_secs = (renew_at - now).max(0),
            );
        }
        Err(e) => {
            let code = e.code();
            publisher.metrics.renew_failed(code);
            let failures = publisher.store.record_failure(&entry.target_path, now);
            // The old certificate is still on disk and still valid: renewal
            // starts at half the lifetime, so there is a lot of runway.
            let expires_in = entry.not_after - now;
            let retryable = e.is_retryable();
            if retryable {
                warn!(
                    "renewal failed; will retry",
                    spiffe_id = entry.spiffe_id,
                    code = code,
                    error = e,
                    failures = failures,
                    current_cert_expires_in_secs = expires_in,
                );
            } else {
                error!(
                    "renewal failed and is unlikely to succeed on retry",
                    spiffe_id = entry.spiffe_id,
                    code = code,
                    error = e,
                    failures = failures,
                    current_cert_expires_in_secs = expires_in,
                );
            }
        }
    }
}

/// Periodically refresh `ca.crt` in every published volume.
///
/// This is what lets a trust-domain root rotation reach running workloads
/// without restarting them or re-issuing their certificates.
pub async fn ca_refresh_loop(publisher: Arc<Publisher>) {
    let interval = publisher.cfg.ca_refresh_interval;
    loop {
        tokio::time::sleep(interval).await;
        refresh_ca_once(publisher.clone()).await;
    }
}

/// One pass of the trust-bundle refresh.
pub async fn refresh_ca_once(publisher: Arc<Publisher>) {
    let _ = tokio::task::spawn_blocking(move || match publisher.refresh_ca() {
        Ok(0) => debug!("trust bundle unchanged"),
        Ok(updated) => {
            publisher
                .metrics
                .ca_refreshes
                .fetch_add(1, Ordering::Relaxed);
            info!("trust bundle refreshed", volumes_updated = updated);
        }
        Err(e) => {
            crate::metrics::Metrics::inc(&publisher.metrics.ca_refresh_failures);
            warn!(
                "trust bundle refresh failed; keeping the current ca.crt",
                code = e.code(),
                error = e,
            );
        }
    })
    .await;
}

/// Remove entries whose target path no longer exists.
///
/// `NodeUnpublishVolume` is the normal way a volume leaves the store; this
/// catches the case where the kubelet tore a pod down while the plugin was not
/// running, so no unpublish call was ever delivered.
pub async fn reaper_loop(publisher: Arc<Publisher>) {
    let interval = publisher.cfg.ca_refresh_interval;
    loop {
        tokio::time::sleep(interval).await;
        reap_orphans(&publisher);
    }
}

/// One pass of the reaper. Returns how many entries were dropped.
pub fn reap_orphans(publisher: &Publisher) -> usize {
    let mut reaped = 0;
    for entry in publisher.store.all() {
        if !entry.target_path.exists() {
            info!(
                "reaping an orphaned volume",
                path = entry.target_path.display(),
                spiffe_id = entry.spiffe_id,
            );
            publisher.store.remove(&entry.target_path);
            let _ = volume::unpublish(&entry.target_path);
            reaped += 1;
        }
    }
    reaped
}
