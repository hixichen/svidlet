//! `svidlet-policy` — policy distribution, in its own process.
//!
//! Runs beside `svidlet` in the same DaemonSet pod and writes into the same CSI
//! volumes, but holds none of svidlet's credentials and does not need root.
//! See docs/DESIGN.md, "Two processes, one volume".

use std::sync::Arc;

use svidlet::config::PolicyConfig;
use svidlet::policy::daemon::{self, Daemon};
use svidlet::policy::oci::BundleSource;
use svidlet::policy::{grpc, oci, PolicyManager};
use svidlet::{info, log, rand, warn};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = PolicyConfig::from_env()?;
    log::set_level(cfg.log_level);
    rand::seed();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .thread_name("svidlet-policy")
        .build()?;

    runtime.block_on(run(cfg))
}

async fn run(cfg: PolicyConfig) -> Result<(), Box<dyn std::error::Error>> {
    info!(
        "starting",
        version = env!("CARGO_PKG_VERSION"),
        node = cfg.node_name,
        cluster = cfg.cluster,
        kubelet_root = cfg.kubelet_root.display(),
    );

    if !cfg.enabled() {
        // Nothing configured to distribute. Exiting would crash-loop the
        // container; idling makes the "no source configured" state visible and
        // harmless, and its liveness probe keeps answering.
        warn!(
            "no policy source is configured; idling",
            hint = "set SVIDLET_POLICY_ENDPOINT or SVIDLET_BUNDLE_ROLLOUT_REF, \
                    or drop this container from the DaemonSet",
        );
    }

    let node_name = cfg.node_name.clone();
    let metrics_addr = cfg.metrics_addr.clone();
    let stream_enabled = cfg.stream_enabled();
    let bundle_enabled = cfg.bundle_enabled();

    let bundle = if bundle_enabled {
        let settings = cfg.bundle.clone().expect("bundle_enabled implies settings");
        // A failure here is fatal on purpose: it means a bad reference or a key
        // that is not a key, and a daemon that silently published nothing would
        // be worse than one that will not start.
        let source = Arc::new(BundleSource::new(
            settings,
            cfg.cluster.clone(),
            cfg.node_name.clone(),
        )?);
        let current = source.current();
        info!(
            "bundle rollout enabled",
            bucket = source.bucket(),
            ring = if current.ring.is_empty() {
                "<none yet>"
            } else {
                &current.ring
            },
            digest = if current.digest.is_empty() {
                "<none yet>"
            } else {
                &current.digest
            },
        );
        Some(source)
    } else {
        None
    };

    let policy = PolicyManager::new(cfg.clone());
    let daemon = Daemon::new(cfg, policy.clone(), bundle.clone())?;

    if stream_enabled {
        tokio::spawn(grpc::watch_loop(policy.clone(), node_name.clone()));
    }
    if let Some(source) = &bundle {
        tokio::spawn(oci::poll_loop(source.clone(), policy.clone()));
    }
    if !metrics_addr.is_empty() {
        tokio::spawn(daemon::serve_metrics(metrics_addr, daemon.clone()));
    }

    tokio::select! {
        _ = daemon::run_loop(daemon) => {}
        _ = shutdown() => info!("shutting down"),
    }
    Ok(())
}

async fn shutdown() {
    use tokio::signal::unix::{signal, SignalKind};
    let (Ok(mut term), Ok(mut int)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) else {
        return std::future::pending().await;
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
}
