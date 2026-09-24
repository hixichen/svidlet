//! Process wiring: sockets, background loops, shutdown.

use std::path::Path;
use std::sync::Arc;

use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;

use svidlet_issue::vault::{
    AppRoleAuth, CertAuth, KubernetesAuth, StaticTokenAuth, VaultEndpoint, VaultHttp, VaultIssuer,
    VaultPkiConfig,
};
use svidlet_issue::Issuer;

use crate::config::AuthSettings;

use crate::config::Config;
use crate::csi::identity::IdentityService;
use crate::csi::node::NodeService;
use crate::csi::proto::csi::identity_server::IdentityServer;
use crate::csi::proto::csi::node_server::NodeServer;
use crate::csi::proto::registration::registration_server::RegistrationServer;
use crate::csi::registration::RegistrationService;
use crate::issue::Publisher;
use crate::metrics::Metrics;
use crate::store::Store;
use crate::{debug, error, info, metrics, recover, renew, volume, warn};

pub async fn run(cfg: Config) -> Result<(), Box<dyn std::error::Error>> {
    info!(
        "starting",
        version = env!("CARGO_PKG_VERSION"),
        driver = cfg.driver_name,
        node = cfg.node_name,
        trust_domain = cfg.trust_domain,
        cluster = cfg.cluster,
    );
    if !volume::TMPFS_SUPPORTED {
        warn!("not a Linux host: volumes are plain directories, private keys will touch disk");
    }

    let policy = Arc::new(cfg.id_policy()?);
    info!(
        "issuing identities of this shape",
        template = policy.template().as_str(),
        pattern = policy.pattern().unwrap_or("<none>"),
    );

    let cfg = Arc::new(cfg);
    let store = Arc::new(Store::new());
    let metrics = Arc::new(Metrics::default());
    let issuer = build_issuer(&cfg)?;
    metrics.set_backend(issuer.name(), issuer.auth_name());
    if let AuthSettings::Cert { cert_path, .. } = &cfg.vault.auth {
        metrics.set_node_certificate(cert_path.clone());
        check_node_certificate(&cfg, cert_path);
    }
    info!(
        "pki backend",
        backend = issuer.name(),
        auth = issuer.auth_name()
    );

    if cfg.policy.required {
        info!(
            "policy is required before a pod starts",
            wait_secs = cfg.policy.initial_timeout.as_secs_f64(),
        );
    }
    if cfg.policy_gid.is_some() {
        info!(
            "published volumes are writable by the policy group",
            gid = cfg.policy_gid.unwrap_or_default(),
        );
    }

    let publisher = Arc::new(Publisher::new(
        Arc::clone(&cfg),
        Arc::clone(&policy),
        Arc::clone(&issuer),
        Arc::clone(&store),
        Arc::clone(&metrics),
    ));

    // Prime the trust bundle before serving, but do not make it fatal: the
    // chain returned with the first signature is a usable substitute, and
    // refusing to start during a Vault outage would take down a node that could
    // still be serving already-valid certificates.
    {
        let primer = Arc::clone(&publisher);
        match tokio::task::spawn_blocking(move || primer.prime_ca()).await? {
            Ok(()) => info!("trust bundle loaded", backend = issuer.name()),
            Err(e) => warn!(
                "could not load the trust bundle at start-up; will retry",
                error = e
            ),
        }
    }

    // Adopt whatever this node already has. Nothing is re-issued. The loop
    // re-runs the same adoption periodically: a volume that cannot be adopted
    // the first time is never re-published by the kubelet, so without the
    // loop its certificate would expire under a running pod.
    let adopting = Arc::clone(&publisher);
    tokio::task::spawn_blocking(move || {
        recover::adopt(
            &adopting.cfg,
            &adopting.policy,
            &adopting.store,
            &adopting.metrics,
        )
    })
    .await?;

    tokio::spawn(renew::renewal_loop(Arc::clone(&publisher)));
    tokio::spawn(renew::ca_refresh_loop(Arc::clone(&publisher)));
    tokio::spawn(renew::reaper_loop(Arc::clone(&publisher)));
    tokio::spawn(renew::adopt_loop(Arc::clone(&publisher)));

    if !cfg.metrics_addr.is_empty() {
        tokio::spawn(metrics::serve(
            cfg.metrics_addr.clone(),
            Arc::clone(&metrics),
            Arc::clone(&store),
        ));
    }

    let csi = serve_csi(&cfg, Arc::clone(&publisher))?;
    let registration = serve_registration(&cfg)?;

    // Either server exiting means the plugin can no longer do its job; let the
    // process die so the kubelet sees the sockets close and the DaemonSet
    // restarts it.
    tokio::select! {
        r = csi => { r??; }
        r = registration => { r??; }
        () = shutdown() => info!("shutting down"),
    }
    Ok(())
}

fn serve_csi(
    cfg: &Config,
    publisher: Arc<Publisher>,
) -> Result<tokio::task::JoinHandle<Result<(), tonic::transport::Error>>, Box<dyn std::error::Error>>
{
    let listener = bind(&cfg.csi_socket)?;
    info!("csi socket listening", path = cfg.csi_socket.display());

    let identity = IdentityServer::new(IdentityService::new(cfg.driver_name.clone()));
    let node = NodeServer::new(NodeService::new(publisher));

    Ok(tokio::spawn(async move {
        Server::builder()
            .add_service(identity)
            .add_service(node)
            .serve_with_incoming(UnixListenerStream::new(listener))
            .await
    }))
}

fn serve_registration(
    cfg: &Config,
) -> Result<tokio::task::JoinHandle<Result<(), tonic::transport::Error>>, Box<dyn std::error::Error>>
{
    let listener = bind(&cfg.registration_socket)?;
    info!(
        "registration socket listening",
        path = cfg.registration_socket.display(),
        advertised_endpoint = cfg.advertised_endpoint,
    );

    let registration = RegistrationServer::new(RegistrationService::new(
        cfg.driver_name.clone(),
        cfg.advertised_endpoint.clone(),
    ));

    Ok(tokio::spawn(async move {
        Server::builder()
            .add_service(registration)
            .serve_with_incoming(UnixListenerStream::new(listener))
            .await
    }))
}

/// Bind a Unix socket, clearing any stale one left by a previous instance.
///
/// The kubelet treats a socket that exists but does not answer as a plugin in
/// need of re-registration, so removing it here is what makes a restart clean.
pub fn bind(path: &Path) -> std::io::Result<tokio::net::UnixListener> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::remove_file(path) {
        Ok(()) => debug!("removed a stale socket", path = path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    tokio::net::UnixListener::bind(path).map_err(|e| {
        // The kernel caps a Unix socket path at ~104 bytes, and the message it
        // returns does not say which path was too long.
        if e.kind() == std::io::ErrorKind::InvalidInput {
            std::io::Error::new(
                e.kind(),
                format!(
                    "cannot bind {} ({} bytes): {e}. A Unix socket path is limited to \
                     around 104 bytes; shorten SVIDLET_CSI_SOCKET or SVIDLET_KUBELET_ROOT",
                    path.display(),
                    path.as_os_str().len(),
                ),
            )
        } else {
            std::io::Error::new(e.kind(), format!("cannot bind {}: {e}", path.display()))
        }
    })
}

/// Assemble the PKI backend from its two seams: a [`TokenSource`] that proves
/// who this node is, and an [`Issuer`] that signs. Supporting another vendor
/// means adding arms here, not touching the CSI plugin.
///
/// [`TokenSource`]: svidlet_issue::TokenSource
pub fn build_issuer(cfg: &Config) -> Result<Arc<dyn Issuer>, Box<dyn std::error::Error>> {
    let ca_cert_pem = match &cfg.vault.ca_cert_path {
        Some(path) => Some(
            std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read VAULT_CACERT from {}: {e}", path.display()))?,
        ),
        None => None,
    };

    let http = Arc::new(VaultHttp::new(VaultEndpoint {
        address: cfg.vault.address.clone(),
        namespace: cfg.vault.namespace.clone(),
        ca_cert_pem,
        timeout: cfg.vault.timeout,
    })?);
    let pki = VaultPkiConfig {
        mount: cfg.vault.pki_mount.clone(),
        role: cfg.vault.pki_role.clone(),
    };

    Ok(match &cfg.vault.auth {
        AuthSettings::AppRole {
            mount,
            role_id,
            secret_id_path,
        } => Arc::new(VaultIssuer::new(
            Arc::clone(&http),
            pki,
            AppRoleAuth::new(http, mount.clone(), role_id.clone(), secret_id_path.clone()),
        )),
        AuthSettings::Kubernetes {
            mount,
            role,
            token_path,
        } => Arc::new(VaultIssuer::new(
            Arc::clone(&http),
            pki,
            KubernetesAuth::new(http, mount.clone(), role.clone(), token_path.clone()),
        )),
        AuthSettings::Cert {
            mount,
            role,
            cert_path,
            key_path,
        } => Arc::new(VaultIssuer::new(
            Arc::clone(&http),
            pki,
            CertAuth::new(
                http,
                mount.clone(),
                role.clone(),
                cert_path.clone(),
                key_path.clone(),
            ),
        )),
        AuthSettings::Token { path } => Arc::new(VaultIssuer::new(
            http,
            pki,
            StaticTokenAuth::new(path.clone()),
        )),
    })
}

/// Say at start-up whether the node certificate is the one this node should
/// log in with. Never fatal: until node bootstrap delivers a usable one, the
/// certificates already published keep being served and renewal retries.
fn check_node_certificate(cfg: &Config, path: &Path) {
    let expected = crate::node::expected_id(&cfg.trust_domain, &cfg.cluster, &cfg.node_name);
    match crate::node::read(path) {
        Err(crate::node::ReadError::Missing(e)) => warn!(
            "no node certificate yet; waiting for node bootstrap",
            path = path.display(),
            expected = expected,
            error = e,
        ),
        Err(e) => error!(
            "the node certificate is unusable",
            path = path.display(),
            error = e
        ),
        Ok(facts) => {
            let problems = crate::node::check(&facts, &expected, crate::log::unix_now());
            if problems.is_empty() {
                info!(
                    "node certificate ready",
                    spiffe_id = facts.spiffe_id,
                    expires_in_secs = facts.not_after - crate::log::unix_now(),
                );
            }
            for problem in problems {
                error!(
                    "node certificate will not authenticate this node",
                    path = path.display(),
                    problem = problem,
                );
            }
        }
    }
}

async fn shutdown() {
    use tokio::signal::unix::{signal, SignalKind};
    // Without a signal handler there is nothing to wait for; the servers run
    // until the kubelet kills the pod.
    let Ok(mut term) = signal(SignalKind::terminate()) else {
        return std::future::pending().await;
    };
    let Ok(mut int) = signal(SignalKind::interrupt()) else {
        return std::future::pending().await;
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PolicyGate, VaultSettings};
    use std::path::PathBuf;
    use std::time::Duration;

    fn config(auth: AuthSettings) -> Config {
        Config {
            driver_name: "csi.svidlet.io".into(),
            node_name: "node-1".into(),
            trust_domain: "example.org".into(),
            cluster: "a".into(),
            csi_socket: PathBuf::from("/tmp/csi.sock"),
            registration_socket: PathBuf::from("/tmp/reg.sock"),
            advertised_endpoint: "/tmp/csi.sock".into(),
            kubelet_root: PathBuf::from("/var/lib/kubelet"),
            spiffe_id_template: svidlet_issue::IdTemplate::DEFAULT.into(),
            spiffe_id_pattern: None,
            vault: VaultSettings {
                address: "https://vault.example:8200".into(),
                namespace: None,
                ca_cert_path: None,
                timeout: Duration::from_secs(5),
                pki_mount: "pki".into(),
                pki_role: "spiffe-a".into(),
                auth,
            },
            policy: PolicyGate {
                required: false,
                initial_timeout: Duration::from_secs(10),
            },
            policy_gid: None,
            cert_ttl: Duration::from_secs(3600),
            cert_subject: svidlet_issue::SubjectSource::PodName,
            cloud_profile: Vec::new(),
            token: None,
            renew_fraction: (0.5, 0.7),
            renew_check_interval: Duration::from_secs(30),
            startup_spread: Duration::from_secs(300),
            ca_refresh_interval: Duration::from_secs(3600),
            readopt_interval: Duration::from_secs(60),
            volumes_dir: PathBuf::from("/var/lib/svidlet/volumes"),
            tmpfs_size: "1m".into(),
            key_mode: 0o640,
            key_gid: None,
            cert_mode: 0o644,
            metrics_addr: String::new(),
            log_level: crate::log::Level::Warn,
        }
    }

    #[test]
    fn every_auth_method_produces_a_working_issuer() {
        let cases = [
            (
                AuthSettings::AppRole {
                    mount: "approle".into(),
                    role_id: "r".into(),
                    secret_id_path: "/dev/null".into(),
                },
                "approle",
            ),
            (
                AuthSettings::Kubernetes {
                    mount: "kubernetes".into(),
                    role: "svidlet".into(),
                    token_path: "/dev/null".into(),
                },
                "kubernetes",
            ),
            (
                AuthSettings::Token {
                    path: "/dev/null".into(),
                },
                "token",
            ),
        ];
        for (auth, expected) in cases {
            let issuer = match build_issuer(&config(auth)) {
                Ok(issuer) => issuer,
                Err(e) => panic!("the issuer builds: {e}"),
            };
            assert_eq!(issuer.name(), "vault");
            assert_eq!(issuer.auth_name(), expected);
        }
    }

    #[test]
    fn a_missing_vault_ca_file_is_reported_with_its_path() {
        let mut cfg = config(AuthSettings::Token {
            path: "/dev/null".into(),
        });
        cfg.vault.ca_cert_path = Some(PathBuf::from("/nonexistent/vault-ca.pem"));

        let err = match build_issuer(&cfg) {
            Ok(_) => panic!("a missing CA file must not be ignored"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("VAULT_CACERT"), "{err}");
        assert!(err.contains("/nonexistent/vault-ca.pem"), "{err}");
    }

    #[tokio::test]
    async fn binding_replaces_a_stale_socket_left_by_a_previous_instance() {
        let dir = std::env::temp_dir().join(format!("svidlet-bind-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("nested").join("csi.sock");

        // The parent directory does not exist yet; bind creates it.
        let first = bind(&path).expect("binds");
        assert!(path.exists());
        drop(first);

        // The socket file outlives the listener. A second bind must take it
        // over, or a restarted plugin would never register with the kubelet.
        assert!(path.exists());
        let _second = bind(&path).expect("rebinds over the stale socket");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn binding_somewhere_impossible_is_an_error_not_a_panic() {
        bind(Path::new("/proc/nonexistent/csi.sock")).unwrap_err();
    }
}
