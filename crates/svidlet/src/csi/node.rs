//! CSI Node service — where identity is actually decided.
//!
//! The namespace and ServiceAccount come from the kubelet's volume context.
//! Nothing here reads pod labels or annotations, so a principal who can create
//! a pod still cannot choose which identity that pod receives.

use std::path::PathBuf;
use std::sync::Arc;

use tonic::{Request, Response, Status};

use svidlet_issue::{SpiffeId, WorkloadAttributes};

use super::proto::csi::node_server::Node;
use super::proto::csi::{
    NodeGetCapabilitiesRequest, NodeGetCapabilitiesResponse, NodeGetInfoRequest,
    NodeGetInfoResponse, NodePublishVolumeRequest, NodePublishVolumeResponse,
    NodeUnpublishVolumeRequest, NodeUnpublishVolumeResponse,
};
use crate::config::volume_context as vc;
use crate::issue::Publisher;
use crate::log::unix_now;
use crate::metrics::Metrics;
use crate::store::{jittered_renew_at, Entry, PodRef};
use crate::{debug, error, info, volume, warn};

/// Wait for `svidlet-policy` to publish a revision file into this volume.
async fn wait_for_policy(target: &std::path::Path, timeout: std::time::Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    let revision = target.join(crate::config::REVISION_FILE);
    loop {
        if revision.exists() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

/// Map an issuance failure onto the gRPC status the kubelet should see.
///
/// The distinction matters in `kubectl describe pod`: `InvalidArgument` says
/// the request was malformed, `PermissionDenied` says it was well formed and
/// refused, and `Internal` says the fault is ours.
fn status_for(e: svidlet_issue::Error) -> Status {
    use svidlet_issue::ErrorCode;
    match e.code() {
        ErrorCode::Identity => Status::invalid_argument(e.to_string()),
        ErrorCode::Policy => Status::permission_denied(e.to_string()),
        _ => Status::internal(e.to_string()),
    }
}

pub struct NodeService {
    publisher: Arc<Publisher>,
}

impl NodeService {
    pub fn new(publisher: Arc<Publisher>) -> Self {
        NodeService { publisher }
    }

    /// Build the SPIFFE ID from the kubelet's volume context.
    ///
    /// Only the fields the configured template actually substitutes are
    /// required. A template that never mentions the pod name works on a cluster
    /// that does not supply one; a template that does mention it fails loudly
    /// rather than issuing an identity with a blank segment.
    fn identity_from(
        &self,
        ctx: &std::collections::HashMap<String, String>,
    ) -> Result<(SpiffeId, PodRef), Status> {
        let cfg = &self.publisher.cfg;
        let field = |key: &str| ctx.get(key).cloned().unwrap_or_default();

        let attrs = WorkloadAttributes {
            trust_domain: cfg.trust_domain.clone(),
            cluster: cfg.cluster.clone(),
            namespace: field(vc::POD_NAMESPACE),
            service_account: field(vc::SERVICE_ACCOUNT),
            pod_name: field(vc::POD_NAME),
            pod_uid: field(vc::POD_UID),
            node_name: cfg.node_name.clone(),
        };

        // Name the missing volume-context key rather than the template field:
        // the fix is almost always podInfoOnMount on the CSIDriver object.
        for (key, value) in [
            (vc::POD_NAMESPACE, &attrs.namespace),
            (vc::SERVICE_ACCOUNT, &attrs.service_account),
            (vc::POD_NAME, &attrs.pod_name),
            (vc::POD_UID, &attrs.pod_uid),
        ] {
            if value.is_empty() && self.template_needs(key) {
                return Err(Status::invalid_argument(format!(
                    "volume context is missing {key}, which the SPIFFE ID template {:?} needs; \
                     the CSIDriver object must set podInfoOnMount: true",
                    cfg.spiffe_id_template
                )));
            }
        }

        let pod = PodRef {
            name: attrs.pod_name.clone(),
            namespace: attrs.namespace.clone(),
            uid: attrs.pod_uid.clone(),
        };

        let spiffe_id = self.publisher.spiffe_id(&attrs).map_err(status_for)?;
        Ok((spiffe_id, pod))
    }

    /// Whether the configured template substitutes the attribute that a given
    /// volume-context key carries.
    fn template_needs(&self, key: &str) -> bool {
        use svidlet_issue::Field;
        let field = match key {
            vc::POD_NAMESPACE => Field::Namespace,
            vc::SERVICE_ACCOUNT => Field::ServiceAccount,
            vc::POD_NAME => Field::PodName,
            vc::POD_UID => Field::PodUid,
            _ => return false,
        };
        self.publisher
            .policy
            .template()
            .required_fields()
            .contains(&field)
    }
}

#[tonic::async_trait]
impl Node for NodeService {
    async fn node_publish_volume(
        &self,
        request: Request<NodePublishVolumeRequest>,
    ) -> Result<Response<NodePublishVolumeResponse>, Status> {
        let req = request.into_inner();
        if req.volume_id.is_empty() {
            return Err(Status::invalid_argument("volume_id is required"));
        }
        if req.target_path.is_empty() {
            return Err(Status::invalid_argument("target_path is required"));
        }
        // Svidlet only serves inline ephemeral volumes. A PersistentVolume
        // pointing at this driver would have no pod context to derive an
        // identity from, so it is refused rather than guessed at.
        if req.volume_context.get(vc::EPHEMERAL).map(String::as_str) != Some("true") {
            return Err(Status::invalid_argument(
                "svidlet serves inline ephemeral volumes only; use a csi: volume in the pod spec",
            ));
        }

        let (spiffe_id, pod) = self.identity_from(&req.volume_context)?;
        let target = PathBuf::from(&req.target_path);
        let publisher = self.publisher.clone();

        // The kubelet retries NodePublishVolume until it succeeds, and calls it
        // again on any subsequent mount of the same volume. Publishing twice
        // would mint a second certificate and leak the first from the renewal
        // list, so an already-served target is answered from the store.
        if let Some(existing) = publisher.store.get(&target) {
            if existing.spiffe_id == spiffe_id {
                debug!(
                    "volume already published",
                    spiffe_id = spiffe_id,
                    target = req.target_path,
                );
                return Ok(Response::new(NodePublishVolumeResponse {}));
            }
            return Err(Status::already_exists(format!(
                "target path already holds {}",
                existing.spiffe_id
            )));
        }

        let tmpfs_size = publisher.cfg.tmpfs_size.clone();
        let policy_gid = publisher.cfg.policy_gid;
        let target_for_task = target.clone();
        let id_for_task = spiffe_id.clone();

        // Key generation and the call to the PKI backend both block.
        let started = std::time::Instant::now();
        let outcome = tokio::task::spawn_blocking(move || {
            volume::ensure_tmpfs(&target_for_task, &tmpfs_size, policy_gid)
                .map_err(svidlet_issue::Error::Io)?;
            publisher.issue(&id_for_task, &target_for_task)
        })
        .await
        .map_err(|e| Status::internal(format!("issuance task panicked: {e}")))?;

        let bundle = match outcome {
            Ok(bundle) => {
                self.publisher.metrics.observe_publish(started.elapsed());
                bundle
            }
            Err(e) => {
                let code = e.code();
                self.publisher.metrics.publish_failed(code);
                // Leave nothing half-published behind: the kubelet will retry,
                // and a stale tmpfs would make the retry look like a republish.
                let _ = volume::unpublish(&target);
                if e.is_caller_error() {
                    // A pod asked for something it may not have. Loud enough to
                    // find, but not an operational alert.
                    warn!(
                        "refused to issue",
                        spiffe_id = spiffe_id,
                        pod = pod.name,
                        namespace = pod.namespace,
                        code = code,
                        error = e,
                    );
                } else {
                    error!(
                        "issuance failed",
                        spiffe_id = spiffe_id,
                        pod = pod.name,
                        namespace = pod.namespace,
                        code = code,
                        retryable = e.is_retryable(),
                        error = e,
                    );
                }
                return Err(status_for(e));
            }
        };

        // The only thing svidlet knows about policy: whether a revision file
        // has appeared beside the certificate it just wrote. The policy daemon
        // discovers this volume by reading that certificate, so the certificate
        // has to exist first. No IPC, no shared credential, one direction.
        if self.publisher.cfg.policy.required {
            let timeout = self.publisher.cfg.policy.initial_timeout;
            if !wait_for_policy(&target, timeout).await {
                let _ = volume::unpublish(&target);
                error!(
                    "no policy arrived; refusing to publish",
                    spiffe_id = spiffe_id,
                    pod = pod.name,
                    namespace = pod.namespace,
                    waited_secs = timeout.as_secs_f64(),
                );
                return Err(Status::unavailable(format!(
                    "no policy for {spiffe_id} after {timeout:?}; SVIDLET_POLICY_REQUIRED is set \
                     and svidlet-policy has not published a bundle for it"
                )));
            }
        }

        let renew_at = jittered_renew_at(
            bundle.not_before,
            bundle.not_after,
            self.publisher.cfg.renew_fraction,
        );
        self.publisher.store.insert(Entry {
            volume_id: req.volume_id.clone(),
            target_path: target,
            spiffe_id: spiffe_id.clone(),
            pod: pod.clone(),
            not_before: bundle.not_before,
            not_after: bundle.not_after,
            renew_at,
            failures: 0,
        });
        self.publisher.metrics.published();

        info!(
            "published",
            spiffe_id = spiffe_id,
            pod = pod.name,
            namespace = pod.namespace,
            target = req.target_path,
            volume_id = req.volume_id,
            lifetime_secs = bundle.lifetime_secs(),
            renewal_in_secs = (renew_at - unix_now()).max(0),
        );
        Ok(Response::new(NodePublishVolumeResponse {}))
    }

    async fn node_unpublish_volume(
        &self,
        request: Request<NodeUnpublishVolumeRequest>,
    ) -> Result<Response<NodeUnpublishVolumeResponse>, Status> {
        let req = request.into_inner();
        if req.target_path.is_empty() {
            return Err(Status::invalid_argument("target_path is required"));
        }
        let target = PathBuf::from(&req.target_path);

        let removed = self.publisher.store.remove(&target);
        let target_for_task = target.clone();
        tokio::task::spawn_blocking(move || volume::unpublish(&target_for_task))
            .await
            .map_err(|e| Status::internal(format!("unpublish task panicked: {e}")))?
            .map_err(|e| {
                Status::internal(format!("could not unpublish {}: {e}", target.display()))
            })?;

        Metrics::inc(&self.publisher.metrics.unpublished);
        match removed {
            Some(entry) => info!(
                "unpublished",
                spiffe_id = entry.spiffe_id,
                volume_id = entry.volume_id,
                target = req.target_path,
            ),
            // Idempotent by contract: the kubelet retries until it gets an OK.
            None => debug!("unpublish of an unknown volume", target = req.target_path),
        }
        Ok(Response::new(NodeUnpublishVolumeResponse {}))
    }

    async fn node_get_capabilities(
        &self,
        _request: Request<NodeGetCapabilitiesRequest>,
    ) -> Result<Response<NodeGetCapabilitiesResponse>, Status> {
        // No staging, no volume stats, no expansion.
        Ok(Response::new(NodeGetCapabilitiesResponse {
            capabilities: Vec::new(),
        }))
    }

    async fn node_get_info(
        &self,
        _request: Request<NodeGetInfoRequest>,
    ) -> Result<Response<NodeGetInfoResponse>, Status> {
        Ok(Response::new(NodeGetInfoResponse {
            node_id: self.publisher.cfg.node_name.clone(),
            max_volumes_per_node: 0,
        }))
    }
}
