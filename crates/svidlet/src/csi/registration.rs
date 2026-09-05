//! Kubelet plugin-registration service.
//!
//! Answering this directly is what removes the `node-driver-registrar` sidecar:
//! the kubelet's plugin watcher notices the socket in `plugins_registry/`,
//! calls `GetInfo`, then dials the endpoint we hand back.

use tonic::{Request, Response, Status};

use super::proto::registration::registration_server::Registration;
use super::proto::registration::{
    InfoRequest, PluginInfo, RegistrationStatus, RegistrationStatusResponse,
};
use crate::{error, info};

pub struct RegistrationService {
    driver_name: String,
    /// The CSI socket path as the kubelet sees it on the host.
    endpoint: String,
}

impl RegistrationService {
    pub fn new(driver_name: String, endpoint: String) -> Self {
        RegistrationService {
            driver_name,
            endpoint,
        }
    }
}

#[tonic::async_trait]
impl Registration for RegistrationService {
    async fn get_info(
        &self,
        _request: Request<InfoRequest>,
    ) -> Result<Response<PluginInfo>, Status> {
        Ok(Response::new(PluginInfo {
            r#type: "CSIPlugin".to_string(),
            name: self.driver_name.clone(),
            endpoint: self.endpoint.clone(),
            supported_versions: vec!["1.0.0".to_string()],
        }))
    }

    async fn notify_registration_status(
        &self,
        request: Request<RegistrationStatus>,
    ) -> Result<Response<RegistrationStatusResponse>, Status> {
        let status = request.into_inner();
        if status.plugin_registered {
            info!(
                "registered with kubelet",
                driver = self.driver_name,
                endpoint = self.endpoint
            );
        } else {
            // Nothing else in the process can publish volumes until this is
            // fixed, so it is logged at error and left visible.
            error!(
                "kubelet rejected registration",
                driver = self.driver_name,
                endpoint = self.endpoint,
                error = status.error,
            );
        }
        Ok(Response::new(RegistrationStatusResponse {}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> RegistrationService {
        RegistrationService::new(
            "csi.svidlet.io".into(),
            "/var/lib/kubelet/plugins/csi.svidlet.io/csi.sock".into(),
        )
    }

    #[tokio::test]
    async fn get_info_identifies_svidlet_as_a_csi_plugin() {
        let info = service()
            .get_info(Request::new(InfoRequest {}))
            .await
            .unwrap()
            .into_inner();

        // The kubelet's plugin watcher dispatches on this exact string.
        assert_eq!(info.r#type, "CSIPlugin");
        assert_eq!(info.name, "csi.svidlet.io");
        assert_eq!(
            info.endpoint,
            "/var/lib/kubelet/plugins/csi.svidlet.io/csi.sock"
        );
        assert_eq!(info.supported_versions, vec!["1.0.0".to_string()]);
    }

    #[tokio::test]
    async fn registration_status_is_accepted_either_way() {
        for (registered, error) in [(true, ""), (false, "driver name mismatch")] {
            assert!(service()
                .notify_registration_status(Request::new(RegistrationStatus {
                    plugin_registered: registered,
                    error: error.into(),
                }))
                .await
                .is_ok());
        }
    }
}
