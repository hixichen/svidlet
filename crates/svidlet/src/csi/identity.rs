//! CSI Identity service.

use tonic::{Request, Response, Status};

use super::proto::csi::identity_server::Identity;
use super::proto::csi::{
    GetPluginCapabilitiesRequest, GetPluginCapabilitiesResponse, GetPluginInfoRequest,
    GetPluginInfoResponse, ProbeRequest, ProbeResponse,
};

pub struct IdentityService {
    driver_name: String,
}

impl IdentityService {
    pub fn new(driver_name: String) -> Self {
        IdentityService { driver_name }
    }
}

#[tonic::async_trait]
impl Identity for IdentityService {
    async fn get_plugin_info(
        &self,
        _request: Request<GetPluginInfoRequest>,
    ) -> Result<Response<GetPluginInfoResponse>, Status> {
        Ok(Response::new(GetPluginInfoResponse {
            name: self.driver_name.clone(),
            vendor_version: env!("CARGO_PKG_VERSION").to_string(),
            manifest: Default::default(),
        }))
    }

    async fn get_plugin_capabilities(
        &self,
        _request: Request<GetPluginCapabilitiesRequest>,
    ) -> Result<Response<GetPluginCapabilitiesResponse>, Status> {
        // Node-only driver: no controller service, no volume expansion.
        Ok(Response::new(GetPluginCapabilitiesResponse {
            capabilities: Vec::new(),
        }))
    }

    async fn probe(
        &self,
        _request: Request<ProbeRequest>,
    ) -> Result<Response<ProbeResponse>, Status> {
        // `ready` is left unset, which the spec defines as "assume ready".
        // Readiness deliberately does not depend on the PKI backend: a Vault
        // outage must not make the kubelet stop calling a plugin whose already
        // published certificates are still valid for hours.
        Ok(Response::new(ProbeResponse {}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn plugin_info_names_the_driver_and_version() {
        let svc = IdentityService::new("csi.svidlet.io".into());
        let info = svc
            .get_plugin_info(Request::new(GetPluginInfoRequest {}))
            .await
            .unwrap()
            .into_inner();

        // The kubelet matches this against the CSIDriver object; a mismatch
        // means volumes are never routed here.
        assert_eq!(info.name, "csi.svidlet.io");
        assert_eq!(info.vendor_version, env!("CARGO_PKG_VERSION"));
        assert!(info.manifest.is_empty());
    }

    #[tokio::test]
    async fn no_capabilities_are_advertised() {
        let svc = IdentityService::new("csi.svidlet.io".into());
        let caps = svc
            .get_plugin_capabilities(Request::new(GetPluginCapabilitiesRequest {}))
            .await
            .unwrap()
            .into_inner();
        // Node-only: no controller service, no volume expansion.
        assert!(caps.capabilities.is_empty());
    }

    #[tokio::test]
    async fn probe_always_succeeds() {
        // Readiness must not depend on the PKI backend, or a Vault outage
        // would stop the kubelet calling a plugin whose certificates are fine.
        let svc = IdentityService::new("csi.svidlet.io".into());
        assert!(svc.probe(Request::new(ProbeRequest {})).await.is_ok());
    }
}
