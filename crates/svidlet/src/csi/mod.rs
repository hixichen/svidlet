//! The gRPC surface: the CSI Identity and Node services, and the kubelet's
//! plugin-registration service.

pub mod identity;
pub mod node;
pub mod registration;

pub mod proto {
    pub mod csi {
        tonic::include_proto!("csi.v1");
    }
    pub mod registration {
        tonic::include_proto!("pluginregistration");
    }
}
