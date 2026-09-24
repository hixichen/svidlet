//! The token issuer: JWT-SVIDs for relying parties that cannot take a
//! certificate.
//!
//! AWS and GCP accept a pod's X.509-SVID directly. Azure, OIDC-only hosted services and
//! internal services that verify bearer tokens do not; for them this issuer
//! turns the X.509-SVID into a signed JWT, and publishes the keys to verify it
//! with. It performs no attestation of its own: it inherits it. Vault already
//! bound the pod certificate to a cluster, and node bootstrap already bound the
//! caller's certificate to a node — the issuer checks the two agree, that the
//! caller holds the pod's key, and that a grant allows the audience.
//!
//! - [`mint`]: the decision, free of I/O.
//! - [`keys`]: the ES256 key pool and the JWKS.
//! - [`grants`]: which identities may have which audiences.
//! - [`config`]: the configuration file.
//! - [`server`]: the gRPC service and the HTTP endpoints for discovery,
//!   the JWKS and metrics.

#![forbid(unsafe_code)]

pub mod config;
pub mod grants;
pub mod keys;
pub mod mint;
pub mod server;
