//! Issuance library for Svidlet.
//!
//! Renders a SPIFFE ID from a template, generates a P-256 key and a CSR for it,
//! hands the CSR to a PKI backend, and verifies what comes back.
//!
//! Three seams keep vendors out of the plugin:
//!
//! - [`Issuer`] is the PKI engine. Vault PKI is the first implementation;
//!   step-ca, cert-manager `CertificateRequest`, cloud-managed CAs and a
//!   `PodCertificateRequest` signer all fit behind it.
//! - [`TokenSource`] is how a node proves who it is to that engine. Vault
//!   AppRole, Vault Kubernetes auth and a static token ship here.
//! - [`IdPolicy`] is the shape of the identity itself, so the SPIFFE ID layout
//!   is an operator's decision rather than a constant in the code.
//!
//! This crate knows nothing about CSI or Kubernetes. It is the piece that
//! survives the migration to `PodCertificateRequest` signing on Kubernetes
//! 1.35+, where the kubelet takes over key generation and mounting.

// This crate handles key material and parses input from a PKI backend. There is
// nothing here that needs raw pointers, so the compiler is told to reject them
// outright rather than leaving it to review.
#![forbid(unsafe_code)]

pub mod auth;
pub mod bundle;
pub mod error;
pub mod issuer;
pub mod key;
pub mod template;
pub mod vault;

pub use auth::{Token, TokenCache, TokenSource};
pub use bundle::{assert_identity, inspect, CertFacts, IssuedBundle};
pub use error::{Error, ErrorCode, Result};
pub use issuer::{Issuer, SignRequest};
pub use key::{generate, KeyAndCsr};
pub use template::{Field, IdPolicy, IdTemplate, SpiffeId, WorkloadAttributes};
pub use vault::{
    AppRoleAuth, KubernetesAuth, StaticTokenAuth, VaultEndpoint, VaultHttp, VaultIssuer,
    VaultPkiConfig,
};
