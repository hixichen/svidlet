//! Svidlet — a lightweight SPIFFE X.509 issuer for Kubernetes.
//!
//! One process per node, registered with the kubelet as a CSI node plugin.
//! When a pod starts, the kubelet says which namespace and ServiceAccount it
//! belongs to; svidlet generates a P-256 key on the node, has a PKI backend
//! sign a certificate for
//! `spiffe://<trust-domain>/cluster/<cluster>/ns/<namespace>/sa/<serviceaccount>`,
//! and publishes the result into a tmpfs mounted only into the containers that
//! should hold it.
//!
//! The binary is a thin wrapper around [`server::run`]; everything else lives
//! here so it can be exercised from integration tests.
//!
//! See docs/DESIGN.md.

// Unsafe code is denied crate-wide. The only exception is the pair of mount
// syscalls in `volume`, which are `#[allow]`ed individually with a SAFETY note
// each: a tmpfs cannot be mounted without libc FFI, and shelling out to
// mount(8) would trade two audited lines for a process spawn and a PATH
// dependency. Anything else that needs `unsafe` is a compile error.
#![deny(unsafe_code)]

pub mod config;
pub mod csi;
pub mod issue;
pub mod log;
pub mod metrics;
pub mod policy;
pub mod rand;
pub mod recover;
pub mod renew;
pub mod server;
pub mod store;
pub mod volume;
