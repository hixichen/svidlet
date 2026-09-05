//! The PKI-engine seam.

use std::time::Duration;

use crate::bundle::IssuedBundle;
use crate::error::Result;
use crate::template::SpiffeId;

/// One certificate to sign.
///
/// Deliberately vendor-neutral: a CSR, the identity it must carry, how long it
/// should live, and who is asking. A backend that needs more — cert-manager's
/// `issuerRef`, a cloud CA's pool name — carries that in its own configuration
/// rather than in the request, so adding one does not change this type.
#[derive(Debug, Clone, Copy)]
pub struct SignRequest<'a> {
    /// The identity the certificate must carry, already rendered and checked
    /// against the operator's SPIFFE ID policy.
    pub spiffe_id: &'a SpiffeId,
    /// PKCS#10, PEM encoded.
    pub csr_pem: &'a str,
    /// Requested lifetime. Backends may clamp it to their own maximum; the
    /// caller reads the real lifetime back off the issued certificate.
    pub ttl: Duration,
    /// The node making the request, for the backend's audit trail.
    pub node_name: &'a str,
}

/// A PKI backend that signs CSRs for workload identities.
///
/// HashiCorp Vault PKI is the first implementation. step-ca, cert-manager
/// `CertificateRequest` and cloud-managed CAs slot in here without the CSI
/// plugin knowing; so does a `PodCertificateRequest` signer on Kubernetes 1.35+.
///
/// Implementations are shared across threads and called from a blocking pool.
pub trait Issuer: Send + Sync {
    /// Sign one CSR.
    ///
    /// The backend is expected to enforce that the requested URI SAN falls
    /// inside the prefix it is configured for — that enforcement is what keeps
    /// a compromised node from minting identities in another cluster.
    /// Implementations must also verify the returned certificate actually
    /// carries the requested identity before handing it back, so a
    /// misconfigured backend is caught on the node.
    fn sign(&self, request: &SignRequest<'_>) -> Result<IssuedBundle>;

    /// Current trust bundle (CA chain) for the trust domain.
    fn ca_chain(&self) -> Result<String>;

    /// Short name for logs and metric labels, e.g. `vault`.
    fn name(&self) -> &'static str;

    /// Short name of the authentication method in use, e.g. `approle`.
    ///
    /// Reported alongside `name()` so an operator can see at a glance which
    /// credential a node is holding.
    fn auth_name(&self) -> &'static str {
        "none"
    }
}
