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
    /// The pod this certificate is for, as the kubelet described it.
    ///
    /// A backend that signs on the node's own authority (Vault PKI with a
    /// per-cluster credential) ignores it. The broker needs it: the pod token
    /// in here is what proves to the broker that the kubelet on this node
    /// asked for this pod, and everything else in it is only a hint the broker
    /// re-derives from that token.
    pub pod: Option<PodContext<'a>>,
}

/// What the kubelet told the node about one pod.
#[derive(Clone, Copy)]
pub struct PodContext<'a> {
    pub namespace: &'a str,
    pub name: &'a str,
    pub uid: &'a str,
    pub service_account: &'a str,
    /// The pod-bound ServiceAccount token the kubelet minted for the CSI
    /// driver (`tokenRequests` on the CSIDriver). `None` until the kubelet has
    /// supplied one — after a restart, until the next republish.
    pub token: Option<&'a str>,
}

/// Never print the token: a `SignRequest` is the kind of value that ends up
/// in a `{:?}` during debugging.
impl std::fmt::Debug for PodContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PodContext")
            .field("namespace", &self.namespace)
            .field("name", &self.name)
            .field("uid", &self.uid)
            .field("service_account", &self.service_account)
            .field("token", &self.token.map(|_| "<redacted>"))
            .finish()
    }
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
