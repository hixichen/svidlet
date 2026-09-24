//! Deciding whether to mint a token, and minting it.
//!
//! [`Minter::mint`] is the whole policy, free of I/O: given the calling node's
//! certificate (already verified by the TLS handshake against the node CA),
//! a request and the time, it either returns a signed token or says exactly
//! why not. The checks, in order:
//!
//! 1. **The caller is a node.** Its certificate carries one URI SAN,
//!    `spiffe://<td>/cluster/<c>/node/<n>`.
//! 2. **The pod certificate chains to the pod CA** — the Vault PKI bundle —
//!    is currently valid, and is usable for client authentication. Verified
//!    with `rustls-webpki`, the same path validation rustls performs.
//! 3. **Same cluster.** The pod's SPIFFE ID is under `cluster/<c>/`. A node
//!    can mint any identity in its own cluster already; it must not reach
//!    another.
//! 4. **The caller holds the pod's key.** A fresh proof, signed by the key in
//!    the pod certificate, naming this node ([`svidlet_token::pop`]).
//! 5. **A grant allows the audience** for that SPIFFE ID ([`crate::grants`]).
//!
//! The token's `exp` is the earlier of the configured lifetime and the pod
//! certificate's `notAfter`: a token never outlives the credential that
//! earned it. svidlet re-mints at every certificate renewal, so tokens keep
//! pace with certificates without a schedule of their own.

use std::fmt;
use std::time::Duration;

use base64::Engine as _;
use rustls_pki_types::{CertificateDer, TrustAnchor, UnixTime};
use svidlet_token::{pop, proto::MintRequest, Claims};
use webpki::{EndEntityCert, KeyUsage};
use x509_parser::pem::Pem;
use x509_parser::prelude::{FromDer as _, GeneralName, X509Certificate};

use crate::grants::Grants;
use crate::keys::KeyPool;

/// Why a request was refused. The kind maps onto a gRPC status; the label is a
/// stable metric value; the detail is for the log and the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denied {
    kind: DeniedKind,
    label: &'static str,
    detail: String,
}

/// Which gRPC status a refusal becomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeniedKind {
    /// The caller is not a node of this trust domain.
    Unauthenticated,
    /// The request is malformed, or its proof is stale or wrong.
    InvalidArgument,
    /// Well formed, and not allowed.
    PermissionDenied,
    /// The issuer itself failed.
    Internal,
}

impl Denied {
    fn new(kind: DeniedKind, label: &'static str, detail: impl Into<String>) -> Denied {
        Denied {
            kind,
            label,
            detail: detail.into(),
        }
    }

    #[must_use]
    pub fn kind(&self) -> DeniedKind {
        self.kind
    }

    /// A stable name for the reason, for metric labels.
    #[must_use]
    pub fn label(&self) -> &'static str {
        self.label
    }

    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for Denied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.label, self.detail)
    }
}

impl std::error::Error for Denied {}

/// Every reason a request can be refused, as metric labels.
pub const DENIAL_LABELS: [&str; 9] = [
    "node_identity",
    "pod_certificate",
    "pod_identity",
    "cluster",
    "proof_stale",
    "proof",
    "grant",
    "expired",
    "internal",
];

/// A token, and when it expires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Minted {
    pub token: String,
    pub claims: Claims,
    pub kid: String,
}

/// The issuer's policy and keys.
#[derive(Debug)]
pub struct Minter {
    issuer: String,
    trust_domain: String,
    ttl: Duration,
    pod_anchors: Vec<TrustAnchor<'static>>,
    keys: KeyPool,
    grants: Grants,
}

impl Minter {
    /// Build a minter.
    ///
    /// `pod_ca_pem` is the bundle pod certificates must chain to: the Vault
    /// PKI CA chain, which is also every node's `ca.crt`.
    ///
    /// # Errors
    ///
    /// A description of the problem when `pod_ca_pem` holds no usable CA
    /// certificate.
    pub fn new(
        issuer: &str,
        trust_domain: &str,
        ttl: Duration,
        pod_ca_pem: &str,
        keys: KeyPool,
        grants: Grants,
    ) -> Result<Minter, String> {
        let mut pod_anchors = Vec::new();
        for der in pem_certificates(pod_ca_pem)? {
            let cert = CertificateDer::from(der);
            let anchor = webpki::anchor_from_trusted_cert(&cert)
                .map_err(|e| format!("a pod CA certificate is unusable as an anchor: {e}"))?;
            pod_anchors.push(anchor.to_owned());
        }
        if pod_anchors.is_empty() {
            return Err("the pod CA bundle holds no certificate".into());
        }
        Ok(Minter {
            issuer: issuer.to_string(),
            trust_domain: trust_domain.to_string(),
            ttl,
            pod_anchors,
            keys,
            grants,
        })
    }

    /// The JWKS to publish.
    #[must_use]
    pub fn jwks(&self) -> serde_json::Value {
        self.keys.jwks()
    }

    /// The `iss` of every token.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Decide on one request from the node whose (TLS-verified) leaf
    /// certificate is `node_cert_der`, at Unix time `now`.
    ///
    /// # Errors
    ///
    /// [`Denied`] naming the first check that failed; see the module docs.
    pub fn mint(
        &self,
        node_cert_der: &[u8],
        request: &MintRequest,
        now: i64,
    ) -> Result<Minted, Denied> {
        use DeniedKind::{Internal, InvalidArgument, PermissionDenied, Unauthenticated};

        // 1. The caller.
        let node_id = only_spiffe_id(node_cert_der)
            .map_err(|e| Denied::new(Unauthenticated, "node_identity", e))?;
        let node_cluster = self.cluster_of(&node_id, "node").ok_or_else(|| {
            Denied::new(
                Unauthenticated,
                "node_identity",
                format!("{node_id} is not a node of {}", self.trust_domain),
            )
        })?;

        // 2. The pod certificate.
        let pod = self.verified_pod(&request.pod_cert_chain_pem, now)?;
        let pod_id = pod.id;

        // 3. The cluster.
        let pod_cluster = self.cluster_of(&pod_id, "workload");
        if pod_cluster.as_deref() != Some(node_cluster.as_str()) {
            return Err(Denied::new(
                PermissionDenied,
                "cluster",
                format!("{node_id} may not mint for {pod_id}"),
            ));
        }

        // 4. Possession of the pod key.
        if !pop::is_fresh(request.proof_time, now) {
            return Err(Denied::new(
                InvalidArgument,
                "proof_stale",
                format!(
                    "proof made at {}, {}s from the issuer's clock; at most {}s is accepted",
                    request.proof_time,
                    request.proof_time.abs_diff(now),
                    pop::WINDOW_SECS
                ),
            ));
        }
        let message = pop::message(&node_id, &pod_id, &request.audience, request.proof_time);
        pop::verify(&pod.public_key, &message, &request.proof)
            .map_err(|e| Denied::new(InvalidArgument, "proof", e.to_string()))?;

        // 5. The grant.
        if !self.grants.allows(&pod_id, &request.audience) {
            return Err(Denied::new(
                PermissionDenied,
                "grant",
                format!(
                    "no grant gives {pod_id} the audience {:?}",
                    request.audience
                ),
            ));
        }

        // Sign.
        let not_after = pod.not_after;
        let ttl = i64::try_from(self.ttl.as_secs()).unwrap_or(i64::MAX);
        let exp = now.saturating_add(ttl).min(not_after);
        if exp <= now {
            return Err(Denied::new(
                PermissionDenied,
                "expired",
                "the pod certificate has expired",
            ));
        }
        let mut jti = [0u8; 16];
        self.keys
            .random(&mut jti)
            .map_err(|e| Denied::new(Internal, "internal", e.to_string()))?;
        let claims = Claims {
            iss: self.issuer.clone(),
            sub: pod_id,
            aud: request.audience.clone(),
            iat: now,
            nbf: now,
            exp,
            jti: b64(&jti),
        };
        let payload = serde_json::to_vec(&claims)
            .map_err(|e| Denied::new(Internal, "internal", e.to_string()))?;
        let (kid, token) = self
            .keys
            .sign(|kid| {
                let header = serde_json::json!({ "alg": "ES256", "typ": "JWT", "kid": kid });
                format!("{}.{}", b64(header.to_string().as_bytes()), b64(&payload))
            })
            .map_err(|e| Denied::new(Internal, "internal", e.to_string()))?;
        Ok(Minted { token, claims, kid })
    }

    /// Verify a pod certificate chain against the pod CA at `now`.
    fn verified_pod(&self, chain_pem: &str, now: i64) -> Result<Pod, Denied> {
        use DeniedKind::{Internal, InvalidArgument, PermissionDenied};
        let unparsable = |e: &dyn fmt::Display| {
            Denied::new(
                InvalidArgument,
                "pod_certificate",
                format!("unparsable: {e}"),
            )
        };

        let chain = pem_certificates(chain_pem)
            .map_err(|e| Denied::new(InvalidArgument, "pod_certificate", e))?;
        let Some((leaf_der, rest)) = chain.split_first() else {
            return Err(Denied::new(
                InvalidArgument,
                "pod_certificate",
                "no pod certificate",
            ));
        };
        let leaf_cert = CertificateDer::from(leaf_der.as_slice());
        let intermediates: Vec<CertificateDer<'_>> = rest
            .iter()
            .map(|d| CertificateDer::from(d.as_slice()))
            .collect();
        let end_entity = EndEntityCert::try_from(&leaf_cert).map_err(|e| unparsable(&e))?;
        let now_secs = u64::try_from(now).map_err(|e| {
            Denied::new(
                Internal,
                "internal",
                format!("the clock is before the Unix epoch: {e}"),
            )
        })?;
        end_entity
            .verify_for_usage(
                webpki::ALL_VERIFICATION_ALGS,
                &self.pod_anchors,
                &intermediates,
                UnixTime::since_unix_epoch(Duration::from_secs(now_secs)),
                KeyUsage::client_auth(),
                None,
                None,
            )
            .map_err(|e| {
                Denied::new(
                    PermissionDenied,
                    "pod_certificate",
                    format!("does not chain to the pod CA: {e}"),
                )
            })?;
        let (_, leaf) = X509Certificate::from_der(leaf_der).map_err(|e| unparsable(&e))?;
        Ok(Pod {
            id: only_spiffe_id(leaf_der)
                .map_err(|e| Denied::new(InvalidArgument, "pod_identity", e))?,
            public_key: leaf.public_key().subject_public_key.data.to_vec(),
            not_after: leaf.validity().not_after.timestamp(),
        })
    }

    /// The cluster an ID belongs to, if it is `spiffe://<td>/cluster/<c>/…`
    /// and, for a node, exactly `…/cluster/<c>/node/<n>`.
    fn cluster_of(&self, id: &str, role: &str) -> Option<String> {
        let rest = id.strip_prefix(&format!("spiffe://{}/cluster/", self.trust_domain))?;
        let (cluster, tail) = rest.split_once('/')?;
        if cluster.is_empty() {
            return None;
        }
        if role == "node" {
            let name = tail.strip_prefix("node/")?;
            if name.is_empty() || name.contains('/') {
                return None;
            }
        }
        Some(cluster.to_string())
    }
}

/// What a verified pod certificate contributes to a token.
struct Pod {
    id: String,
    /// The uncompressed EC point the proof must verify against.
    public_key: Vec<u8>,
    not_after: i64,
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The DER of every certificate in a PEM bundle.
fn pem_certificates(pem: &str) -> Result<Vec<Vec<u8>>, String> {
    let mut out = Vec::new();
    for item in Pem::iter_from_buffer(pem.as_bytes()) {
        let item = item.map_err(|e| format!("not PEM: {e}"))?;
        if item.label == "CERTIFICATE" {
            out.push(item.contents);
        }
    }
    Ok(out)
}

/// The single SPIFFE URI SAN of a certificate.
fn only_spiffe_id(der: &[u8]) -> Result<String, String> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| format!("unparsable: {e}"))?;
    let uris: Vec<&str> = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|n| match n {
                    GeneralName::URI(u) => Some(*u),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    match uris.as_slice() {
        [one] if one.starts_with("spiffe://") => Ok((*one).to_string()),
        _ => Err(format!(
            "expected exactly one SPIFFE URI SAN, found {uris:?}"
        )),
    }
}

#[cfg(test)]
mod tests;
