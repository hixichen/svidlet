# Svidlet — Design

A lightweight SPIFFE X.509 issuer for Kubernetes, in Rust.

**Status:** Design draft · **Date:** 2026-09-05 · **License:** Apache-2.0

## TL;DR

Every pod that should have an identity gets a short-lived X.509 certificate carrying a SPIFFE (Secure Production Identity Framework for Everyone) ID, so services can authenticate each other with mutual TLS (mTLS) at the application layer instead of trusting network position.

Svidlet is a small Rust DaemonSet that acts as a CSI (Container Storage Interface) node plugin. When a pod starts, the kubelet tells the plugin which namespace and ServiceAccount the pod belongs to; the plugin generates a private key on the node, asks a PKI backend (HashiCorp Vault PKI first; other backends later) to sign a certificate with the identity `spiffe://<trust-domain>/cluster/<cluster>/ns/<namespace>/sa/<serviceaccount>`, and mounts the result into only the containers that should hold it. The plugin authenticates to Vault with one AppRole per cluster.

Why this shape: it fits very small DaemonSet memory budgets (target 5–8 MB), keeps certificate issuance off the Kubernetes API server, works on Kubernetes 1.31+, respects restricted Pod Security Standards, and scales to tens of thousands of nodes with one PKI credential per cluster.

## Problem

- Services commonly authenticate each other by network position (namespace, NetworkPolicy) or shared secrets. Per-workload identity enables application-level mTLS and explicit authorization by peer identity.
- Existing options each miss a constraint:
  - **SPIRE** is the reference implementation but its agent alone consumes tens to hundreds of MB per node, and it brings a server component and its own datastore.
  - **cert-manager `csi-driver-spiffe`** issues X.509 SVIDs but runs three Go processes per node (driver, registrar, approver), routes every issuance through API server objects, and fixes the SPIFFE path to `/ns/<ns>/sa/<sa>`, so multi-cluster deployments need separate trust domains and federation.
  - **cert-manager `Certificate` → Secret** is built for long-lived, deployment-level certificates: private keys land in etcd, rotation requires remounting, and one object per pod does not scale.
  - **`PodCertificateRequest`** (KEP-4317) is the right long-term primitive but requires Kubernetes 1.35+.
- Multi-tenant clusters often run untrusted workloads under restricted Pod Security Standards (PSS): no `hostPath`, no privileged containers in those pods. Identity delivery must respect that.
- Node-level agents on edge or resource-constrained nodes may have only tens of MB of memory available across all DaemonSets.
- Designs where each pod authenticates to the PKI backend directly create one PKI identity per ServiceAccount, which does not scale operationally.

## Requirements

- X.509 SVIDs only (no JWT SVIDs).
- Certificates held per container: a platform-owned sidecar can hold an identity that the tenant container in the same pod cannot read.
- The identity a pod receives must not be chosen by the pod itself (no label/annotation-derived identity).
- The SPIFFE ID layout must be an operator's decision, not a constant in the code: not every deployment wants the cluster in the path, and some want the node or pod in it.
- The PKI backend and the way a node authenticates to it must be separable, so a second vendor does not mean a second plugin.
- Vault must not need to call back into cluster API servers, and must not require per-cluster key material beyond one credential per cluster.
- Single trust domain across clusters; no bundle federation.
- Kubernetes 1.31+, restricted PSS for tenant pods.

## Design

### Components

**1. `svidlet` — CSI node plugin (Rust, DaemonSet, one process per node)**

- Implements the kubelet plugin-registration protocol itself (no `node-driver-registrar` sidecar).
- On `NodePublishVolume`: reads the pod's namespace, ServiceAccount, name and UID from the volume context supplied by the kubelet; generates a P-256 private key in memory; builds a certificate signing request (CSR); hands the CSR to the PKI backend (Vault: `pki/sign/spiffe-<cluster>`) with the URI SAN above; writes `tls.crt`, `tls.key`, `ca.crt` to a tmpfs mount.
- Renews at a random point between 50 % and 70 % of the certificate lifetime, writing files atomically so applications can reload on file change.
- On restart, rebuilds its renewal list from the kubelet's CSI volume records under `/var/lib/kubelet/pods`; never re-issues on restart.
- Refreshes `ca.crt` from Vault's CA chain periodically.
- Target footprint: 5–8 MB resident memory, one static binary (musl), no Kubernetes API server access, no Tokio-heavy dependency tree.

**2. PKI backend — Vault PKI (one-time configuration per cluster)**

The backend is behind an `Issuer` trait in the `svidlet-issue` crate; Vault PKI is the first implementation. Other backends (step-ca, cert-manager `CertificateRequest`, cloud-managed CAs) can be added without touching the CSI plugin.


- One PKI mount and one intermediate CA shared by all clusters (single trust domain, one `ca.crt` everywhere).
- One PKI role per cluster whose `allowed_uri_sans` is pinned to `spiffe://<td>/cluster/<cluster>/ns/*/sa/*`, with `no_store=true` and no DNS/IP SANs permitted.
- One AppRole per cluster, with a policy granting only `update` on that cluster's `pki/sign/…` path and `read` on the CA chain. The role ID ships in the DaemonSet config; the secret ID is delivered as a Kubernetes Secret and rotated on a fixed cadence.
- The plugin logs in once and keeps a periodic, renewable token; it does not log in per certificate.

**3. Policy distribution (optional)**

A certificate says who a workload *is*. It says nothing about who it may talk to, and that half has to come from somewhere. When a policy endpoint is configured, the plugin holds one long-lived bidirectional gRPC stream per node to a policy backend — a service fronting a git repository, typically — subscribes to the identities that node hosts, and publishes each returned bundle into that workload's volume beside its certificate. Upstream changes are pushed, not polled, and reach the volume without restarting the pod.

One stream per node, not per pod: a node running fifty workloads holds one connection. Certificate issuance does not depend on the policy backend — a backend outage leaves the policy already on disk in place and fills in the rest when the stream recovers — unless the operator sets `SVIDLET_POLICY_REQUIRED`, which trades that for refusing to start a pod that would run unpoliced.

Policy can also be distributed the other way round — pulled as a signed, content-addressed OCI artifact with a staged ring rollout, rather than pushed over a stream. That is a design of its own: see [POLICY.md](POLICY.md). Both sources sit behind one seam and write to the same directory in the volume.

`SVIDLET_POLICY_ENABLED=false` disables the whole subsystem independently of whether an endpoint is configured, so a deployment can be run without a policy backend without editing its manifest. It is deliberately a separate switch rather than "unset the endpoint": during local development and when narrowing down a production problem, the useful operation is turning the feature off while leaving the configuration alone.

**No mutating webhook.** Workloads declare the `csi` ephemeral volume themselves and mount it only into the containers that should hold the identity. A webhook would add an admission-path dependency and a certificate to manage for the sake of saving six lines of YAML.

### Seams

Three things are behind traits, because they are the three that change for different reasons:

| Seam | Trait | Ships with | Later |
|---|---|---|---|
| PKI engine | `Issuer` | Vault PKI | step-ca, cert-manager `CertificateRequest`, cloud CAs, `PodCertificateRequest` |
| Node authentication | `TokenSource` | Vault AppRole, Vault Kubernetes auth, static token | Cloud IAM |
| Identity layout | `IdPolicy` | A template plus an optional operator regex | — |

The identity layout is a template rather than a constant:

```
spiffe://{trust_domain}/cluster/{cluster}/ns/{namespace}/sa/{service_account}   (default)
spiffe://{trust_domain}/ns/{namespace}/sa/{service_account}                     (SPIRE shape)
spiffe://{trust_domain}/node/{node_name}/ns/{namespace}/pod/{pod_name}
```

The template both renders an ID and takes one apart again, which is what lets restart recovery read an identity back out of a certificate instead of keeping state on disk. `SVIDLET_SPIFFE_ID_PATTERN` is a second, independent gate: the template says what svidlet builds, the pattern says what it is allowed to build, and an ID failing it is refused with `PermissionDenied` rather than signed.

### Benefits

1. **Fits tiny memory budgets.** One Rust process per node versus three Go processes or a SPIRE agent; deployable where existing agents are not.
2. **Issuance path avoids the API server.** Each certificate is one HTTPS call to Vault. The cert-manager path is four API server writes plus a watch per certificate — at hundreds of thousands of certificates per day that is continuous etcd churn and a per-cluster controller in the critical path of pod start-up.
3. **Identity the pod cannot forge.** Namespace and ServiceAccount come from the kubelet, not from pod metadata, so anyone able to create a pod cannot claim another workload's identity. Private keys are generated on the node and never leave tmpfs.
4. **Single trust domain, cluster-scoped blast radius.** The cluster name lives in the SPIFFE path, not the trust domain, so cross-cluster mTLS needs no federation. Vault enforces the per-cluster prefix: a compromised node can at most impersonate identities within its own cluster.
5. **One PKI identity per cluster.** One AppRole per cluster, regardless of how many ServiceAccounts exist; adding a workload never touches the PKI backend.
6. **Fail-safe under Vault outages.** With a 24 h lifetime and renewal starting at 12 h, running pods keep working through a half-day Vault outage; only new pod start-ups are delayed.
7. **Clear upgrade path.** The issuance logic (CSR → PKI backend → files) is the standalone `svidlet-issue` crate. On Kubernetes 1.35+, it becomes a `PodCertificateRequest` signer, the kubelet takes over key generation and mounting, and the node component is retired.

### Trust boundaries, stated plainly

- Vault asserts: "this certificate was requested by a node in cluster X."
- The plugin asserts: "for this pod, the kubelet told me namespace N and ServiceAccount S." The kubelet is root on the node, so this adds no trust beyond what the node already has. This is the same local-attestation model SPIRE uses.
- Consequence: compromise of one node = ability to mint any identity in that cluster. Cross-cluster impersonation is impossible by Vault policy.

**The AppRole credential is the weakest part of this design.** The secret ID is a shared bearer secret in a Kubernetes Secret: anyone who can read that Secret in the plugin's namespace can mint any identity in the cluster, from anywhere, until it is rotated. It does not prove that the caller is a node, only that the caller has the secret. Nothing else in the design has that property — the kubelet's word about a pod is backed by the kubelet already being root on the node, and Vault's per-cluster role is enforced server-side.

It is kept as the default anyway, because it is the one method that works everywhere, including bare metal, and because it is simple enough to reason about in one sentence: one secret per cluster, rotated on a cadence, blast radius bounded by the Vault role. Where the environment allows it, use something stronger — Vault Kubernetes auth (`SVIDLET_VAULT_AUTH=kubernetes`) proves the plugin's own ServiceAccount to Vault with no shared secret to leak, and cloud IAM does the same with a per-node identity. Both are additive `TokenSource` implementations, not migrations.

## Out of Scope

- A mutating webhook for volume injection.
- JWT SVIDs.
- SPIFFE federation with external trust domains.
- Issuing identities to untrusted tenant containers.
- Certificate revocation; short lifetimes replace it.
- Application-side authorization libraries (which SPIFFE IDs may talk to which).

## Open Questions

1. **Certificate lifetime.** 24 h proposed; 48–72 h reduces Vault load and widens the outage window at the cost of a longer exposure window for a leaked key.
2. **AppRole secret ID rotation** cadence. Rotation without restart is implemented — the secret ID is re-read on every login, and a 403 from Vault triggers exactly one re-login — but the cadence itself is a deployment decision. See the trust discussion above for why this credential is the part to replace first.
3. **Peer verification.** mTLS is only useful if services check the peer's SPIFFE ID, not just the CA. A small client library per language (or guidance for `spiffe` crates and go-spiffe) should accompany the plugin.
4. **Alternative authentication tiers.** Cloud IAM auth (per-node identity on cloud nodes) and Vault JWT auth against an aggregated JWKS endpoint are cleaner than AppRole where available; both can be added as additive login backends.

## Details (Appendix)

### A. Issuance flow

1. Pod scheduled → kubelet calls `NodePublishVolume` with pod namespace, SA, name, UID.
2. Plugin: generate key → CSR with URI SAN `spiffe://<td>/cluster/<c>/ns/<ns>/sa/<sa>` → `POST pki/sign/spiffe-<c>` with `metadata.node=<nodeName>`.
3. Vault: policy check (cluster path) → role check (URI SAN prefix) → sign.
4. Plugin: write `tls.key`, `tls.crt`, `ca.crt` to tmpfs at the target path; record renewal time.
5. Renew at 50–70 % of lifetime with jitter; atomic write; application reloads on inotify.

### B. Scale estimate and load shape

**Steady-state renewal load (20k nodes, planning ceiling)**

| | 20 containers/node (400k certs) | 50 containers/node (1M certs) |
|---|---|---|
| 24 h lifetime | ~4.6/s | ~11.6/s |
| 48 h lifetime | ~2.3/s | ~5.8/s |
| 72 h lifetime | ~1.5/s | ~3.9/s |
| AppRole logins (24 h token period) | ~0.23/s | ~0.23/s |
| Network (~5 KB per issuance, 48 h) | ~1.7 GB/day | ~4.3 GB/day |
| Vault audit log (~7 KB per request, 48 h) | ~1–1.5 GB/day | ~2.5–3.5 GB/day |

Vault signs P-256 certificates at thousands per second per active node; steady-state renewal is not a capacity concern at any of these settings. `no_store=true` is required so issuance does not write to Vault storage; audit-log write rate then becomes the dominant I/O.

**Renewal jitter.** Each certificate renews at a uniformly random point in `[0.5T, 0.7T]` of its lifetime `T`. After an initial fleet-wide rollout (all certificates issued within roughly an hour), the first renewal round spreads that wave over a `0.2T` window (9.6 h at `T = 48h`); each subsequent round widens it by another `0.2T`, so renewals are uniformly distributed across `T` after about five lifetimes. A narrower jitter window converges proportionally slower.

**What jitter does not smooth — the real peak sources**

1. *Pod creation rate.* Every new pod is signed immediately, regardless of lifetime. A rollout of 10k pods in 10 minutes is ~17/s; concurrent rollouts across clusters add. Peak sizing must be derived from pod creation rate, not from `T`.
2. *Plugin restarts.* The plugin recovers existing certificates from the kubelet's CSI volume records and must not re-issue; otherwise a plugin upgrade becomes a fleet-wide simultaneous signing storm. This is a correctness requirement, not a tuning knob.
3. *Vault recovery after an outage.* Renewals that failed during the outage retry together when Vault returns. Retries use exponential backoff with jitter, and a failed renewal never removes the existing certificate.

**Vault-side controls**

- A rate-limit quota on `pki/sign/*` (e.g. 200/s per cluster role) bounds the blast radius of a plugin bug; expected peaks sit well below it.
- Whether performance standbys can serve `pki/sign` with `no_store=true` without forwarding to the active node depends on Vault version and should be measured rather than assumed.
- Audit log sink: file backend with rotation, sized for 3–4 GB/day; not a socket backend that can block the request path.

### C. Alternatives considered

| Option | Why not |
|---|---|
| cert-manager `csi-driver-spiffe` | Three Go processes per node; issuance through API server objects; fixed SPIFFE path forces per-cluster trust domains and federation. It does provide an independent approval layer (approver-policy) that this design lacks. |
| A mutating webhook to inject the volume | An admission-path dependency and a serving certificate to manage, to save six lines of YAML per workload. Explicitly out of scope. |
| SPIRE | Agent alone exceeds small memory budgets; full server/agent stack. |
| `PodCertificateRequest` | Correct long-term answer; needs Kubernetes 1.35+. Planned migration target. |
| Pods call the PKI backend directly | One PKI identity per ServiceAccount; needs an in-pod agent for renewal. |
| Vault Kubernetes/JWT auth for the plugin | No secret to distribute, but requires Vault to hold per-cluster signing keys or reach an aggregated JWKS endpoint. Supported as an optional login backend. |
| Cloud IAM auth for the plugin | Per-node identity on cloud nodes; unavailable on bare metal. Optional login backend. |

### D. Vault policy sketch (per cluster)

```hcl
path "pki/sign/spiffe-cluster-a" { capabilities = ["update"] }
path "pki/ca_chain"               { capabilities = ["read"] }
```

PKI role `spiffe-cluster-a`: `allowed_uri_sans = ["spiffe://<td>/cluster/a/ns/*/sa/*"]`, `allowed_domains = []`, `allow_ip_sans = false`, `no_store = true`, `max_ttl = 72h`, `key_type = ec`, `key_bits = 256`.

### E. Milestones

1. Plugin registers with kubelet, publishes a volume, signs via Vault, manual mount verification. No renewal.
2. Renewal with jitter, restart recovery, CA refresh, Prometheus metrics.
3. Policy bundle distribution over a gRPC stream, e2e tests on kind with a dev Vault, example peer-verification snippets.
4. Optional login backends: cloud IAM. Additional PKI backends behind the `Issuer` trait. `PodCertificateRequest` signer mode.
