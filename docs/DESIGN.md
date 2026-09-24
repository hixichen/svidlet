# Svidlet — Design

A lightweight SPIFFE X.509 issuer for Kubernetes, in Rust.

**Status:** Design draft · **Date:** 2026-09-24 · **License:** Apache-2.0

Where this is going — node attestation, the certificate as a cloud credential, and a central JWT issuer — is [ROADMAP.md](ROADMAP.md). This document describes what svidlet is; the roadmap records which of its phases have landed.

## TL;DR

Every pod that should have an identity gets a short-lived X.509 certificate carrying a SPIFFE (Secure Production Identity Framework for Everyone) ID, so services can authenticate each other with mutual TLS (mTLS) at the application layer instead of trusting network position.

Svidlet is a small Rust DaemonSet that acts as a CSI (Container Storage Interface) node plugin. When a pod starts, the kubelet tells the plugin which namespace and ServiceAccount the pod belongs to; the plugin generates a private key on the node, asks a PKI backend (HashiCorp Vault PKI first; other backends later) to sign a certificate with the identity `spiffe://<trust-domain>/cluster/<cluster>/ns/<namespace>/sa/<serviceaccount>`, and mounts the result into only the containers that should hold it. The plugin authenticates to Vault with its node certificate — issued by node registration, bound to the cluster by its URI SAN — through Vault's cert auth method; AppRole remains for development clusters.

Why this shape: it fits a small DaemonSet memory budget (target: 16 MB resident or under), keeps certificate issuance off the Kubernetes API server, works on Kubernetes 1.31+, respects restricted Pod Security Standards, and scales to tens of thousands of nodes with one PKI role per cluster.

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

- X.509 SVIDs are what the node issues, and the only thing it signs for. JWT-SVIDs, when they come, are signed by a central issuer that takes the pod's X.509 SVID as its input ([ROADMAP.md](ROADMAP.md), Stage 2) — the node never holds a JWT signing key.
- The SVID must be usable as a cloud credential as issued: AWS IAM Roles Anywhere and GCP Workload Identity Federation trust the CA directly ([ROADMAP.md](ROADMAP.md), Stage 1).
- Certificates held per container: a platform-owned sidecar can hold an identity that the tenant container in the same pod cannot read.
- The identity a pod receives must not be chosen by the pod itself (no label/annotation-derived identity).
- The SPIFFE ID layout must be an operator's decision, not a constant in the code: not every deployment wants the cluster in the path, and some want the node or pod in it.
- The PKI backend and the way a node authenticates to it must be separable, so a second vendor does not mean a second plugin.
- Vault must not need to call back into cluster API servers, and must not require per-cluster key material: one PKI role and one auth role per cluster, with each node's credential coming from node registration.
- Single trust domain across clusters; no bundle federation.
- Kubernetes 1.31+, restricted PSS for tenant pods.

## Design

### Components

**1. `svidlet` — CSI node plugin (Rust, DaemonSet, one process per node)**

- Implements the kubelet plugin-registration protocol itself (no `node-driver-registrar` sidecar).
- On `NodePublishVolume`: reads the pod's namespace, ServiceAccount, name and UID from the volume context supplied by the kubelet; generates a P-256 private key in memory; builds a certificate signing request (CSR); hands the CSR to the PKI backend (Vault: `pki/sign/spiffe-<cluster>`) with the URI SAN above and a Subject `CN=<pod name>` (`SVIDLET_CERT_SUBJECT`); writes `tls.crt`, `tls.key`, `ca.crt` to a tmpfs mount.
- Renews at a random point between 50 % and 70 % of the certificate lifetime, writing files atomically so applications can reload on file change.
- On restart, rebuilds its renewal list from the kubelet's CSI volume records under `/var/lib/kubelet/pods`; never re-issues on restart.
- Refreshes `ca.crt` from Vault's CA chain periodically.
- Target footprint: 16 MB resident memory or under, one static binary (musl), no Kubernetes API server access, no Tokio-heavy dependency tree.

**2. PKI backend — Vault PKI (one-time configuration per cluster)**

The backend is behind an `Issuer` trait in the `svidlet-issue` crate; Vault PKI is the first implementation. Other backends (step-ca, cert-manager `CertificateRequest`, cloud-managed CAs) can be added without touching the CSI plugin.


- One PKI mount and one intermediate CA shared by all clusters (single trust domain, one `ca.crt` everywhere).
- One PKI role per cluster whose `allowed_uri_sans` is pinned to `spiffe://<td>/cluster/<cluster>/ns/*/sa/*`, with `no_store=true` and no DNS/IP SANs permitted. `cn_validations=disabled` accepts the pod-name CN without treating it as a host name; svidlet sends `exclude_cn_from_sans=true`, and since the role allows no DNS names a request without it is refused.
- One cert auth role per cluster, trusting the node registration CA, with `allowed_uri_sans` pinned to `spiffe://<td>/cluster/<cluster>/node/*` and a policy granting only `update` on that cluster's `pki/sign/…` path and `read` on the CA chain. Each node logs in with its own certificate, so there is no shared secret; tokens last an hour and are re-obtained, which re-reads a rotated node certificate.
- AppRole remains for development and kind clusters, where there is no registration CA: one per cluster, with the same policy, its secret ID in a Kubernetes Secret.
- The plugin logs in once per token lifetime; it does not log in per certificate.

**3. `svidlet-policy` — policy distribution (optional, separate process)**

A certificate says who a workload *is*. It says nothing about who it may talk to, and that half has to come from somewhere. When policy distribution is configured, a second process on the node — no Vault credential, no root, no capabilities — fetches authorization policy and publishes it into each workload's volume beside its certificate: either streamed per identity from a backend over one gRPC stream per node (the server side is designed in [POLICY_STORE_BACKEND.md](../svidlet-policy/POLICY_STORE_BACKEND.md)), or pulled as a signed, content-addressed OCI bundle with a staged ring rollout. The two sources are mutually exclusive on one node. Certificate issuance does not depend on the policy backend — an outage leaves the policy already on disk in place — unless the operator sets `SVIDLET_POLICY_REQUIRED`, which trades that for refusing to start a pod that would run unpoliced.

`SVIDLET_POLICY_ENABLED=false` disables the whole subsystem independently of whether an endpoint is configured, so a deployment can be run without a policy backend without editing its manifest. It is deliberately a separate switch rather than "unset the endpoint": during local development and when narrowing down a production problem, the useful operation is turning the feature off while leaving the configuration alone.

The whole of that policy is designed across two documents: [../svidlet-policy/authz-management-plane.md](../svidlet-policy/authz-management-plane.md) — why distribution is a second process rather than a thread, how the two share one volume without IPC, the signed ring rollout, and how a production policy change ships safely — and [../svidlet-policy/authz-enforcement-plane.md](../svidlet-policy/authz-enforcement-plane.md) — what the bytes conventionally contain, and the in-process SDK that evaluates them. Enforcement never enters svidlet itself.

**No mutating webhook.** Workloads declare the `csi` ephemeral volume themselves and mount it only into the containers that should hold the identity. A webhook would add an admission-path dependency and a certificate to manage for the sake of saving six lines of YAML.

### Seams

Three things are behind traits, because they are the three that change for different reasons:

| Seam | Trait | Ships with | Later |
|---|---|---|---|
| PKI engine | `Issuer` | Vault PKI | step-ca, cert-manager `CertificateRequest`, cloud CAs, `PodCertificateRequest` |
| Node authentication | `TokenSource` | Vault cert auth (node certificate), Vault Kubernetes auth, Vault AppRole (dev), static token | TPM-backed signer for the node key; cloud IAM |
| Policy source | `svidlet-policy` | gRPC stream, signed OCI bundles (mutually exclusive per node) | — |
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
5. **One PKI role per cluster.** One role and one auth role per cluster, regardless of how many ServiceAccounts exist; adding a workload never touches the PKI backend.
6. **Fail-safe under Vault outages.** With a 6 h lifetime and renewal starting at 3 h, running pods keep working through a three-hour Vault outage; only new pod start-ups are delayed.
7. **The certificate is the cloud credential.** With a Subject CN and exactly one SPIFFE URI SAN, the SVID in the volume is accepted by AWS IAM Roles Anywhere and GCP's X.509 workload identity federation as issued — no static cloud keys, no token exchange service on the hot path. `SVIDLET_CLOUD_PROFILE` checks every issuance against both clouds' rules.
8. **Clear upgrade path.** The issuance logic (CSR → PKI backend → files) is the standalone `svidlet-issue` crate. On Kubernetes 1.35+, it becomes a `PodCertificateRequest` signer, the kubelet takes over key generation and mounting, and the node component is retired.

### Trust boundaries, stated plainly

- Node registration asserts: "this node is inventory machine N in cluster X" — by TPM credential activation against the EK allowlist ([ROADMAP.md](ROADMAP.md), §3).
- Vault asserts: "this certificate was requested by a node in cluster X" — because the node certificate it authenticated says so.
- The plugin asserts: "for this pod, the kubelet told me namespace N and ServiceAccount S." The kubelet is root on the node, so this adds no trust beyond what the node already has. This is the same local-attestation model SPIRE uses.
- Consequence: compromise of one node = ability to mint any identity in that cluster. Cross-cluster impersonation is impossible by Vault policy.

**The node credential is now a certificate, not a shared secret.** Until this change the default was AppRole, whose secret ID sat in a Kubernetes Secret: anyone who could read it could mint any identity in the cluster, from anywhere, until it was rotated — it proved possession of a secret, not that the caller was a node. Vault's cert auth method with a per-node registration certificate removes that: each node proves itself with its own certificate, the cluster is bound by the certificate's URI SAN at Vault, and there is nothing to copy out of the cluster that works for every node.

What remains is the key. Today svidlet reads the node key from a file (`SVIDLET_NODE_KEY_FILE`), so a root compromise of a node can copy it — worth at most that node's cluster, for at most the certificate's one-day lifetime. A TPM-backed signer in place of the file closes that, making the credential non-exportable: a compromised node can be *used*, but not cloned. Where there is no TPM and no registration service, Vault Kubernetes auth (`SVIDLET_VAULT_AUTH=kubernetes`) proves the plugin's own ServiceAccount instead. AppRole stays for development and kind clusters only. All four are `TokenSource` implementations; switching between them is configuration, not a migration.

### Admission control: the missing half of the chain

Svidlet's assertion is narrow and worth restating exactly: *the kubelet told me this pod runs as ServiceAccount S in namespace N*. A pod cannot forge that. But it says nothing about whether that pod **should exist**. Anyone who can create a pod in namespace N with ServiceAccount S gets S's identity, and svidlet will hand it over without hesitation, because from its position that request is indistinguishable from a legitimate one.

So the real boundary is not in svidlet at all. It is Kubernetes RBAC on pod creation, plus whatever admission control the cluster runs. Svidlet issues identity to *whatever was admitted*; it does not decide what should be admitted.

**A validating admission controller that verifies workload provenance is the missing half, and it is essential.** Verifying that a pod's images are signed by a trusted builder, and that its spec matches a reviewed manifest, is what turns the identity from "something is running in namespace N as S" into "the workload CI built and review approved is running as S". Without it, the strength of every certificate svidlet issues is bounded by who can call `kubectl run` — which is usually a much larger set of people than anyone intends.

It is deliberately **future work rather than part of this design**, for three reasons:

1. **It is on the critical path for every pod create in the cluster**, not just pods that want an identity. A webhook that fails wrong stops all deployments, cluster-wide. Svidlet's entire shape is about staying out of critical paths — issuance is one HTTPS call, restart adopts rather than re-issues, a backend outage fails stale. Adding a component whose failure mode is "nothing can be deployed" is a different kind of thing, and it deserves to be designed as one rather than bolted on.
2. **It is already well served.** Sigstore's policy-controller, Kyverno and Gatekeeper all do image signature verification and pod spec policy properly, with the operational maturity that takes. Svidlet should compose with one of them, not reimplement it badly.
3. **It changes the deployment story.** Today it is a DaemonSet, a ConfigMap and a Secret. A webhook adds a serving certificate to issue and rotate, a failure policy to get right, and a new way for the cluster to break — exactly the maintenance cost this project exists to avoid.

Note the distinction from the mutating webhook in *Out of Scope*: that one injects a volume into pod specs, and is genuinely unnecessary because workloads can declare the volume themselves. This one verifies that a workload is what it claims to be, and is not unnecessary at all — only out of scope for now, and worth stating plainly rather than leaving as an implied gap.

Until it exists, the honest statement of what a SPIFFE ID from svidlet means is: *this workload was admitted to namespace N with ServiceAccount S by a cluster whose RBAC and admission rules you must evaluate separately*.

### After admission: balancing security and usability

Once a pod is admitted and running, every remaining decision is a trade between a tighter security posture and a system people can actually operate. The design resolves them with one principle:

> **Fail stale — not open, and not closed.**

Anything already issued keeps working; anything new is delayed. An outage degrades new deployments and never breaks running traffic. Failing open would hand out identities that should not exist; failing closed would take down healthy nodes because a backend was briefly unreachable. Staleness is the only failure mode that is visible, bounded, and harmless in the short term — and it is measurable, which is why `svidlet_earliest_certificate_expiry_seconds` and `svidlet_bundle_age_seconds` are the two gauges to alert on.

Applied to each knob:

| Decision | Secure end | Usable end | Default, and why |
|---|---|---|---|
| Certificate lifetime | hours: a leaked key expires fast | days: less issuance load, wider outage window | **6 h.** Renewal starts at 3 h, so a three-hour Vault outage is invisible to running pods — and a cloud credential minted from a leaked key is worth hours, not days. |
| Certificate a cloud would refuse | refuse to issue it | issue it silently | **Issue it, and count it.** It is still a valid SVID for mTLS; `svidlet_cloud_profile_findings_total` says which cloud rule it breaks. |
| Vault unreachable | refuse to serve | keep serving | **Keep serving.** The certificate on disk is still valid and still trustworthy; refusing would convert a Vault incident into a fleet incident. |
| Renewal failure | drop the certificate | keep it, retry with backoff | **Keep it.** Renewal begins at half the lifetime, so there is a lot of runway before anything is at risk. |
| Policy backend unreachable | block pod start | start without policy | **Start.** `SVIDLET_POLICY_REQUIRED=true` inverts this for operators who would rather a pod not start than start unpoliced — the choice is theirs, but the default keeps a second network dependency out of pod start-up. |
| Bad policy bundle | apply it and hope | refuse it, keep the last good one | **Refuse.** A bundle that fails signature, digest or validation never reaches a pod, and the node keeps what it has. |
| SPIFFE ID shape | pin an exact pattern | allow whatever the template builds | **No pattern by default.** `SVIDLET_SPIFFE_ID_PATTERN` is there for operators who want a second, independent gate; requiring one out of the box would be a cliff for a first deployment. |
| `tls.key` permissions | root-only | world-readable | **0640 plus `SVIDLET_KEY_GID`.** Readable by the workload's group and nobody else. The group is set by svidlet directly rather than relying on the kubelet's `fsGroup` handling, which depends on driver capabilities svidlet does not advertise and has not been verified on a real cluster. |
| Liveness probe | tied to the PKI backend | process-only | **Process-only.** Tying liveness to Vault would restart every node in the fleet during a Vault outage, at the exact moment restarts are least helpful. |

Each of these can be moved. What should not move is the principle: the failure of a dependency should cost you *new* work, never *running* work.

## Out of Scope

- A mutating webhook for volume injection. (A *validating* admission controller for workload provenance is a different thing, and is future work rather than out of scope — see above.)
- JWT SVIDs signed on the node. They are planned as a central issuer that consumes the pod's X.509 SVID ([ROADMAP.md](ROADMAP.md), Stage 2); the node never holds a JWT signing key.
- SPIFFE federation with external trust domains.
- Issuing identities to untrusted tenant containers.
- Certificate revocation; short lifetimes replace it.
- A policy *language* of svidlet's own, and any component in the request path (proxies, sidecars, authorization servers). Application-side *enforcement* is in scope — as a thin per-language SDK embedding CEL, designed in [../svidlet-policy/authz-enforcement-plane.md](../svidlet-policy/authz-enforcement-plane.md); the plugin and daemon stay byte couriers either way.

## Open Questions

1. **Certificate lifetime.** Settled at 6 h: the certificate is now also a cloud credential, which shortens the exposure a leaked key buys, and node authentication no longer needs a long Vault-outage runway to hide a fragile credential. Load at this lifetime is in Appendix B.
3. **AppRole secret ID rotation** is a development-cluster concern now that production nodes use cert auth. Rotation without restart still works — the secret ID is re-read on every login, and a 403 from Vault triggers exactly one re-login.
4. **Peer verification and authorization.** mTLS is only useful if services check the peer's SPIFFE ID, not just the CA. Direction now settled: a thin per-language SDK (Go first) wraps go-spiffe / the `spiffe` crate for peer verification and embeds CEL to evaluate the mounted policy bundle — see [../svidlet-policy/authz-enforcement-plane.md](../svidlet-policy/authz-enforcement-plane.md). What remains open there: environment versioning and the cross-language conformance mechanism.
5. **Alternative authentication tiers.** Settled as the tiers in [ROADMAP.md](ROADMAP.md) §3.3: a TPM-registered node certificate (Tier A/B, `cert`), Kubernetes auth where there is no TPM (Tier C), AppRole for development only. The TPM-backed signer for the node key is the outstanding piece.

Rollout-manifest freshness was an open question here and is now resolved: the signed manifest carries a monotonic `sequence` and a `valid_until`, checked on the node against a persisted high-water mark — see [../svidlet-policy/authz-management-plane.md](../svidlet-policy/authz-management-plane.md), *Freshness*.

## Details (Appendix)

### A. Issuance flow

1. Pod scheduled → kubelet calls `NodePublishVolume` with pod namespace, SA, name, UID.
2. Plugin: generate key → CSR with URI SAN `spiffe://<td>/cluster/<c>/ns/<ns>/sa/<sa>` and Subject `CN=<pod name>` → `POST pki/sign/spiffe-<c>` with `exclude_cn_from_sans=true`.
3. Vault: policy check (cluster path) → role check (URI SAN prefix; no DNS names) → sign. With cert auth the token's metadata names the node — the node certificate's CN and serial — in every audit entry. With AppRole the node name travels only as an `X-Svidlet-Node` request header, which reaches the audit log only if the operator lists it in `audit_non_hmac_request_headers`.
4. Plugin: write `tls.key`, `tls.crt`, `ca.crt` to tmpfs at the target path; record renewal time.
5. Renew at 50–70 % of lifetime with jitter; atomic write; application reloads on inotify.

### B. Scale estimate and load shape

**Steady-state renewal load (20k nodes, planning ceiling)**

| | 20 containers/node (400k certs) | 50 containers/node (1M certs) |
|---|---|---|
| **6 h lifetime (default)** | ~18.5/s | ~46/s |
| 24 h lifetime | ~4.6/s | ~11.6/s |
| 48 h lifetime | ~2.3/s | ~5.8/s |
| 72 h lifetime | ~1.5/s | ~3.9/s |
| Cert auth logins (1 h tokens, re-login at 40 min) | ~8.3/s | ~8.3/s |
| AppRole logins (24 h token period) | ~0.23/s | ~0.23/s |
| Network (~5 KB per issuance, 48 h) | ~1.7 GB/day | ~4.3 GB/day |
| Vault audit log (~7 KB per request, 48 h) | ~1–1.5 GB/day | ~2.5–3.5 GB/day |

Vault signs P-256 certificates at thousands per second per active node; steady-state renewal is not a capacity concern at any of these settings. At the roadmap's scope — 2.4M pods across ~100 clusters — the 6 h default is ~110/s fleet-wide, about 1/s per cluster, and cert auth adds one mTLS login per node every 40 minutes — ~50/s across 120k nodes. `no_store=true` is required so issuance does not write to Vault storage; audit-log write rate then becomes the dominant I/O.

**Renewal jitter.** Each certificate renews at a uniformly random point in `[0.5T, 0.7T]` of its lifetime `T`. After an initial fleet-wide rollout (all certificates issued within roughly an hour), the first renewal round spreads that wave over a `0.2T` window (9.6 h at `T = 48h`); each subsequent round widens it by another `0.2T`, so renewals are uniformly distributed across `T` after about five lifetimes. A narrower jitter window converges proportionally slower.

**What jitter does not smooth — the real peak sources**

1. *Pod creation rate.* Every new pod is signed immediately, regardless of lifetime. A rollout of 10k pods in 10 minutes is ~17/s; concurrent rollouts across clusters add. Peak sizing must be derived from pod creation rate, not from `T`.
2. *Plugin restarts.* The plugin recovers existing certificates from the kubelet's CSI volume records and must not re-issue; otherwise a plugin upgrade becomes a fleet-wide simultaneous signing storm. This is a correctness requirement, not a tuning knob.
3. *Vault recovery after an outage.* Renewals that failed during the outage retry together when Vault returns. Retries use exponential backoff with jitter, and a failed renewal never removes the existing certificate.

**Vault-side controls**

- A rate-limit quota on `pki/sign/*` (e.g. 200/s per cluster role, `RATE_LIMIT` in `vault-bootstrap.sh`) bounds the blast radius of a plugin bug. Steady state sits far below it, but a single node can exceed it — `hack/bench-memory.sh` measures 150–350 publishes/s on Linux — so size it from the cluster's pod-rollout peak. A publish refused by the quota is a retryable `backend_status` 429; the kubelet retries.
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

PKI role `spiffe-cluster-a`: `allowed_uri_sans = ["spiffe://<td>/cluster/a/ns/*/sa/*"]`, `allowed_domains = []`, `allow_any_name = false`, `allow_ip_sans = false`, `require_cn = false`, `cn_validations = ["disabled"]`, `use_csr_common_name = false`, `use_csr_sans = false`, `no_store = true`, `ttl = 6h`, `max_ttl = 24h`, `key_type = ec`, `key_bits = 256`.

Cert auth role `svidlet-cluster-a`: `certificate` = the node registration CA, `allowed_uri_sans = ["spiffe://<td>/cluster/a/node/*"]`, `token_policies = ["svidlet-cluster-a"]`, `token_ttl = token_max_ttl = 1h`. Node certificates carry `CN=<node name>`: Vault's cert method names the entity alias after it and refuses a login without one.

`deploy/vault-bootstrap.sh` writes all of this (`AUTH=cert NODE_CA_FILE=…`); `hack/local-vault.sh` stands a second PKI mount in for the registration CA.

### E. Milestones

The original milestones 1–4 are done; what follows them is [ROADMAP.md](ROADMAP.md) §8, with its progress table at the top. In brief:

1. ✅ Plugin registers with kubelet, publishes a volume, signs via Vault.
2. ✅ Renewal with jitter, restart recovery, CA refresh, Prometheus metrics.
3. ✅ Policy distribution (gRPC stream and signed OCI bundles), e2e tests on kind with a dev Vault.
4. `svidlet-sdk-go` — see [../svidlet-policy/authz-enforcement-plane.md](../svidlet-policy/authz-enforcement-plane.md).
5. Roadmap Phase 0 (certificate profile for cloud federation) ✅, Phase 1 (node attestation; cert auth ✅, TPM-backed signer outstanding), Phase 2 (Stage 1 cloud federation), Phase 3 (Stage 2 token issuer), Phase 4 (hardening, `PodCertificateRequest` signer mode).
6. Composition with a validating admission controller, so an identity means "the workload CI built" and not merely "a pod in namespace N". Most likely integration with Sigstore policy-controller or Kyverno rather than a webhook of svidlet's own — see *Admission control: the missing half of the chain*.
