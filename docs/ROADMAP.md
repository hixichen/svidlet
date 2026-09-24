# Svidlet: Design and Roadmap

**Workload identity for rented GPU fleets — node attestation, X.509 pod identity, and cloud federation without a per-cluster control plane.**

Status: Phase 0 and svidlet's side of Phases 1 and 3 landed; not yet deployed · Scope: \~100 clusters, \~120k nodes, 1–2.4M pods · Owner: platform identity

**Depends on:** [DESIGN.md](DESIGN.md) (what svidlet is today) · [DEPLOY.md](DEPLOY.md) (deploying it, alone or with node bootstrap) · [USAGE.md](USAGE.md) (what a workload does with the certificate) · [config.md](config.md)

Node attestation — §3 — is built in its own repository,
[svidlet-node-bootstrap](https://github.com/hixichen/svidlet-node-bootstrap). This repository
covers svidlet, and the interface between the two.

---

## Progress

What is in this repository now, against the phases in §8. Items that live outside svidlet (the placement auditor, EK inventory, step-ca, cloud-side configuration) are tracked here so the whole plan reads in one place, but are not code in this repo.

| Phase | Item | State |
| --- | --- | --- |
| 0 | Certificate profile: Subject `CN=<pod-name>`, exactly one URI SAN, 6h default TTL | **Done.** `SVIDLET_CERT_SUBJECT` (`pod_name` \| `service_account` \| `none`), default 6h, CN capped at 64 bytes in the `sourceIdentity` alphabet, read back from the certificate on restart so a renewal keeps it. |
| 0 | Unit tests for Roles Anywhere / GCP X.509 acceptance rules | **Done.** `svidlet_issue::profile` checks Subject, CN, single SPIFFE URI SAN, CA flag, key usage, `clientAuth`, signature and key algorithms, chain order, chain length, leaf lifetime and the 127-byte `google.subject`. `SVIDLET_CLOUD_PROFILE=aws,gcp` runs it on every issuance and counts refusals in `svidlet_cloud_profile_findings_total{cloud,rule}`; it never blocks issuance. A live-Vault test proves what the documented role signs passes both clouds. |
| 0 | Vault role accepts a CN without it becoming a host name | **Done**, and verified against Vault 1.20: `cn_validations=disabled` with `allowed_domains=""`, `allow_any_name=false`. A request that omits `exclude_cn_from_sans` is refused, so no certificate from the role can be valid for a DNS name. |
| 0 | Root CA offline/HSM with online intermediate; anchor-at-root rule | Documented (§4.2, [USAGE.md](USAGE.md)); `deploy/vault-bootstrap.sh` still generates a demo root and says so. |
| 0 | AWS `CreateSession` quota increase; per-account sharding plan | Not started (cloud-side). |
| 0 | Placement auditor v0 | Not started (separate component). |
| 1 | svidlet: cert-auth to Vault with the node certificate | **Done** for a file-held key: `SVIDLET_VAULT_AUTH=cert`. The cert and key are re-read on every login; tokens are short and re-obtained rather than renewed. Verified live: a node certificate for another cluster, from the same registration CA, is refused. |
| 1 | TPM-resident node key (Tier A) | Not started in svidlet. The key file path is the seam a TPM-backed signer replaces. |
| 1 | AppRole removed from `deploy/` | **Done.** `deploy/` is now variants over one base: `standalone` (Vault Kubernetes auth), `with-node-bootstrap` (cert auth) and `dev` (AppRole, kind only). Only `dev` mounts or ships an AppRole Secret. |
| 1 | Hand-off from svidlet-node-bootstrap | **Done on svidlet's side** ([DEPLOY.md](DEPLOY.md)): the `node-bootstrap` kustomize component runs the bootstrap init container and renew sidecar in svidlet's pod over a memory-backed `/node`; svidlet reads `/node/node.crt` and `node.key` by default, checks at start-up that the certificate names this node and cluster and carries a CN, and exports `svidlet_node_certificate_expiry_seconds`. |
| 1 | EK inventory, step-ca, enrolment and renewal containers, soak | In [svidlet-node-bootstrap](https://github.com/hixichen/svidlet-node-bootstrap). `hack/local-vault.sh` and the kind e2e stand a Vault PKI mount in for step-ca, so cert auth is testable without a TPM. |
| 2 | Cloud federation rollout | Not started (cloud-side). |
| 3 | Token issuer service | In [svidlet-token-issuer](https://github.com/hixichen/svidlet-token-issuer). This repository fixes the interface — `crates/svidlet-token` and [DEPLOY.md](DEPLOY.md#token-issuer-the-interface): gRPC `Mint` over mutual TLS with the node certificate, a proof of possession of the pod key, status codes and what each means to svidlet — and what the issuer must check: pod chain to the Vault CA, same cluster as the node, the proof, a per-identity grant, `exp` ≤ the pod certificate's `notAfter`. §5 records where this departs from the original design. |
| 3 | svidlet: `audiences` attribute, `jwt/<name>` publication, refresh | **Built** (`SVIDLET_TOKEN_ISSUER`), tested against a stand-in issuer that enforces the interface. Minted after the certificate at publish and re-minted with every renewal, all-or-nothing, in the same `..data` swap; restart recovers audiences from the published tokens. A refused audience fails the mount with `PermissionDenied`; an unreachable issuer with `Unavailable`, so the kubelet retries. Metrics `svidlet_tokens_minted_total`, `svidlet_token_failures_total{code}`, `svidlet_earliest_token_expiry_seconds`. |
| 3 | `iss` registered with a relying party; rotation rehearsed | Not started. |
| 4 | Hardening | Not started. |
| — | CI | **Added**: fmt, clippy `-D warnings`, the test suite (privileged container), MSRV build, `deploy/` validated with kubeconform, and the live-Vault tests. |

### What implementing Phase 0–1 and 3 taught us

- **Node certificates need a Subject CN.** Vault's cert auth method names the entity alias after the client certificate's CN and refuses a login without one (`missing name in alias`). Registration must issue `CN=<node-name>` alongside the URI SAN; step-ca does by default.
- **The per-cluster rate-limit quota is reachable.** On Linux, one svidlet publishes 150–350 certificates/s against a local Vault — past the 200/s `pki/sign` quota `vault-bootstrap.sh` sets (now `RATE_LIMIT`). That is the quota doing its job, and it means a large simultaneous pod rollout in one cluster can meet it: pod start retries, it does not fail, but size the quota from the rollout rate, not from steady state (DESIGN.md, Appendix B).
- **The audit log hashes the identity by default.** Vault HMACs every request value in audit entries, so the placement auditor could not read which SPIFFE ID was issued. `vault-bootstrap.sh` now tunes the PKI mount with `audit_non_hmac_request_keys=uri_sans,common_name`.
- **The test suite needs root.** Volumes are bind-mounted and chowned exactly as on a node, so the tests need `CAP_SYS_ADMIN` and `CAP_CHOWN`; CI runs them in a privileged container.
- **Linux footprint, first real measurement** (tmpfs volumes, as root): svidlet 5.4 MB idle, 7.7 MB with 2000 certificates; both processes 9.3–11.7 MB. Inside the 16 MB budget.

---

## 1. Goal and principles

Every pod that needs an identity gets a short-lived X.509 SVID carrying a SPIFFE ID of the form `spiffe://<td>/cluster/<c>/ns/<ns>/sa/<sa>`, usable for mTLS between services and for obtaining cloud credentials — on hosts we rent from vendors and do not fully control, without running an identity control plane in every cluster.

The design holds to five principles, each of which resolves at least one hard decision below.

1. **Nodes never hold a signing key.** A node holds a credential that lets it *request* signatures, scoped to its own cluster by policy at the signer. This is true today for X.509 (Vault PKI roles) and is preserved for JWT.
2. **The cluster prefix is the blast-radius boundary.** Every compromise scenario reduces to "one cluster, until you notice," and every cloud-side binding is written against a cluster-scoped SPIFFE path, never `cluster/*`.
3. **Attest hardware identity, not runtime integrity.** TPM proves *which inventory machine* is asking and makes the node credential non-exportable. PCR/measured-boot attestation is out of scope for rented hosts.
4. **Prefer the relying party's native trust over an intermediary.** AWS and GCP trust private CAs directly; use that, and issue JWTs only for relying parties that cannot consume X.509.
5. **Fail stale.** Outages of Vault, the token issuer, or a cloud STS cost new work, never running work.

Explicitly not goals: replacing SPIRE, certificate revocation (short lifetimes replace it), federating with external trust domains, evaluating policy in svidlet (it delivers bytes), and threshold/split-key cryptography (see §7).

## 2. Trust model

```
Inventory allowlist  { sha256(EKpub) → (node, cluster) }        ← bottom of trust
        │  credential activation (MakeCredential / ActivateCredential)
        ▼
Node cert   spiffe://td/cluster/C/node/N   (TPM-resident key, 24h)
        │  Vault cert-auth; policy binds cluster/C
        ▼
Vault PKI   root offline/HSM → intermediate in Vault → per-cluster role
        │  allowed_uri_sans pinned to cluster/C prefix
        ▼
Pod SVID    spiffe://td/cluster/C/ns/N/sa/S   (P-256 key in tmpfs, 6–12h)
        ├──► AWS IAM Roles Anywhere      (trust anchor = our root CA)
        ├──► GCP Workload Identity Fed.  (X.509 provider, mTLS STS)
        └──► Token issuer (mTLS) ──► JWT-SVID for OIDC-only relying parties
```

**Roots of trust, in order of consequence if compromised:**

| Root | Held where | Compromise means |
| --- | --- | --- |
| Vault root CA | Offline / HSM; only the intermediate is online | Every identity in every cluster; every cloud trust anchor. Rotating it touches AWS and GCP config. |
| EK inventory allowlist | Provisioning database, change-controlled | Attacker's own TPM becomes a fleet node in the cluster you assign it to. |
| Vault (running) | Central, HA | Any identity in any cluster until re-keyed. |
| Token issuer key pool | Issuer replicas' memory, KMS-wrapped at rest | Any JWT `sub` for any audience until rotation (minutes, rehearsed). |
| Node cert | TPM on one node | Any identity **in that cluster**, from that node only. |

The kubelet is trusted for `(namespace, serviceaccount)` as it is today; it is already root on the node, so this adds no trust. Admission control — deciding *which* pods deserve a given ServiceAccount — remains the missing half of the chain and is unchanged by anything here.

## 3. Node attestation and registration

### 3.1 What TPM buys on a rented host

Not integrity: the vendor's technician has physical access and PCR attestation is a burden that proves little here. It buys two cheap, decisive properties:

- **Non-exportability.** The node credential lives in the chip. A compromised node can be *used*, but the credential cannot be copied to a laptop and used from anywhere. This closes the AppRole weakness in the current design ("proves possession of a secret, not that the caller is a node").
- **Binding to inventory.** The EK is a fixed, vendor-certified identity for that chip. The allowlist of EK public-key hashes is the actual security boundary; treat "add EK hash to inventory" with the ceremony of "mint a Vault root token."

### 3.2 Registration flow

```
provisioning (once, out of band)
  read EK pub  →  record sha256(EKpub) → {node, cluster, vendor, rack}

first boot / re-register (go-attestation, or step-ca ACME device-attest-01 tpm)
  node:    create AK under EK; send {EK cert, AK pub, AK attestation}
  server:  verify EK cert chain → TPM vendor root, or hypervisor CA for vTPM
           sha256(EKpub) ∈ inventory → (node, cluster)
           MakeCredential(EKpub, AKname, nonce) → challenge
  node:    ActivateCredential in TPM → nonce
  server:  issue node cert, URI SAN spiffe://td/cluster/C/node/N, CN=N,
           key TPM-resident (certified by AK), TTL 24h, auto-renew

steady state
  svidlet authenticates to Vault with cert-auth using the node cert;
  Vault policy binds cluster/C from the SAN. AppRole is retired.
```

Registration is performed by **step-ca** (ACME `device-attest-01`, `tpm` format, verifying EK chain + inventory allowlist) or a small service on `google/go-attestation`; Vault cert-auth trusts its CA. Svidlet itself does not implement TPM logic — it consumes the node cert.

The node certificate must carry `CN=<node-name>` as well as its URI SAN: Vault's cert auth method names the entity alias after the CN and refuses a login without one.

On the Vault side this is one cert role per cluster (`deploy/vault-bootstrap.sh`, `AUTH=cert NODE_CA_FILE=…`): `certificate` = the registration CA, `allowed_uri_sans = spiffe://<td>/cluster/<c>/node/*`, `token_policies` = that cluster's signing policy, `token_ttl = token_max_ttl = 1h`. Svidlet logs in again rather than renewing, which re-reads a rotated node certificate and means a node removed from the inventory loses Vault within the hour even if the CRL step is late.

### 3.3 Tiers and fallbacks

| Tier | Node credential | When |
| --- | --- | --- |
| A | TPM-bound node cert via EK registration | Bare metal with TPM 2.0; VMs with vTPM chaining to a hypervisor CA |
| B | TPM present but no EK cert | Trust the EK hash alone against inventory (allowlist is the boundary anyway) |
| C | No TPM. With node bootstrap: a node certificate from step-ca's per-cluster ServiceAccount-token provisioner, software key. Without: Vault Kubernetes auth (`deploy/standalone`) | Lower assurance: the key, or the token, is usable by whoever is root on the node |
| — | AppRole | Dev/kind only (`deploy/dev`) |

Which Tier C a cluster gets is the deployment's choice, not svidlet's: `deploy/with-node-bootstrap` gives every tier the same certificate shape and the same Vault auth method, while `deploy/standalone` needs no step-ca at all. svidlet supports both. Tiers A, B and bootstrapped C all reach svidlet as `SVIDLET_VAULT_AUTH=cert` with the node certificate in `/node`. Today the key is read from a PEM file; Tier A replaces that file with a TPM-backed signer, which is the one remaining piece of Phase 1 inside svidlet.

### 3.4 Revocation

Kick a node = delete its EK hash from inventory + deny its SAN at the token issuer + Vault cert-auth revocation. Because node certs are 24h, Vault self-heals even if the CRL step is missed. Already-issued pod SVIDs remain valid to `exp`.

## 4. Pod identity — Stage 1: X.509 directly to AWS and GCP

### 4.1 Rationale

Both AWS and GCP trust a private CA natively and condition access on the certificate's URI SAN. Therefore the pod SVID svidlet already writes into `/var/run/svid/` **is** the cloud credential. No JWT, no signing key outside Vault's CA, no JWKS, no central issuer on the hot path.

### 4.2 AWS — IAM Roles Anywhere

- One **trust anchor per AWS account** = our root CA bundle (≤25 KB; intermediates travel in the client chain so intermediate rotation never touches AWS).
- Pod SDK signs `CreateSession` (`AWS4-X509-*` scheme) with `tls.key`; receives STS credentials.
- SPIFFE ID surfaces as the session tag `aws:PrincipalTag/x509SAN/URI`. Role trust policies condition on it, always cluster-scoped: `StringLike: "spiffe://td/cluster/prod-*/ns/inference/sa/*"` — never `cluster/*`.
- **Certificate requirement:** the SVID must carry a non-empty Subject; `sourceIdentity` is taken from the Subject CN. Svidlet sets `CN=<pod-name>` (a useful CloudTrail breadcrumb). Only the *first* URI SAN is mapped; svidlet issues exactly one.
- **Quotas to file for on day one:** `CreateSession` defaults to 20 TPS/region (adjustable); 50 trust anchors/account; 2 CRLs/anchor (we don't use CRLs). Throttling is per certificate + IP, so distinct pods don't collide.

### 4.3 GCP — Workload Identity Federation, X.509 provider

- One **workload identity pool + X.509 provider per environment**; trust store = root anchor (limit 3) plus up to 10 intermediates; chain depth ≤5; P-256 accepted.
- Pod SDK does mTLS token exchange at `sts.mtls.googleapis.com` with `subject_token_type: urn:ietf:params:oauth:token-type:mtls`, passing leaf + intermediates as the subject token.
- Attribute mapping uses `assertion.san.uri`. **`google.subject` is capped at 127 bytes**, so map `google.subject = assertion.san.uri.extract('spiffe://td/cluster/{id}')` (yields `C/ns/N/sa/S`) and keep the full URI as `attribute.spiffe_id`. Attribute conditions restrict by cluster prefix.
- Leaf lifetime must be ≤390 days — irrelevant at 6–12h.
- Google client libraries (`google-auth` ≥2.39, `cloud.google.com/go/auth` ≥0.16) support X.509 WIF natively via a certificate config file; the SDK can mostly delegate.

### 4.4 Certificate profile changes in svidlet

| Field | Before | Stage 1 (implemented) |
| --- | --- | --- |
| Subject | empty | `CN=<pod-name>` (or SA, via `SVIDLET_CERT_SUBJECT`); required by Roles Anywhere |
| URI SAN | one SPIFFE ID | unchanged, exactly one |
| Key usage | digitalSignature | digitalSignature (+ keyEncipherment only if a relying party demands it) |
| TTL (`SVIDLET_CERT_TTL`) | 24h | **6h default**, renew in \[50%, 70%\]; node no longer needs long Vault-outage runway |

The Vault role sets `cn_validations=disabled` so the CN is accepted without being treated as a host name, and svidlet sends `exclude_cn_from_sans=true`; because the role allows no DNS names, a request without that flag is refused rather than signed.

### 4.5 What Stage 1 does not cover

Azure (federated credentials are OIDC-only; certificate auth there is per-app public-key upload, not CA trust), and OIDC-only SaaS: Databricks, Snowflake, Vault's own JWT auth, GitHub, and any internal service that verifies bearer tokens. These are Stage 2.

## 5. Pod identity — Stage 2: JWT-SVID via token issuer

### 5.1 Why a central issuer, and why it is small

Signing JWTs in-cluster requires the cluster to hold a signing key — SPIRE accepts this and publishes a union bundle, which puts N `kid`s in one JWKS and collides with cloud key-count limits at 100 clusters. Signing centrally requires an issuer, but our topology makes it trivially small: the issuer's *authorization input is the pod's X.509 SVID*, whose cluster prefix Vault already enforced. The issuer inherits attestation; it does not perform any.

### 5.2 Flow

```
svidlet (per node)                              token issuer (~10 replicas, regional)
──────────────────────                           ──────────────────────────────────────
one persistent HTTP/2 connection,                verify node cert chain → node registration CA
mTLS with the NODE cert, unary Mint calls        for each request (pod chain, aud, proof):
  for pods whose volume declares audiences:        · verify pod chain → Vault CA
    Mint(pod chain, aud,                            · pod.cluster == node.cluster
         sign_podkey(node, pod, aud, t)) ──►        · proof verifies under the pod key, |t−now| ≤ 120s
                                                    · grant: pod ID prefix → aud
    write jwt/<name> into the volume ◄──────       · sub = pod URI SAN, exp ≤ pod cert notAfter
    (same ..data atomic swap)                       · sign ES256 with a pool key in memory
```

- **Audience is declared, not discovered**: `volumeAttributes: { audiences: "..." }`, mirroring projected ServiceAccount tokens. A pod that declares none costs zero signs.
- **Svidlet does the exchange, not the pod**: connections collapse from millions to 120k long-lived streams; the SDK keeps reading files; no socket into the node daemon.
- **JWT TTL 6h**, refresh at 50–70% with jitter. Runway ≈ 3h of issuer outage before any pod lacks a fresh token; fail-stale applies.
- **Issuer server SVID** comes from the same Vault CA; nodes verify it with the `ca.crt` they already hold.

**The interface as fixed, and why it differs** (svidlet and `crates/svidlet-token` implement the caller; [svidlet-token-issuer](https://github.com/hixichen/svidlet-token-issuer) the rest):

- **Unary calls, not a stream.** Each mint is a unary RPC on a connection svidlet keeps open and rebuilds only when the node certificate or CA changes. The handshake amortisation is the same; a unary call needs no in-band correlation, retries per token, and maps refusals onto gRPC status codes svidlet already classifies.
- **Proof of possession.** A pod certificate is public — it is sent in every TLS handshake the pod makes — so the chain alone proves nothing about the caller. Each request carries a signature by the pod's key over the node ID, pod ID, audience and time. A node can only exchange certificates whose keys it holds, which for an honest fleet means pods it issued for, and the issuer's log then attributes every token to the node that issued its certificate — the join the placement auditor needs.
- **Grants per identity, not per cluster.** `aud ∈ allowlist[cluster]` would let every workload in a cluster obtain every audience any of them needs. Grants map a SPIFFE ID prefix (inside one cluster, no wildcards) to audiences; nothing is granted by default.
- **`exp` never outlives the certificate.** A token is capped at its pod certificate's `notAfter`, so revoking a pod's X.509 (letting it expire) revokes its tokens on the same schedule.
- **One refresh schedule.** Tokens are re-minted with every certificate renewal instead of on their own 50–70 % timer: the cap above would otherwise force the two clocks together anyway, and a volume never shows a token from a certificate generation it no longer holds.
- **Named audiences.** `audiences: "azure=api://AzureADTokenExchange,snowflake"` writes `jwt/azure` and `jwt/snowflake`; an audience is a URI and makes a poor file name.

### 5.3 Keys and JWKS

- **Pool of K = 2–4 ES256 keys**, generated in Vault Transit/KMS, loaded into replica memory at start  KMS/Vault touched only at rotation. Weekly rotation with one overlapping generation ⇒ **4–8 `kid`s** in the JWKS, changing weekly — under any cloud limit and independent of pod or replica churn.
- One `iss` per security boundary you would revoke wholesale (typically prod / non-prod), not per cluster. Cloud federation is registered once per `iss`.
- Algorithm agility is the actual PQ plan: when relying parties accept ML-DSA, add an ML-DSA `kid`, later retire ES256. Only the issuer changes.
- Optional hardening: run issuer replicas in a TEE (Nitro Enclave / SEV-SNP / TDX) with the pool key sealed to the image measurement. This yields the "compromised issuer host cannot mint" property that motivates split-key schemes, with plain ES256 and attestation on \~10 machines we own rather than 120k we rent.

### 5.4 Scale check

|  | Ceiling | Realistic |
| --- | --- | --- |
| Pods | 2.4M | \~1M |
| Fraction declaring a JWT audience | 100% | ≤30% (most inference pods use X.509 → AWS/GCP directly) |
| Signs / pod / hour at 6h TTL, 60% refresh | ≈0.3 per audience |  |
| Sustained sign rate | \~400/s | **\<150/s** |
| Persistent node streams | 120k | 120k (\~12k per replica) |

An ES256 signature is \~50 µs; the cost centre is mTLS handshakes, which the persistent-stream design amortises. A full issuer restart costs 120k reconnects spread over the existing startup jitter window.

## 6. Blast radius

| Compromised | Can | Cannot | Tail after cut-off |
| --- | --- | --- | --- |
| One node (svidlet is root) | Mint any `(ns, sa)` **in that cluster**; exchange for JWTs / cloud creds in that cluster's allowlists | Sign anything itself; touch other clusters; alter policy bundles; exfiltrate the node credential | Pod SVID ≤6h + JWT ≤6h + cloud cred ≤1h |
| One cluster (admin creds) | Same as a node, from any node, via pod creation | Exfiltrate node credentials (TPM); reach other clusters | Same |
| Token issuer | Sign any `sub`/`aud` in the trust domain until rotation | Issue X.509; obtain cloud creds via Stage 1 paths (those bypass it) | Rotation (minutes) + JWT ≤6h + cloud cred ≤1h |
| Vault (online intermediate) | Any identity anywhere | — | Re-key intermediate; re-anchor not needed (root is the anchor) |

**Detection that matters most:** issuance for pods not scheduled on the issuing node. Neither svidlet nor Vault can see scheduling; a central **placement auditor** joins Vault audit logs (issuing node SAN, URI SAN) with pod placement from each cluster's API server and pages on mismatch, alongside per-node issuance rate limits at Vault and the issuer.

With cert auth the issuing node is in the audit log without any extra configuration: the token's metadata carries the node certificate's `common_name` and `serial_number`, and Vault records auth metadata on every request. The `X-Svidlet-Node` request header remains for AppRole deployments, where every node shares one role and the header is the only node attribution.

**Standing rules:** no cloud role ever trusts `cluster/*`; audience allowlists are per cluster and narrow; node cert 24h, pod SVID 6h, JWT 6h.

## 7. Decisions and rejected alternatives

| Option | Verdict | Why |
| --- | --- | --- |
| Host/PCR attestation | Rejected | Vendor has physical access; burden without proportional assurance. TPM used only for identity + non-exportability. |
| AppRole in production | Retired | Shared bearer secret; exactly the exfiltration TPM prevents. |
| Per-cluster JWT signing keys (SPIRE nested / kube-oidc-fed) | Rejected | N `kid`s vs cloud limits; cluster holds a key; per-cluster rotation ceremonies. |
| Kubernetes SA tokens as attestation to the issuer | Rejected | N API servers as N issuers; issuer must reach each cluster's API server from rented hosts. |
| Mediated RSA (split `d` per cluster) | Rejected | Only improves "issuer compromised alone"; issuer + any one member reconstructs `d`; 100-cluster re-split on rotation; RSA deprecates 2030–35; no PQ path. Cert-authenticated issuer has the same trust shape with no shared secret. |
| 2-party ECDSA (Lindell17 / DKLs / CGGMP21) | Rejected for now | Deployable, but multi-round MPC in the identity hot path, large protocol surface with published implementation bugs, same 2-of-2 collusion property. Revisit only if issuer operators become the adversary. |
| EdDSA / FROST threshold | Rejected | Clouds do not accept EdDSA JWTs. |
| Threshold ML-DSA | Not available | Research stage; clouds do not accept ML-DSA JWTs yet. |
| Pod SDK exchanging JWTs itself | Rejected | Millions of handshakes; svidlet already holds the pod key and a node stream. |
| TEE for issuer | Adopted as optional hardening | Gives the split-key property by isolation, cheaply, on machines we own. |
| Refuse to issue a certificate a cloud would reject | Rejected | The certificate is still a valid SVID for mTLS; fail-stale says a cloud-only defect must not cost a pod its identity. `SVIDLET_CLOUD_PROFILE` reports instead. |

## 8. Roadmap

**Phase 0 — Groundwork (now → +6 weeks)**

- ✅ Certificate profile: add Subject CN, keep single URI SAN, default TTL 6h. Unit tests for Roles Anywhere / GCP X.509 acceptance rules (Subject present, key usage, chain order).
- Root CA offline/HSM with online intermediate in Vault; document the anchor-at-root rule.
- File AWS quota increase for `CreateSession`; establish per-account sharding plan.
- Placement auditor v0: Vault audit log → pod placement join, batch, alert on mismatch.

**Phase 1 — Node attestation (+6 → +14 weeks)**

- EK inventory schema and provisioning hook; change control on allowlist writes.
- step-ca (or go-attestation service) deployment; ACME `device-attest-01` path validated on two vendor board families and one vTPM.
- svidlet: cert-auth to Vault with TPM-resident node cert (Tier A); Tier B/C fallbacks; AppRole removed from `deploy/`. *(✅ cert auth with a file-held key, both Tier C routes, deploy variants with AppRole confined to `dev`, the bootstrap hand-off; TPM-backed signer outstanding.)*
- Soak on one production cluster; measure registration latency and re-registration under node reimage.

**Phase 2 — Stage 1 cloud federation (+10 → +18 weeks, overlaps Phase 1)**

- AWS: trust anchors per account, profiles, role trust-policy templates conditioned on `x509SAN/URI` with cluster prefix; SDK `CreateSession` signing in Go/Python/Rust (or wrap the reference helper).
- GCP: pool + X.509 provider per environment; attribute mapping with 127-byte `extract`; SDK via native client-library certificate config.
- HOWTO.md: "from `tls.crt` to STS credentials" for both clouds; kind-e2e extended with mocked STS.
- Migrate the first inference workloads off static cloud keys.

**Phase 3 — Stage 2 token issuer (+16 → +28 weeks)**

- Issuer service: mTLS, node-cert-authenticated persistent streams, pod-cert verification, cluster-prefix and audience allowlist enforcement, ES256 pool keys, JWKS publisher, OIDC discovery.
- svidlet: `audiences` volume attribute, `jwt/<aud>` publication with atomic swap, refresh loop, metrics (`svidlet_jwt_age_seconds`, issuer stream connected). *(✅ svidlet's side built and tested against a stand-in issuer; the issuer is [svidlet-token-issuer](https://github.com/hixichen/svidlet-token-issuer).)*
- Register `iss` with Azure and first OIDC-only SaaS; rotation runbook rehearsed (target: \<15 min pool rotation end-to-end).
- Optional: TEE deployment of issuer replicas.

**Phase 4 — Hardening (+28 weeks →)**

- Placement auditor v1 with per-node rate limits feeding automatic node denial.
- Kubernetes 1.35+ `PodCertificateRequest` signer mode: kubelet takes over key generation and mounting; `svidlet-issue` survives, node component shrinks.
- ML-DSA `kid` added when a relying party accepts it.

## 9. Future: identity-to-cloud mapping management and policy visualisation

Once identities flow, the operational risk moves to the *bindings*: which SPIFFE prefixes may assume which AWS roles, impersonate which GCP service accounts, and request which JWT audiences. Today those live in three places (IAM trust policies, GCP pool bindings, the issuer's allowlist) with three syntaxes. Proposed tooling, as a separate project consuming svidlet's identity shape:

- **Single source of truth** for `SPIFFE prefix → {cloud principal, audience}` grants, in Git, rendered by CI into IAM trust policies (`x509SAN/URI` conditions), GCP `principalSet://…/attribute.spiffe_id/…` bindings and attribute conditions, and the issuer's per-cluster audience allowlist. Lint rules: no `cluster/*`, no prefix broader than `ns`, every grant has an owner and expiry.
- **Reachability graph**: given a `(cluster, ns, sa)`, enumerate every cloud role, service account and audience it can reach — and the inverse, given a role, every identity that can assume it. Rendered from the SoT plus a periodic read-back of live IAM/GCP state, with drift as a first-class alert.
- **Blast-radius view per cluster**: the union of cloud permissions reachable from that cluster's prefix, so "what does losing cluster C cost" is a query, not a war-room exercise.
- **Placement auditor UI**: issuance-vs-scheduling mismatches, per-node issuance rates, node cert and EK inventory status, with one-click node denial.
- **Policy bundle lineage**: which signed bundle digest each ring is on, who promoted it, and the diff — extending the existing OCI rollout manifest.

## 10. Gaps found in review

What the plan above did not cover, found while building Phases 0–3. The first four were design gaps in Stage 2 and are closed in the interface (§5.2); the rest are open and belong to the phase named.

| # | Gap | State |
| --- | --- | --- |
| 1 | The issuer accepted a pod certificate without proof the caller holds its key | **Closed**: proof of possession. |
| 2 | Audience allowlist per cluster: any workload could get any audience its cluster had | **Closed** in the interface: the issuer grants per SPIFFE ID prefix. |
| 3 | A JWT could outlive the certificate it was derived from | **Closed** in the interface: the issuer caps `exp` at `notAfter`, and svidlet re-mints with every renewal. |
| 4 | Two refresh clocks (certificate, token) that drift | **Closed**: re-mint on renewal. |
| 5 | **Public discovery.** Azure, GCP and SaaS verifiers fetch `https://<iss>/.well-known/openid-configuration` and the JWKS from the internet; the issuer runs in private networks | Open, Phase 3 (svidlet-token-issuer): static hosting (bucket + CDN) or a load balancer in front of the issuer. Decide which, per `iss`. |
| 6 | **Key rollover vs JWKS caching.** Verifiers cache the JWKS for hours; a key that signs before they have fetched it causes a fleet-wide outage for that audience | Open, Phase 3 (svidlet-token-issuer). Publish before signing; the runbook must wait out the longest verifier cache, so the "\<15 min rotation" target applies to *removing* a compromised key, not to introducing one. |
| 7 | **The issuer's serving certificate is issued by hand** — from the Vault role `TOKEN_ISSUER_DNS` creates, because svidlet verifies the issuer by DNS name | Open, Phase 4, svidlet side: verify the issuer by SPIFFE ID instead, so it can take its certificate from svidlet like any pod and rotate with no ceremony. |
| 8 | **No node deny list.** A node found misbehaving keeps its registration certificate for up to 24 h, and nothing at Vault or the issuer refuses it sooner | Open, Phase 4. Both need the same hook — Vault cert-auth `allowed_common_names` or an entity disable, and an issuer deny list — fed by the placement auditor. |
| 9 | **Vault audit volume** at full scope: ~110 signs/s plus ~50 logins/s at ~7 KB per entry is **~70–100 GB/day** into the placement auditor's pipeline | Open, Phase 0 sizing. Ship to a log pipeline, not local disk; the auditor needs only the node CN, serial and `uri_sans`. |
| 10 | **Rate limits are per path, not per client.** One noisy node can exhaust its cluster's `pki/sign` quota and delay every other node's pods | Open (§11 Q6). A per-node limit belongs at the placement auditor or the issuer, which know the node. |
| 11 | **Standalone has no trustworthy node attribution.** Kubernetes auth shares one ServiceAccount across nodes; `X-Svidlet-Node` is self-asserted | By design: `standalone` is the Phase 0 posture. Production — and every Stage 2 deployment, which needs a node certificate for the issuer — is `with-node-bootstrap`. |
| 12 | **Root rotation runbook.** svidlet delivers a changed trust bundle to running pods, but the order of operations across Vault, AWS trust anchors, GCP trust stores and the issuer's `pod_ca` is unwritten | Open, before Phase 2 goes wide. |
| 13 | **Vault availability.** Fail-stale gives each pod ~2–3 h of runway after its renewal point; a longer Vault outage expires certificates fleet-wide | Open, Phase 0: HA plus a DR replica, and an alert on `svidlet_earliest_certificate_expiry_seconds` well above the runway. |
| 14 | **SLOs and alerts** were not defined | Open. Proposed: issuance success ratio and publish p99 per cluster; earliest certificate, token and node-certificate expiry; token failures by code; issuer denials by reason — `grant` spikes mean misconfiguration, `proof` and `node_identity` mean someone is probing. |
| 15 | **Mount-time failure is the only feedback** for an audience without a grant | Open, nice to have: a validating admission policy that checks `audiences` against the grants before the pod is scheduled. |
| 16 | **Nothing verified a token end to end in a real relying party**, and the kind e2e has not been run in CI | Open, Phase 3: register an `iss` with Azure in a sandbox tenant; run `hack/kind-e2e.sh` on a runner that allows nested containers. |
| 17 | **CI** did not exist | **Closed**: `.github/workflows/ci.yml`. |

## 11. Open questions

1. AWS `CreateSession` maximum session duration and its interaction with a 6h SVID — confirm whether cloud-credential lifetime should be pinned below SVID lifetime.
2. Per-account trust anchors versus a shared-services account: one anchor per account keeps the 50-anchor limit irrelevant but multiplies root-rotation work by the account count; decide the sharding before Phase 2, together with how `CreateSession` TPS is spread across accounts and regions.
3. GCP pool topology: one pool per environment with attribute conditions per cluster, or one pool per cluster group — the 3-root / 10-intermediate trust store limit is per provider, and the answer decides how a root rotation is staged.
4. Subject CN choice per workload class: `pod_name` gives CloudTrail per-replica attribution; `service_account` gives stable Subjects for relying parties (PostgreSQL `cert` auth, Kafka ACLs) that key on the CN. Is one fleet-wide default enough, or does it need to be a volume attribute?
5. TPM-backed signer for the node key: tpm2 PKCS#11 through the TLS stack, or a small local signing helper — which keeps the 16 MB budget and a static musl binary.
6. Vault rate-limit quota sizing now that a single node can exceed 200 signatures/s: per cluster from observed pod-rollout peaks, or a per-node limit enforced at the placement auditor instead.
