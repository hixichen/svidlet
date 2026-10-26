# Svidlet: per-cluster broker for X.509 and JWT identity

**Design and code update guide**

|  |  |
| --- | --- |
| **Version** | v0.2 |
| **Status** | Draft for review |
| **Date** | 25 October 2026 |
| **Scope** | A multi-cluster Kubernetes fleet across many GPU vendors, Kubernetes 1.31+, Vault Enterprise |
| **Supersedes** | v0.1 (X.509 via broker only); replaces today’s direct node → Vault issuance ([DESIGN-v0.1.md](DESIGN-v0.1.md)) |
| **Unchanged for workloads** | One CSI volume, files only, no SDK, no socket |

> **Editorial note.** The source text of this draft ended part-way through §9. §9’s last
> rows and §10–§18 (which earlier sections reference: §16 for the LSM layer, §18 for the
> Transit fallback) were completed from the rest of the document and from the code plan,
> and are marked *drafted* — review them with the same care as the rest.

---

## 1. Summary

Every pod that declares the Svidlet volume gets two kinds of identity, both as files:

- **An X.509 SVID** for mTLS between services and for AWS and GCP federation without tokens.
- **JWT-SVIDs** for relying parties that only speak OIDC: Azure, Vault JWT auth, SaaS APIs, and AWS or GCP where teams prefer the token flow they already know.

Three components do the work:

| Component | Runs | Job | Holds |
| --- | --- | --- | --- |
| `svidlet-node` | DaemonSet, every node | Generate the pod’s key, get its certificate, fetch its tokens, write files | Nothing that can sign |
| `svidlet-broker` | Deployment, 3 replicas per cluster on dedicated nodes | Verify callers, enforce per-cluster rules, ask Vault to sign | The cluster’s only Vault credential |
| Vault | Control plane | Sign certificates (PKI engine) and tokens (SPIFFE secrets engine), rotate the token key, serve discovery documents | The CA key and the JWT signing key |

Two rules carry the design:

1. **The broker never signs anything.** Vault signs both certificates and tokens, and Vault policy, not broker code, limits each broker to its own cluster’s identities and each identity to its approved audiences.
2. **A token is derived only from a certificate.** A pod (or `svidlet-node` acting with the pod’s key) presents its X.509 SVID to the broker over mTLS. The token’s subject is that certificate’s SPIFFE ID; the request can only choose among approved audiences.

What the fleet gets:

- **Node compromise is limited to that node’s pods,** for certificates and tokens.
- **Broker compromise is limited to its cluster,** for certificates and tokens, enforced by Vault.
- **One issuer, one JWKS, registered once** with every relying party, regardless of cluster count.
- **No signing or key-rotation code of our own.** Vault generates, rotates and publishes the token key.
- **One Vault client per cluster,** not one per node.

---

## 2. Context and constraints

Workload-plane clusters run on hosts rented from many vendors, who have physical and root access. Some control planes are self-managed; others are run by the vendor, where we cannot change API server flags or feature gates. Our control plane runs in the cloud and cannot call workload-plane API servers; the planes connect through the Tailscale overlay. Vault is central and billed per client. Customer pods do not automount ServiceAccount tokens. Clusters run Kubernetes 1.31 or later. Engineers are familiar with OIDC federation and expect token files their SDKs can read.

---

## 3. Goals and non-goals

**Goals**

1. Nodes never hold a credential that can produce a signature.
2. A compromised node obtains identities only for pods scheduled on it.
3. Vault, independently of the broker, confines each broker to its cluster’s identities and each identity to its approved audiences.
4. One OIDC issuer for the whole fleet.
5. No signing keys or rotation logic in our code.
6. Fail stale: outages of the broker, API server or Vault delay new work and never break running work.
7. Workloads see files only: no SDK, sidecar, socket or pod-spec change beyond the volume.

**Non-goals**

A Workload API socket, kernel hooks on the issuance path (identity is never derived from observed syscalls or traffic), per-process attestation, certificate revocation lists (short lifetimes replace them), federation with external trust domains, runtime integrity attestation, and supply-chain enforcement (that belongs to admission control; the broker adds an optional issuance-time check for sensitive identities). An optional LSM layer that protects credentials after issuance is future work (§16).

---

## 4. Architecture

```
node N                                broker (cluster C)                         Vault (control plane)
──────                                ──────────────────                         ─────────────────────
kubelet ─ NodePublishVolume ─► svidlet-node
          (ns, sa, pod, uid,     │
           pod token)            │ X.509 path, port 8443
                                 ├─ key in tmpfs, CSR ───────────► Sign
                                 │  + pod token                    ├─ TokenReview ×2, informer
                                 │  + node token                   ├─ invariants I1–I12
                                 │                                 └─ pki_int/sign/spiffe-C ───────► PKI engine
                                 │◄────────────── chain ───────────┘                                (cluster/C/* only)
                                 │
                                 │ JWT path, port 8444
                                 ├─ mTLS with the pod’s SVID ────► POST /v1/tokens
                                 │                                 ├─ verify chain, SAN, cluster
                                 │                                 ├─ rules T1–T8, cache
                                 │                                 └─ spiffe/role/C__ns__sa/mintjwt ► SPIFFE engine
                                 │◄────────────── tokens ──────────┘                                (policy: own roles,
                                 └─ write tls.*, jwt/<alias>                                         allowed audiences)
pod (runtime audiences, optional) ─ mTLS with its SVID ──► POST /v1/token                            │
                                                                                                     ▼
relying parties (AWS, GCP, Azure, Vault, SaaS) ◄── https://oidc.corp.example/v1/spiffe/.well-known/… (public bucket,
                                                                                    synced from Vault by a publisher)
```

| Component | Kubernetes permissions | Network |
| --- | --- | --- |
| `svidlet-node` | None | Egress to the broker only |
| `svidlet-broker` | `create tokenreviews`; `get, list, watch pods` | Ingress on 8443 from `svidlet-node`; on 8444 from `svidlet-node` and opted-in pods; egress to the API server and Vault |
| `svidlet-policy` | None (unchanged) | Egress to the OCI registry (unchanged) |
| `oidc-publisher` (control plane) | n/a | Reads Vault’s discovery endpoints; writes the public bucket |

---

## 5. X.509 path

Unchanged from v0.1 in substance. Summarised here so this document stands alone.

### 5.1 Attestation

The broker trusts two tokens only the API server can mint, and the equality between them.

**Pod token.** The kubelet requests a token for the pod’s ServiceAccount, bound to the pod, and hands it to the CSI driver; the pod never sees it:

```yaml
apiVersion: storage.k8s.io/v1
kind: CSIDriver
metadata: { name: csi.svidlet.io }
spec:
  attachRequired: false
  podInfoOnMount: true
  requiresRepublish: true        # fresh tokens about every minute
  volumeLifecycleModes: [Ephemeral]
  tokenRequests:
    - { audience: svidlet-broker, expirationSeconds: 600 }
```

It is audience-scoped, bound to the pod and its UID (useless once the pod is deleted), and node-restricted: a kubelet can only obtain tokens for pods bound to its own node.

**Node token.** `svidlet-node`’s own projected token with audience `svidlet-broker`. The broker accepts the caller as node N only if the token’s user is `system:serviceaccount:svidlet-system:svidlet-node` and the pod it is bound to is a `svidlet-node` DaemonSet pod with `spec.nodeName == N`.

The pod token proves the kubelet on N′ asked for pod P; the node token proves the caller is Svidlet on N; the broker requires N = N′. A leaked pod token is useless except from that pod’s node.

### 5.2 Flow

- **First publish.** The node mounts a tmpfs, generates a P-256 key, sends a CSR (no names) with the pod token. The broker verifies, renders the SPIFFE ID, and Vault signs. The node checks the leaf matches its key and the expected ID, then swaps files in atomically.
- **Republish.** The node updates the cached pod token in memory; nothing is issued.
- **Renewal.** At 50–70% of the lifetime, with a new key and the latest pod token. Every check runs again. There is no renew-with-current-certificate path.
- **Pod deletion.** The pod token stops validating, renewals are denied, and the certificate dies with its lifetime.

### 5.3 Broker invariants for certificates

| # | Invariant |
| --- | --- |
| I1 | Identity comes only from TokenReview and the Pod informer, never from the request. |
| I2 | The cluster is configuration. Vault policy allows exactly `pki_int/sign/spiffe-<C>`. |
| I3 | The caller’s node equals the pod’s node. |
| I4 | The pod is live: UID matches, not terminating, ServiceAccount matches. |
| I5 | Every issuance and renewal needs a fresh pod token. |
| I6 | The CSR’s signature verifies, the key is P-256, no CA constraint is requested; CSR names are ignored. |
| I7 | The broker renders the ID and checks it against the pattern before calling Vault. |
| I8 | System namespaces and the `default` ServiceAccount are denied; allowlist mode denies anything not in the catalog. |
| I9 | Sensitive identities require digest-pinned images from approved registries. |
| I10 | Per-node limits on issuance rate and on distinct identities per hour. |
| I11 | TTL is set by the broker and clamped to the role maximum. |
| I12 | Every decision is audited; tokens are never logged. |

---

## 6. JWT path

### 6.1 Why Vault’s SPIFFE secrets engine signs

Vault Enterprise’s SPIFFE secrets engine mints JWT-SVIDs, generates and rotates its own signing key, and serves standard OIDC discovery and JWKS endpoints. Its mint call accepts only an audience; the subject comes from the role’s template. That property is what makes the design safe:

- **A role per identity, with a fixed subject.** Role `gpu-a__payments__api` always mints `sub = spiffe://corp.internal/cluster/gpu-a/ns/payments/sa/api`. Double underscores cannot occur in Kubernetes names, so the role name is unambiguous.
- **A generated policy per broker.** Broker `gpu-a` may call `mintjwt` only on `gpu-a__…` roles, and only with that identity’s approved audiences, via `allowed_parameters`.

The alternative, Vault Transit signing a payload the broker builds, signs arbitrary bytes. Vault could not tell a payload for `cluster/gpu-a` from one for `cluster/gpu-b`, so one compromised broker could forge tokens for every cluster. With the SPIFFE engine, it can forge nothing outside its own cluster’s roles and audiences. Transit remains a documented fallback only (§18).

### 6.2 Flow

**File mode, the default.** After each certificate issuance or renewal, and every 15 minutes, `svidlet-node` calls `POST /v1/tokens` on the broker over mTLS using the pod’s certificate and key. The broker returns a token for every audience approved for that identity. It answers from its cache unless a token has passed half its lifetime or its signing key has been retired (T5), so most check-ins cost no signing. The node rewrites `jwt/<alias>` only when a token changed, through the same atomic swap as the certificate. On failure, existing token files stay until they expire. The frequent check-in is what lets an emergency key rotation reach every pod within minutes despite 6–12-hour tokens.

**Direct mode, for audiences chosen at runtime.** A pod calls the broker itself with the files it already has:

```sh
curl --cert /var/run/svid/tls.crt --key /var/run/svid/tls.key --cacert /var/run/svid/ca.crt \
     https://svidlet-broker.svidlet-system.svc:8444/v1/token -d '{"audience":"https://api.vendor.example"}'
```

The audience must still be approved for the identity. Direct mode needs a NetworkPolicy allowing that pod’s namespace to reach port 8444.

### 6.3 What a token contains

```json
{
  "iss": "https://oidc.corp.example/v1/spiffe",
  "sub": "spiffe://corp.internal/cluster/gpu-a/ns/payments/sa/api",
  "aud": ["sts.amazonaws.com"],
  "iat": 1793000000, "nbf": 1793000000, "exp": 1793043200,
  "jti": "5f1c…",
  "vault": { "entity": { "id": "…broker-gpu-a entity…" } }
}
```

| Claim | Source |
| --- | --- |
| `sub` | Fixed by the Vault role, which the broker selects from the caller’s certificate SAN |
| `aud` | Request, restricted by Vault policy to the identity’s approved list |
| `iss`, `iat`, `nbf`, `exp`, `jti` | Vault |
| `vault.entity.id` | Vault: the broker that requested it, useful for audit |

### 6.4 Broker rules for tokens

| # | Rule |
| --- | --- |
| T1 | The caller’s certificate chains to the pinned root through the expected intermediate, is a leaf with client-auth usage, is within its validity, and has exactly one URI SAN matching the SPIFFE pattern. |
| T2 | The SAN’s cluster segment equals this broker’s cluster. Requests for other clusters are denied before Vault is called; Vault would deny them anyway. |
| T3 | The identity has an entry in the catalog and the requested audiences are approved for it. |
| T4 | The Vault role is derived from the SAN, never from the request. |
| T5 | A cached token is served only if more than half its lifetime remains, its `kid` is still in the public JWKS, and its `exp` is not later than the caller’s certificate `notAfter`. A token never outlives the certificate that obtained it. With 48-hour certificates renewed at 50–70%, a certificate always has at least 14 hours left, so 12-hour tokens fit. |
| T6 | A newly minted token is handed out only once its `kid` is present in the public JWKS. Cached tokens whose `kid` has been removed are discarded and re-minted. |
| T7 | Per-identity rate limits on minting. |
| T8 | Every issuance is audited with identity, audience, caller certificate serial and `jti`; token values are never logged. |

The cache is keyed by identity and audience, so all replicas of a Deployment in a cluster share one token per audience. Vault sees one mint per identity, audience and half-lifetime, not one per pod.

### 6.5 Consuming tokens

```sh
# AWS
AWS_ROLE_ARN=arn:aws:iam::123456789012:role/payments-api
AWS_WEB_IDENTITY_TOKEN_FILE=/var/run/svid/jwt/aws
# Azure
AZURE_FEDERATED_TOKEN_FILE=/var/run/svid/jwt/azure
# GCP: external_account credential config with "credential_source": {"file": "/var/run/svid/jwt/gcp"}
# Vault
vault write auth/jwt/login role=payments jwt=@/var/run/svid/jwt/vault
```

For AWS and GCP, the X.509 path (Roles Anywhere, Workload Identity Federation with an X.509 provider) remains available and needs no public issuer. Teams choose per workload.

---

## 7. Vault configuration

### 7.1 PKI, per cluster

```sh
vault write pki_int/roles/spiffe-gpu-a \
  allowed_uri_sans="spiffe://corp.internal/cluster/gpu-a/*" \
  allow_any_name=false require_cn=false \
  use_csr_common_name=false use_csr_sans=false \
  allowed_domains="" allow_ip_sans=false \
  key_type=ec key_bits=256 ttl=48h max_ttl=48h no_store=true \
  server_flag=true client_flag=true
```

### 7.2 SPIFFE secrets engine, fleet-wide

```sh
vault secrets enable spiffe
vault write spiffe/config \
  trust_domain=corp.internal \
  jwt_issuer_url=https://oidc.corp.example \
  jwt_signing_algorithm=ES256 \
  key_lifetime=168h bundle_refresh_hint=1h \
  jwt_oidc_compatibility_mode=true

# Generated from the catalog, one per identity that needs tokens:
vault write spiffe/role/gpu-a__payments__api \
  template='{"sub": "/cluster/gpu-a/ns/payments/sa/api"}' \
  ttl=12h use_jti_claim=true          # 6h to 12h per identity
```

`iss` becomes `https://oidc.corp.example/v1/spiffe` because Vault appends the mount path. Use ES256 if every relying party accepts it; otherwise RS256, and plan the move before RSA-2048 is deprecated in 2030. `jwt_oidc_compatibility_mode` refuses subjects over 255 characters. GCP additionally caps `google.subject` at 127 bytes, so map long IDs with `extract()` there.

### 7.3 Broker policy, generated per cluster

```hcl
# svidlet-broker-gpu-a
path "pki_int/sign/spiffe-gpu-a" { capabilities = ["update"] }

path "spiffe/role/gpu-a__payments__api/mintjwt" {
  capabilities       = ["update"]
  allowed_parameters = { "audience" = ["sts.amazonaws.com", "vault"] }
}
path "spiffe/role/gpu-a__batch__runner/mintjwt" {
  capabilities       = ["update"]
  allowed_parameters = { "audience" = ["vault"] }
}
# … one block per identity in cluster gpu-a that has audiences in the catalog
```

The broker has no other Vault permissions: no `sign-verbatim`, no `issue`, no role management, no Transit.

### 7.4 How the broker authenticates to Vault

| Tier | Method | Stored secret | Use for |
| --- | --- | --- | --- |
| B1 | JWT auth, one mount per cluster, validating the broker’s projected token against that cluster’s signing keys (via a JWKS relay or keys pushed under change control) | None | Default |
| B2 | AppRole, response-wrapped secret ID, weekly rotation | On broker nodes only | Where B1 is not yet possible |
| B3 | TPM-bound certificate auth on broker nodes | None, non-exportable | Later |

```sh
vault auth enable -path=k8s-gpu-a jwt
vault write auth/k8s-gpu-a/config jwks_url=https://jwks-gpu-a.<tailnet>/openid/v1/jwks \
  jwks_ca_pem=@gpu-a-relay-ca.pem bound_issuer="<gpu-a issuer>"
vault write auth/k8s-gpu-a/role/svidlet-broker role_type=jwt user_claim=sub \
  bound_subject="system:serviceaccount:svidlet-system:svidlet-broker" \
  bound_audiences=vault token_policies=svidlet-broker-gpu-a token_ttl=1h token_max_ttl=4h
```

Vault counts a JWT-auth client by its `user_claim` per mount, so all replicas of a cluster’s broker are one client, and the fleet’s client count equals its cluster count. Nodes and pods are never Vault clients, and minting tokens adds none.

---

## 8. Publishing the issuer

Relying parties must fetch discovery and JWKS from a public HTTPS URL; Vault stays private.

- **`oidc-publisher`**, a small job in the control plane, runs every minute. It reads `/v1/spiffe/.well-known/openid-configuration` and `/v1/spiffe/.well-known/keys` from Vault, checks that the issuer matches, every key parses and the current `kid` is present, then uploads both to a public bucket under `/v1/spiffe/.well-known/` with `Cache-Control: max-age=300`.
- **Registration happens once per relying party:** an IAM OIDC provider per AWS account, a Workload Identity Federation OIDC provider per GCP pool, a federated credential per Azure app (with an exact subject), a JWT auth mount per Vault.
- **Write access to the bucket is Tier-0.** Whoever can write the JWKS can make relying parties accept tokens they sign. The publisher’s write credential is used by nothing else, and changes to the bucket alert.

```json
{
  "Effect": "Allow",
  "Principal": { "Federated": "arn:aws:iam::123456789012:oidc-provider/oidc.corp.example/v1/spiffe" },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": { "StringEquals": {
    "oidc.corp.example/v1/spiffe:aud": "sts.amazonaws.com",
    "oidc.corp.example/v1/spiffe:sub": "spiffe://corp.internal/cluster/gpu-a/ns/payments/sa/api"
  } }
}
```

---

## 9. Rotation

| What | Lifetime | Rotated by | Emergency action |
| --- | --- | --- | --- |
| Pod X.509 SVID | 48 h, renewed at 50–70% | `svidlet-node` via the broker | Deny at the broker; expires within two days |
| Pod JWT | 6–12 h, re-minted at 50%, checked every 15 min | `svidlet-node` or the pod via the broker | Retire the signing `kid`, which invalidates all tokens from that key; otherwise expires within 12 h |
| JWT signing key | `key_lifetime` 7 days | Vault, automatically; `oidc-publisher` republishes | Remove the `kid` from the public JWKS; force a new key |
| Broker serving certificate | 24 h | The broker, from Vault PKI | Redeploy |
| Broker Vault token | 1 h | JWT auth login | Disable the broker’s role or entity |
| Pod and node tokens (Kubernetes) *(drafted)* | 10 min pod token, refreshed by `requiresRepublish` about every minute; node token 1 h, kubelet-rotated | The kubelet | Delete the pod; for the node token, delete the `svidlet-node` pod or cordon the node |
| Root and intermediate CA *(drafted)* | Root offline, years; intermediate 1 year | Ceremony; new intermediate cross-published in `ca.crt` before first use | Re-issue the intermediate; AWS and GCP anchor at the root, so no relying-party change |

---

## 10. Failure modes *(drafted)*

Every row applies goal 6: new work waits, running work continues.

| Outage | New pods | Running pods, X.509 | Running pods, JWT | Runway |
| --- | --- | --- | --- | --- |
| Broker (all replicas) | `NodePublishVolume` fails with `Unavailable`; the kubelet retries | Files stay; renewals retry with backoff | Files stay; check-ins retry | ≥ 14 h of certificate (48 h at 70%), ≥ 6 h of a 12-h token |
| API server | Broker cannot TokenReview → `Unavailable` | Renewals wait | Unaffected: the token path needs no API server | As above for X.509 |
| Vault | Broker returns `Unavailable` | Renewals wait | Cached tokens are served until half-life; then check-ins fail | As above |
| `oidc-publisher` or bucket | Unaffected | Unaffected | New `kid` cannot be published, so T6 holds new tokens back; cached tokens keep being served | Vault `key_lifetime` minus overlap |
| `svidlet-node` restart | Waits for the restart | Recovered from disk (unchanged from v0.1) | Recovered: the node re-reads `jwt/` and checks in | — |

Liveness probes stay process-only on both the node and the broker; a dependency outage must never restart the fleet.

---

## 11. Blast radius *(drafted)*

| Compromised | Can | Cannot | Tail after cut-off |
| --- | --- | --- | --- |
| One node | Certificates and tokens for pods scheduled on that node (it holds their pod tokens and keys) | Identities of pods on other nodes (I3); anything in another cluster; sign anything | 48 h certificate, 12 h token |
| One leaked pod token | Nothing off its own node | — | 10 min |
| One pod’s key | That pod’s identity, its approved audiences | Other identities; unapproved audiences | Certificate lifetime |
| One broker | Any identity in its cluster, any approved audience for those identities (Vault policy) | Other clusters; audiences outside the catalog; sign without Vault | 1 h Vault token, 48 h certificate, 12 h token |
| Bucket write credential | Publish a JWKS: relying parties accept tokens from an attacker’s key | Issue X.509 | Until the bucket is restored and caches expire (`max-age=300`) |
| Vault | Everything | — | Re-key |

Detection: the broker audits every decision (I12, T8), and Vault audits every sign and mint with the broker’s entity. The placement auditor of the bootstrap roadmap is now mostly redundant: the broker *enforces* placement (I3) instead of detecting its violation.

---

## 12. The catalog *(drafted)*

One file in Git per fleet is the source of truth for which identities may hold tokens, for which audiences, and which identities are sensitive. CI renders it into the Vault roles of §7.2 and the per-cluster policies of §7.3, and ships the same file to each broker as a ConfigMap. The broker checks the catalog (T3, I8, I9); Vault enforces the rendered policy independently. A catalog edit that the broker sees but Vault has not yet applied fails closed for the new grant and changes nothing else.

```toml
# catalog.toml
schema = 1
trust_domain = "corp.internal"

[mode]
allowlist = false                    # true: I8 denies identities with no entry

[[identity]]
cluster = "gpu-a"                    # or "*" for every cluster in the fleet
namespace = "payments"
service_account = "api"
token_ttl = "12h"
sensitive = true                     # I9: digest-pinned images from approved registries only
audiences = [
  { alias = "aws",   audience = "sts.amazonaws.com" },
  { alias = "vault", audience = "vault" },
]

[[identity]]
cluster = "gpu-a"
namespace = "batch"
service_account = "runner"
audiences = [{ alias = "vault", audience = "vault" }]

[sensitive]
registries = ["registry.corp.example/", "ghcr.io/corp/"]
```

Aliases name the files under `jwt/`, are restricted to `[a-z0-9-]`, and are unique per identity.

---

## 13. Code changes *(drafted)*

| Area | Today (v0.1) | v0.2 |
| --- | --- | --- |
| `svidlet-issue` | `Issuer` trait, Vault PKI, AppRole/Kubernetes/static auth | Adds: `SignRequest.pod_token`; a `BrokerIssuer` client; Vault `mintjwt` and JWKS reads; Vault JWT auth (B1); JWT/JWKS parsing helpers; the catalog type and renderer |
| `svidlet` (now `svidlet-node`) | Signs directly against Vault | Signs via the broker; caches the pod token from each (re)publish; fetches tokens into `jwt/<alias>` on issuance, renewal and every 15 min; holds no Vault credential |
| `svidlet-broker` (new crate) | — | HTTPS on 8443 (sign) and 8444 (tokens, mTLS); TokenReview and Pod lookups; invariants I1–I12, rules T1–T8; token cache; rate limits; audit log |
| `oidc-publisher` (new binary) | — | Fetch, validate, write discovery and JWKS to a publish directory synced to the bucket |
| `svidlet-catalog` (new binary) | — | Lints the catalog; renders Vault role commands and per-cluster HCL policies |
| `deploy/` | DaemonSet with AppRole Secret | DaemonSet without Vault access; broker Deployment, RBAC, NetworkPolicy; CSIDriver with `tokenRequests` and `requiresRepublish` |

Broker API, both JSON over HTTPS:

```
POST :8443/v1/sign      Authorization: Bearer <node token>
  { "pod_token": "...", "namespace": "...", "pod_name": "...", "pod_uid": "...",
    "service_account": "...", "csr": "-----BEGIN CERTIFICATE REQUEST-----..." }
→ 200 { "spiffe_id": "...", "cert_chain": "...", "ca": "...", "not_after": 1793000000 }

POST :8444/v1/tokens    (mTLS, client certificate = the pod's SVID)
  { }                                      → 200 { "tokens": [ { "alias", "audience", "token", "exp" } ] }
POST :8444/v1/token     (mTLS)
  { "audience": "..." }                    → 200 { "token": "...", "exp": ... }
```

The request’s namespace, pod name, UID and ServiceAccount are hints for error messages and a cross-check only; every one is re-derived from TokenReview and the Pod (I1). Errors are `400` malformed, `401` unauthenticated, `403` refused by a rule, `429` rate-limited, `503` a dependency is down; the node maps them onto `InvalidArgument`, `Unauthenticated`, `PermissionDenied`, `ResourceExhausted` and `Unavailable`.

---

## 14. Migration *(drafted)*

1. Deploy Vault: the `pki_int` per-cluster roles (§7.1 unchanged from v0.1 except the mount), the SPIFFE engine, and the catalog-rendered roles and policies.
2. Deploy the broker in a cluster alongside the existing DaemonSet. Nothing calls it yet.
3. Roll `svidlet-node` with `SVIDLET_ISSUER=broker`, ring by ring. Existing certificates are adopted on restart as before; their next renewal goes through the broker.
4. Once every node uses the broker, revoke the cluster’s node AppRole and delete its Secret. `SVIDLET_ISSUER=vault` remains only for kind and development.
5. Publish the issuer (§8), register it with each relying party, and add audiences to the catalog workload by workload.

---

## 15. Observability *(drafted)*

| Metric | Where | Alert |
| --- | --- | --- |
| `svidlet_earliest_certificate_expiry_seconds` | node | < 6 h |
| `svidlet_jwt_earliest_expiry_seconds` | node | < 1 h |
| `svidlet_broker_requests_total{path,outcome,rule}` | broker | sustained `rule="I3"` denials: a node asking for pods it does not host |
| `svidlet_broker_vault_seconds{op}` | broker | p99 > 2 s |
| `svidlet_broker_token_cache{result}` | broker | hit ratio collapse after a `kid` retirement is expected; persisting is not |
| `oidc_publisher_last_success_timestamp` | control plane | older than 10 min |

---

## 16. Future work *(drafted)*

- **LSM credential protection.** A BPF-LSM layer that restricts which processes may open `tls.key` and `jwt/*` after issuance. Explicitly not on the issuance path (§3).
- **`PodCertificateRequest`** on 1.35+: the kubelet takes over key generation and mounting; the broker becomes the signer controller and keeps its rules.
- **TPM-bound broker credentials** (B3).
- **Pod-key proof on the token path for direct mode** beyond mTLS, e.g. DPoP-bound tokens where relying parties support them.

---

## 17. Open questions *(drafted)*

1. JWKS relay versus pushed keys for B1, per vendor-managed control plane.
2. Whether `exp ≤ certificate notAfter` (T5) should shorten tokens near certificate expiry or refuse and wait for the next renewal. The draft code shortens nothing: it refuses to serve a token whose `exp` exceeds the caller’s `notAfter`, and re-mints only if the role TTL fits.
3. Whether the broker should cache Pod objects through an informer from day one, or start with direct `GET`s (simpler, one API call per issuance) and move to an informer when the issuance rate warrants it. The initial implementation uses `GET`s behind a trait.
4. ES256 versus RS256 per relying party (§7.2).

---

## 18. Alternatives considered *(drafted)*

| Option | Verdict | Why |
| --- | --- | --- |
| Nodes sign directly against Vault (v0.1) | Replaced | Every node holds a credential that can mint any identity in its cluster, and every node is a Vault client. |
| Vault Transit signing broker-built JWTs | Fallback only | Transit signs arbitrary bytes, so one broker could forge tokens for every cluster (§6.1). Use only where the SPIFFE engine is unavailable, with one Transit key per cluster and per-cluster issuers, accepting the extra JWKS entries. |
| A token issuer with its own key pool (bootstrap roadmap Stage 2) | Rejected | Signing and rotation code of our own; a compromised issuer forges any subject in the trust domain. |
| Kubernetes ServiceAccount token issuers registered with relying parties | Rejected | One issuer per cluster to register everywhere; vendor-managed control planes cannot expose their issuers. |
| SPIRE | Rejected | Agent footprint; server and datastore per trust domain; its JWT keys live in its own server. |
| A Workload API socket | Non-goal | Files cover every SDK we care about without a socket into a node daemon. |
