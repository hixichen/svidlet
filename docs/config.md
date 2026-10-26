# Svidlet — Configuration Reference

Everything that varies between clusters is an environment variable, so one image and one manifest differ only by a ConfigMap and a Secret. `svidlet` and `svidlet-policy` run from the same image and share the ConfigMap via `envFrom`; each reads only the variables below its own tables, and nothing stops an operator from splitting the ConfigMap — the variables are simply names.

**Depends on:** [DESIGN.md](DESIGN.md) · [../svidlet-policy/authz-management-plane.md](../svidlet-policy/authz-management-plane.md)

---

## Rules every variable follows

- **Blank means unset.** A value that is empty or whitespace is treated as not present, and the default applies.
- **Durations** are `30s`, `10m`, `24h`, `3d`, or a bare number of seconds. A malformed duration stops the process at start-up — deliberately, so a typo costs a restart, not a misbehaving node.
- **File modes** are octal strings: `0640`, `0o644`, bounded to `0777`.
- **Booleans** accept `true/false`, `yes/no`, `1/0`, `on/off` (case-insensitive).
- **Validation happens at start-up.** A bad template, pattern, duration, or mode fails fast with the variable's name in the error. Two cross-variable rules are also enforced at start-up:
  - `SVIDLET_POLICY_GID` must not equal `SVIDLET_KEY_GID` — the policy daemon would be able to read every `tls.key` on the node.
  - `SVIDLET_POLICY_REQUIRED` requires `SVIDLET_POLICY_GID` — without it no bundle could ever be written and every pod start would fail.
- The **gID chain** must line up across manifest and workload: `SVIDLET_KEY_GID` = the workload's `runAsGroup`; `SVIDLET_POLICY_GID` = the `svidlet-policy` container's `runAsGroup`. See [USAGE.md](USAGE.md) §2.

---

## `svidlet` — the CSI plugin

### Identity

| Variable | Default | Meaning |
|---|---|---|
| `NODE_NAME` | *(required)* | This node's name. Usually injected with the `spec.nodeName` fieldRef. |
| `SVIDLET_TRUST_DOMAIN` | *(required)* | The SPIFFE trust domain, `spiffe://<this>/…`. |
| `SVIDLET_CLUSTER` | *(required)* | This cluster's name — the segment in the SPIFFE ID and the name of the Vault PKI role (`spiffe-<cluster>`). |
| `SVIDLET_DRIVER_NAME` | `csi.svidlet.io` | The CSI driver name. Must match the CSIDriver object; also shapes the socket paths. |
| `SVIDLET_SPIFFE_ID_TEMPLATE` | `spiffe://{trust_domain}/cluster/{cluster}/ns/{namespace}/sa/{service_account}` | Renders every issued SPIFFE ID. Placeholders: `{trust_domain} {cluster} {namespace} {service_account} {pod_name} {pod_uid} {node_name}`. Also parses IDs back — which is how restart recovery works. |
| `SVIDLET_SPIFFE_ID_PATTERN` | *(none)* | An anchored regex every issued ID must match — a second, independent gate on top of the template. An ID that fails is refused with `PermissionDenied`, never signed. |
| `SVIDLET_CERT_TTL` | `24h` | Requested certificate lifetime. Renewal begins at half of it. |

### Certificates and renewal

| Variable | Default | Meaning |
|---|---|---|
| `SVIDLET_RENEW_MIN_FRACTION` | `0.5` | Renewal starts no earlier than this fraction of the lifetime. |
| `SVIDLET_RENEW_MAX_FRACTION` | `0.7` | …and no later. Must satisfy `0 < min ≤ max < 1`. |
| `SVIDLET_RENEW_CHECK_INTERVAL` | `30s` | How often the renewal loop wakes. |
| `SVIDLET_STARTUP_SPREAD` | `300s` | Certificates already due on restart are spread over this window, so an upgrade is not a signing storm. |
| `SVIDLET_CA_REFRESH_INTERVAL` | `1h` | How often `ca.crt` is refreshed from the PKI backend. |
| `SVIDLET_READOPT_INTERVAL` | `60s` | How often restart recovery re-runs. A volume that could not be adopted the first time is never re-published by the kubelet, so without this loop its certificate would expire under a running pod. |

### Sockets and host paths

| Variable | Default | Meaning |
|---|---|---|
| `SVIDLET_KUBELET_ROOT` | `/var/lib/kubelet` | Where the kubelet's records live; the source for restart recovery. |
| `SVIDLET_CSI_SOCKET` | `<kubelet-root>/plugins/<driver>/csi.sock` | The CSI socket, as this process sees it. |
| `SVIDLET_ADVERTISED_ENDPOINT` | the CSI socket path | The same socket as the **kubelet** sees it. Differs only when the hostPath is remapped. |
| `SVIDLET_REGISTRATION_SOCKET` | `<kubelet-root>/plugins_registry/<driver>-reg.sock` | The registration socket the kubelet polls. |
| `SVIDLET_VOLUMES_DIR` | `/var/lib/svidlet/volumes` | The exposure farm: one bind mount per published volume, and the only hostPath `svidlet-policy` sees. |

### Volume files

| Variable | Default | Meaning |
|---|---|---|
| `SVIDLET_TMPFS_SIZE` | `1m` | The `size=` option for each volume's tmpfs. Must cover `tls.*`, `ca.crt`, and one copy of the policy bundle. |
| `SVIDLET_KEY_MODE` | `0640` | Mode for `tls.key`. |
| `SVIDLET_KEY_GID` | *(none)* | Group owning `tls.key` — set to the workload's `runAsGroup` so a non-root workload can read its own key. |
| `SVIDLET_CERT_MODE` | `0644` | Mode for `tls.crt` and `ca.crt`. |

### The policy gate (all `svidlet` knows about policy)

| Variable | Default | Meaning |
|---|---|---|
| `SVIDLET_POLICY_REQUIRED` | `false` | `true`: publishing waits for `policy.revision` and fails the pod start with `Unavailable` if none arrives within the timeout. Requires `SVIDLET_POLICY_GID`. |
| `SVIDLET_POLICY_INITIAL_TIMEOUT` | `10s` | How long that wait lasts. |
| `SVIDLET_POLICY_GID` | *(none)* | The group that may write the policy chain into a published volume — set it to the `svidlet-policy` container's `runAsGroup`. Setting it is what switches on the exposure farm and the group-writable tmpfs root. Must differ from `SVIDLET_KEY_GID`. |

### Issuer: Vault directly, or the broker (v0.2)

| Variable | Default | Meaning |
|---|---|---|
| `SVIDLET_ISSUER` | `vault` | `vault`: sign directly against Vault with the variables below (v0.1). `broker`: certificates and tokens come from `svidlet-broker` and the node holds no Vault credential ([DESIGN.md](DESIGN.md) §5–§6). The Vault variables are then not read. |
| `SVIDLET_BROKER_URL` | `https://svidlet-broker.svidlet-system.svc:8443` | Certificate port. |
| `SVIDLET_BROKER_TOKEN_URL` | `https://svidlet-broker.svidlet-system.svc:8444` | Token port (mTLS with each pod's own SVID). |
| `SVIDLET_BROKER_CACERT` | `/etc/svidlet/broker/ca.crt` | Bundle that signed the broker's serving certificate. |
| `SVIDLET_BROKER_TOKEN_FILE` | `/var/run/secrets/svidlet/broker/token` | The node's own projected token, audience `svidlet-broker`; re-read on every request. |
| `SVIDLET_BROKER_AUDIENCE` | `svidlet-broker` | Audience of the pod token in the CSIDriver's `tokenRequests`. |
| `SVIDLET_BROKER_TIMEOUT` | `10s` | Per-request timeout. |
| `SVIDLET_JWT_ENABLED` | `true` | Fetch JWT-SVIDs into `jwt/<alias>`. |
| `SVIDLET_JWT_REFRESH_INTERVAL` | `15m` | How often each volume checks in for tokens. The broker answers from cache, so this is cheap; it bounds how long an emergency key rotation takes to reach pods. |

### Vault — the PKI backend

| Variable | Default | Meaning |
|---|---|---|
| `VAULT_ADDR` | *(required)* | Vault address, `https://…`. |
| `VAULT_NAMESPACE` | *(none)* | Vault Enterprise namespace, if used. |
| `VAULT_CACERT` | *(none)* | PEM file with the CA that signed Vault's own serving certificate. |
| `SVIDLET_VAULT_TIMEOUT` | `10s` | Per-request timeout for Vault calls. |
| `SVIDLET_PKI_MOUNT` | `pki` | The PKI mount that holds the shared intermediate. |
| `SVIDLET_PKI_ROLE` | `spiffe-<cluster>` | The per-cluster role. Its `allowed_uri_sans` pins this cluster's SPIFFE prefix. |
| `SVIDLET_VAULT_AUTH` | `approle` | How the node authenticates to Vault: `approle` \| `kubernetes` \| `token`. Prefer `kubernetes` where Vault can validate ServiceAccount tokens — AppRole is a shared bearer secret and the weakest part of the design. |

Per method:

| Variable | Default | Meaning |
|---|---|---|
| `SVIDLET_APPROLE_MOUNT` | `approle` | *(approle)* The auth mount. |
| `SVIDLET_ROLE_ID` | *(required for approle)* | The AppRole's role ID. Not a secret. |
| `SVIDLET_SECRET_ID_FILE` | `/etc/svidlet/vault/secret-id` | *(approle)* The secret ID, mounted from a Kubernetes Secret and **rotated without restart** — it is re-read on every login, and a 403 triggers exactly one re-login. |
| `SVIDLET_VAULT_K8S_MOUNT` | `kubernetes` | *(kubernetes)* The Kubernetes auth mount. |
| `SVIDLET_VAULT_K8S_ROLE` | *(required for kubernetes)* | The Vault role bound to the plugin's own ServiceAccount. |
| `SVIDLET_VAULT_K8S_TOKEN_FILE` | `/var/run/secrets/kubernetes.io/serviceaccount/token` | *(kubernetes)* The projected ServiceAccount token. |
| `SVIDLET_VAULT_TOKEN_FILE` | `/etc/svidlet/vault/token` | *(token)* A static token file. Dev convenience, not a production method. |

## `svidlet-policy` — the policy daemon

Reads the shared ConfigMap but never the Vault credential; the Secret is mounted only into the `svidlet` container.

### The master switch and the two sources

The two sources are **mutually exclusive** — `SVIDLET_POLICY_ENDPOINT` and `SVIDLET_BUNDLE_ROLLOUT_REF` both set is a start-up error. The stream is transport-trusted while bundles are signed; a node never answers to both. With `SVIDLET_POLICY_ENABLED=false` both may stay configured, inert.

| Variable | Default | Meaning |
|---|---|---|
| `SVIDLET_POLICY_ENABLED` | `true` | The master switch. `false` ignores both sources entirely — the flag to use for local runs and bisecting whether policy is involved in a problem. |
| `SVIDLET_POLICY_ENDPOINT` | *(none)* | gRPC endpoint of the policy backend ([../svidlet-policy/POLICY_STORE_BACKEND.md](../svidlet-policy/POLICY_STORE_BACKEND.md)). Unset means no stream. |
| `SVIDLET_POLICY_CACERT` | *(none)* | CA for the backend's serving certificate. |
| `SVIDLET_POLICY_TOKEN_FILE` | *(none)* | Bearer token for the backend, if it wants one. |
| `SVIDLET_POLICY_RECONNECT_BACKOFF` | `1s` | First reconnection delay; doubles up to a minute. |
| `SVIDLET_VOLUMES_DIR` | `/var/lib/svidlet/volumes` | The exposure farm — the daemon's whole view of the node's volumes. Must match `svidlet`'s. |

### The OCI bundle source

Setting `SVIDLET_BUNDLE_ROLLOUT_REF` switches this source on, and a trusted key becomes mandatory.

| Variable | Default | Meaning |
|---|---|---|
| `SVIDLET_BUNDLE_ROLLOUT_REF` | *(none)* | `registry/repository:tag` of the signed rollout manifest. |
| `SVIDLET_BUNDLE_PUBLIC_KEY` | *(one of the two is required)* | The fleet's Ed25519 public key, inline PEM. |
| `SVIDLET_BUNDLE_PUBLIC_KEY_FILE` | *(one of the two is required)* | …or the same key from a file. |
| `SVIDLET_BUNDLE_REPO` | the rollout ref's own repository | Where bundles are pulled by digest. |
| `SVIDLET_BUNDLE_CACERT` | *(none)* | CA for a registry with a private certificate. |
| `SVIDLET_BUNDLE_TOKEN_FILE` | *(none)* | Bearer token for the registry, re-read on every request. |
| `SVIDLET_BUNDLE_TIMEOUT` | `30s` | Per-request timeout for registry calls. |
| `SVIDLET_BUNDLE_POLL_INTERVAL` | `60s` | Poll cadence, `±` the jitter below. |
| `SVIDLET_BUNDLE_POLL_JITTER` | `30s` | Spread so a fleet does not poll in lockstep. |
| `SVIDLET_BUNDLE_DIR` | `/var/lib/svidlet/policy` | The node-local cache: `versions/`, `current`, `state.json`. |
| `SVIDLET_BUNDLE_KEEP_VERSIONS` | `2` | Superseded versions kept unpacked, so a rollback needs no network. |
| `SVIDLET_BUNDLE_MAX_BYTES` | `1048576` (1 MiB) | Refuse a bundle larger than this, unpacked. The per-pod copy costs `bundle size × pods on the node` of tmpfs — keep bundles small. |
| `SVIDLET_BUNDLE_FULL_FETCH_EVERY` | `60` | Every Nth poll fetches the manifest without its ETag, so the `sequence`/`valid_until` freshness check cannot be hidden behind a cache answering 304. `0` disables the full fetch. |

### Daemon behaviour

| Variable | Default | Meaning |
|---|---|---|
| `SVIDLET_POLICY_SCAN_INTERVAL` | `5s` | How often the farm is rescanned for new volumes. |
| `SVIDLET_POLICY_FILE_MODE` | `0644` | Mode for policy documents. They are not secret. |
| `SVIDLET_POLICY_METRICS_ADDR` | `0.0.0.0:9465` | The daemon's own Prometheus endpoint. |
| `SVIDLET_METRICS_ADDR` | `0.0.0.0:9464` | The plugin's Prometheus endpoint. |

## `svidlet-broker` — the per-cluster broker (v0.2)

Runs as a Deployment, not on workload nodes. See [DESIGN.md](DESIGN.md) §5–§7 for the rules it enforces.

| Variable | Default | Meaning |
|---|---|---|
| `SVIDLET_CLUSTER` | *(required)* | I2: the cluster this broker serves. Never taken from a request. |
| `SVIDLET_TRUST_DOMAIN` | *(required)* | |
| `SVIDLET_SPIFFE_ID_TEMPLATE` / `SVIDLET_SPIFFE_ID_PATTERN` | as for the node | I7. Must render what the node expects; a mismatch is refused. |
| `SVIDLET_BROKER_SIGN_ADDR` | `0.0.0.0:8443` | Certificate port. |
| `SVIDLET_BROKER_TOKEN_ADDR` | `0.0.0.0:8444` | Token port, client certificates required. |
| `SVIDLET_BROKER_METRICS_ADDR` | `0.0.0.0:9466` | `/metrics` and `/healthz`, plain HTTP. Empty disables. |
| `SVIDLET_BROKER_TLS_CERT` / `_KEY` | `/etc/svidlet/tls/tls.{crt,key}` | Serving certificate, re-read every 30 s. |
| `SVIDLET_BROKER_CLIENT_CA` | `/etc/svidlet/trust/ca.crt` | T1: the bundle a caller's SVID must chain to. Read at start-up. |
| `SVIDLET_BROKER_BUNDLE` | the client CA | Served at `GET /v1/bundle` and returned as `ca.crt`. |
| `SVIDLET_CATALOG` | `/etc/svidlet/catalog/catalog.toml` | The catalog (§12). Reloaded every 30 s; an invalid new version is ignored and logged. |
| `SVIDLET_BROKER_AUDIENCE` | `svidlet-broker` | Audience required of node and pod tokens. |
| `SVIDLET_NODE_NAMESPACE` / `SVIDLET_NODE_SERVICE_ACCOUNT` / `SVIDLET_NODE_DAEMONSET` | `svidlet-system` / `svidlet-node` / `svidlet-node` | Who may call as a node. |
| `SVIDLET_DENIED_NAMESPACES` | `kube-system,kube-public,kube-node-lease,svidlet-system` | I8. |
| `SVIDLET_CERT_TTL` / `SVIDLET_CERT_MAX_TTL` | `48h` / `48h` | I11. |
| `SVIDLET_NODE_RATE_PER_MINUTE` | `120` | I10: certificates per node per minute. `0` disables. |
| `SVIDLET_NODE_IDENTITIES_PER_HOUR` | `500` | I10: distinct identities per node per hour. Renewals of an identity already counted are always allowed. |
| `SVIDLET_MINT_RATE_PER_MINUTE` | `60` | T7: Vault mints per identity per minute. |
| `SVIDLET_JWKS_URL` | *(Vault's own)* | T5/T6: the public JWKS relying parties fetch. Set it, so "published" means what relying parties see. |
| `SVIDLET_JWKS_REFRESH` | `60s` | |
| `VAULT_ADDR`, `VAULT_NAMESPACE`, `VAULT_CACERT`, `SVIDLET_VAULT_TIMEOUT` | | As for the node. |
| `SVIDLET_PKI_MOUNT` / `SVIDLET_PKI_ROLE` | `pki_int` / `spiffe-<cluster>` | |
| `SVIDLET_SPIFFE_MOUNT` | `spiffe` | Vault's SPIFFE secrets engine. |
| `SVIDLET_BROKER_VAULT_AUTH` | `jwt` | `jwt` (B1), `approle` (B2) or `token` (development). |
| `SVIDLET_BROKER_VAULT_JWT_MOUNT` / `_ROLE` / `SVIDLET_BROKER_VAULT_TOKEN_FILE` | `k8s-<cluster>` / `svidlet-broker` / `/var/run/secrets/svidlet/vault/token` | B1. |
| `SVIDLET_BROKER_ROLE_ID` / `SVIDLET_BROKER_SECRET_ID_FILE` / `SVIDLET_BROKER_APPROLE_MOUNT` | — / `/etc/svidlet/vault/secret-id` / `approle` | B2. |
| `SVIDLET_KUBE_API`, `SVIDLET_KUBE_CACERT`, `SVIDLET_KUBE_TOKEN_FILE`, `SVIDLET_KUBE_TIMEOUT` | in-cluster defaults, `5s` | |

## `oidc-publisher` and `svidlet-catalog`

`oidc-publisher` (§8) reads `VAULT_ADDR`, `VAULT_CACERT`, `VAULT_NAMESPACE`, `SVIDLET_SPIFFE_MOUNT`, `OIDC_ISSUER` (e.g. `https://oidc.corp.example/v1/spiffe`), `OIDC_OUT_DIR` and `OIDC_INTERVAL` (`60s`; `0` runs once and exits non-zero if it refused to publish). It writes `<OIDC_OUT_DIR>/<issuer path>/.well-known/{openid-configuration,keys}` only after checking the issuer and every key; a sidecar syncs the directory to the bucket with `Cache-Control: max-age=300`.

`svidlet-catalog lint|policy|roles <catalog.toml> [cluster]` lints the catalog and prints the per-cluster Vault policy (§7.3) and the `vault write spiffe/role/…` commands (§7.2).

## Logging (both processes)

| Variable | Default | Meaning |
|---|---|---|
| `SVIDLET_LOG_LEVEL` | `info` | `error` \| `warn` \| `info` \| `debug`. One level for the whole process. |

Events are real structured events via `tracing`: fields are named values (`spiffe_id`, `error`, `target`), not substrings of a message. The output is one line per event — RFC 3339 timestamp, level, message, `key=value` fields — on stderr, ANSI colours off. (A JSON option exists in `tracing-subscriber` but is deliberately not compiled in: the memory budget buys the fields, not the format options.)

---

## Where these live in the manifest

- **ConfigMap `svidlet`** — every `SVIDLET_*` and `VAULT_*` variable above, mounted via `envFrom` into both containers.
- **Secret `svidlet-vault-approle`** — the AppRole secret ID, mounted `readOnly` at `/etc/svidlet/vault` **only into the `svidlet` container**. The policy daemon never sees it; that is the two-process split working.
- The example values and the GID chain are in [deploy/daemonset.yaml](../deploy/daemonset.yaml); what a workload does with the result is [USAGE.md](USAGE.md).
