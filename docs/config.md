# Svidlet — Configuration Reference

Everything that varies between clusters is an environment variable, so one image and one manifest differ only by a ConfigMap. `svidlet` and `svidlet-policy` run from the same image and share the ConfigMap via `envFrom`; each reads only the variables below its own tables, and nothing stops an operator from splitting the ConfigMap — the variables are simply names.

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
  - `SVIDLET_TOKEN_ISSUER` requires `SVIDLET_VAULT_AUTH=cert` — the issuer authenticates the node by its node certificate.
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
| `SVIDLET_CERT_TTL` | `6h` | Requested certificate lifetime. Renewal begins at half of it. Vault clamps it to the role's `max_ttl` (24h as bootstrapped). |
| `SVIDLET_CERT_SUBJECT` | `pod_name` | Which attribute becomes the Subject `CN`: `pod_name` \| `service_account` \| `none`. AWS IAM Roles Anywhere refuses an empty Subject and records the CN as `sourceIdentity`. Capped at 64 bytes; an attribute outside `[A-Za-z0-9_+=,.@-]` yields no CN rather than a failed issuance. Never a SAN. |
| `SVIDLET_CLOUD_PROFILE` | *(none)* | Comma-separated `aws`, `gcp`. Every issued certificate is checked against those clouds' acceptance rules; a violation is logged and counted in `svidlet_cloud_profile_findings_total{cloud,rule}`, and **never** blocks issuance. See [ROADMAP.md](ROADMAP.md) §4. |

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

### Vault — the PKI backend

| Variable | Default | Meaning |
|---|---|---|
| `VAULT_ADDR` | *(required)* | Vault address, `https://…`. |
| `VAULT_NAMESPACE` | *(none)* | Vault Enterprise namespace, if used. |
| `VAULT_CACERT` | *(none)* | PEM file with the CA that signed Vault's own serving certificate. |
| `SVIDLET_VAULT_TIMEOUT` | `10s` | Per-request timeout for Vault calls. |
| `SVIDLET_PKI_MOUNT` | `pki` | The PKI mount that holds the shared intermediate. |
| `SVIDLET_PKI_ROLE` | `spiffe-<cluster>` | The per-cluster role. Its `allowed_uri_sans` pins this cluster's SPIFFE prefix. |
| `SVIDLET_VAULT_AUTH` | `approle` | How the node authenticates to Vault: `cert` \| `kubernetes` \| `approle` \| `token`. Each `deploy/` variant sets it: `cert` in `with-node-bootstrap` (the node certificate svidlet-node-bootstrap issued, nothing shared), `kubernetes` in `standalone`, `approle` in `dev`. The code default stays `approle` so a bare `cargo run` against `hack/local-vault.sh` needs nothing extra; AppRole is a shared bearer secret and is for dev and kind clusters only. |

Per method:

| Variable | Default | Meaning |
|---|---|---|
| `SVIDLET_APPROLE_MOUNT` | `approle` | *(approle)* The auth mount. |
| `SVIDLET_ROLE_ID` | *(required for approle)* | The AppRole's role ID. Not a secret. |
| `SVIDLET_SECRET_ID_FILE` | `/etc/svidlet/vault/secret-id` | *(approle)* The secret ID, mounted from a Kubernetes Secret and **rotated without restart** — it is re-read on every login, and a 403 triggers exactly one re-login. |
| `SVIDLET_VAULT_K8S_MOUNT` | `kubernetes` | *(kubernetes)* The Kubernetes auth mount. |
| `SVIDLET_VAULT_K8S_ROLE` | *(required for kubernetes)* | The Vault role bound to the plugin's own ServiceAccount. |
| `SVIDLET_VAULT_K8S_TOKEN_FILE` | `/var/run/secrets/kubernetes.io/serviceaccount/token` | *(kubernetes)* The projected ServiceAccount token. |
| `SVIDLET_VAULT_CERT_MOUNT` | `cert` | *(cert)* The TLS certificate auth mount. |
| `SVIDLET_VAULT_CERT_ROLE` | `svidlet-<cluster>` | *(cert)* The cert role to log in against. Its `allowed_uri_sans` (`spiffe://<td>/cluster/<cluster>/node/*`) is what binds the node to this cluster. |
| `SVIDLET_NODE_CERT_FILE` | `/node/node.crt` | *(cert)* The node certificate svidlet-node-bootstrap writes — URI SAN `spiffe://<td>/cluster/<cluster>/node/<node>`, and `CN=<node>`, which Vault's cert method requires. Re-read on every login, so a renewal needs no restart; checked at start-up and reported in `svidlet_node_certificate_expiry_seconds`. [DEPLOY.md](DEPLOY.md) has the full interface. |
| `SVIDLET_NODE_KEY_FILE` | `/node/node.key` | *(cert)* Its private key, PEM. The seam a TPM-backed signer replaces. |
| `SVIDLET_VAULT_TOKEN_FILE` | `/etc/svidlet/vault/token` | *(token)* A static token file. Dev convenience, not a production method. |

### JWT-SVIDs — the token issuer

Unset, svidlet never contacts an issuer, and a volume that declares `audiences` fails to mount with `FailedPrecondition`. Set, each such volume gets `jwt/<name>` beside its certificate, minted at publish and re-minted with every renewal ([USAGE.md](USAGE.md) §3, "JWT-SVIDs").

| Variable | Default | Meaning |
|---|---|---|
| `SVIDLET_TOKEN_ISSUER` | *(none)* | The issuer's gRPC endpoint, `https://…`. Requires cert auth. |
| `SVIDLET_TOKEN_ISSUER_CACERT` | *(the trust bundle)* | PEM file with the CA that signed the issuer's serving certificate. By default the pod trust bundle (`ca.crt`) is used, since the issuer's certificate comes from the same Vault CA. |
| `SVIDLET_TOKEN_TIMEOUT` | `10s` | Connect and per-request timeout. |

The client certificate is the node certificate (`SVIDLET_NODE_CERT_FILE` / `SVIDLET_NODE_KEY_FILE`), re-read on every mint, and the connection is rebuilt when it or the CA changes. The issuer's own configuration is a TOML file, documented in [deploy/token-issuer/config.toml](../deploy/token-issuer/config.toml).

## `svidlet-policy` — the policy daemon

Reads the shared ConfigMap but never the Vault credential; the node certificate (and, on dev clusters, the AppRole Secret) is mounted only into the `svidlet` container.

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

## Logging (both processes)

| Variable | Default | Meaning |
|---|---|---|
| `SVIDLET_LOG_LEVEL` | `info` | `error` \| `warn` \| `info` \| `debug`. One level for the whole process. |

Events are real structured events via `tracing`: fields are named values (`spiffe_id`, `error`, `target`), not substrings of a message. The output is one line per event — RFC 3339 timestamp, level, message, `key=value` fields — on stderr, ANSI colours off. (A JSON option exists in `tracing-subscriber` but is deliberately not compiled in: the memory budget buys the fields, not the format options.)

---

## Where these live in the manifest

- **ConfigMap `svidlet`** — every `SVIDLET_*` and `VAULT_*` variable above, mounted via `envFrom` into both containers.
- **`emptyDir` `/node`** (memory-backed; `deploy/with-node-bootstrap` only) — the node certificate and key svidlet-node-bootstrap writes and renews, mounted `readOnly` **only into the `svidlet` container**. The policy daemon never sees it; that is the two-process split working.
- **Secret `svidlet-vault-approle`** (`deploy/dev` only) — the AppRole secret ID, at `/etc/svidlet/vault`, likewise only in the `svidlet` container. No other variant mounts or ships it.
- The example values and the GID chain are in [deploy/base/svidlet.yaml](../deploy/base/svidlet.yaml); each variant in `deploy/` sets only `SVIDLET_VAULT_AUTH` and what that method needs ([DEPLOY.md](DEPLOY.md)); what a workload does with the result is [USAGE.md](USAGE.md).
