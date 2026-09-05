# Svidlet

**A lightweight SPIFFE X.509 issuer for Kubernetes, in Rust.**

> **This is an experimental project, written to learn Rust.** It is not a better SPIFFE
> implementation than SPIRE or cert-manager's `csi-driver-spiffe`, and it is not trying
> to be — both are mature, and both do more. What this aims at is a narrower thing:
> lightweight, easy to deploy, and easy to maintain — one static binary, one DaemonSet,
> no control plane and no API-server dependency — for pod identity across multiple
> Kubernetes clusters. Read it in that spirit.

Svidlet gives pods short-lived X.509 certificates carrying a SPIFFE ID
(`spiffe://<trust-domain>/cluster/<cluster>/ns/<namespace>/sa/<serviceaccount>`)
so services can authenticate each other with mutual TLS at the application layer.

It is a single small Rust process per node, running as a CSI node plugin:

- the **kubelet** tells Svidlet which namespace and ServiceAccount a pod belongs to —
  identity is never derived from pod labels or annotations;
- the **private key** is generated on the node and lives only in tmpfs;
- a **PKI backend** signs the certificate — HashiCorp Vault PKI first, with a
  pluggable `Issuer` trait for other backends;
- the certificate is mounted **only into the containers that should hold it**,
  via a `csi` ephemeral volume that is allowed under restricted Pod Security Standards;
- optionally, **authorization policy** is published into the same volume and refreshed
  when it changes upstream — either streamed per identity from a policy backend, or
  pulled as a signed, content-addressed bundle with a staged ring rollout
  ([docs/POLICY.md](docs/POLICY.md)).

The SPIFFE ID layout is a template, not a constant — see [Identity shape](#identity-shape).

## Why another SPIFFE issuer

| | SPIRE agent | cert-manager csi-driver-spiffe | Svidlet |
|---|---|---|---|
| Processes per node | 1 (+ server) | 3 | 1 |
| Issuance path | agent ↔ server | 4 API-server writes per cert | 1 call to PKI backend |
| Multi-cluster | federation | separate trust domains + federation | single trust domain, cluster in path |
| Kubernetes version | any | any | 1.31+ |

Svidlet trades SPIRE's generality and cert-manager's independent approval layer for a
small footprint and an issuance path that never touches the API server.
The trust model is stated plainly in [docs/DESIGN.md](docs/DESIGN.md).

## Status

Implemented and covered by tests: kubelet registration,
`NodePublishVolume`/`NodeUnpublishVolume`, Vault PKI signing over three
authentication methods, customisable SPIFFE IDs, renewal with jitter, restart
recovery, trust-bundle refresh, policy bundle streaming, and Prometheus metrics.
Policy is distributed either way: streamed per identity over gRPC, or pulled as signed
OCI bundles with a staged ring rollout.

219 tests, ~88% line coverage, plus six integration tests that run against a real
Vault (`./hack/local-vault.sh`).

Not started: cloud IAM authentication, PKI backends other than Vault, and
`PodCertificateRequest` signer mode for Kubernetes 1.35+.

It has not been run on a production cluster. Treat it as working code that still
needs soak time.

## How it works

```
pod scheduled
   │
   ▼
kubelet ──NodePublishVolume(ns, sa, pod)──► svidlet          (one process per node)
                                              │
                                              ├─ render the SPIFFE ID from the template
                                              ├─ generate P-256 key       (never leaves the node)
                                              ├─ build CSR, URI SAN = the rendered ID
                                              ├─ POST pki/sign/spiffe-c ──► Vault
                                              │                            ├─ policy: this cluster's path only
                                              │                            └─ role: allowed_uri_sans pinned
                                              ├─ subscribe on the policy stream ──► policy backend (git)
                                              │                                     └─ pushes on change
                                              └─ publish tls.crt, tls.key, ca.crt, policy/ into a tmpfs
                                                 └─ renew at a random point in [50%, 70%] of the lifetime
```

The volume a workload sees:

```
/var/run/svid/
  tls.crt            leaf + intermediates
  tls.key            P-256 private key, mode 0640
  ca.crt             trust bundle, refreshed independently of the certificate
  policy/            one file per policy document   (only when a policy backend is configured)
  policy.revision    upstream revision, to stat instead of walking the directory
```

Everything under the volume is swapped atomically through a `..data` symlink, the
same way the kubelet publishes Secret volumes, so a reloading application never
reads a certificate that does not match its key or a half-written policy set.

Vault asserts "this certificate was requested by a node in cluster X". Svidlet asserts
"for this pod, the kubelet told me namespace N and ServiceAccount S" — and the kubelet
is already root on the node, so this adds no trust. Compromising one node means being
able to mint any identity **in that cluster**; cross-cluster impersonation is blocked
by Vault policy, not by the plugin.

**The AppRole credential is the weakest part of the design.** It is a shared bearer
secret in a Kubernetes Secret: whoever can read that Secret can mint any identity in
the cluster, from anywhere, until it is rotated. It proves possession of a secret, not
that the caller is a node. It stays the default because it is the only method that
works everywhere including bare metal, and it is simple enough to reason about in one
sentence — but where the environment allows it, use `SVIDLET_VAULT_AUTH=kubernetes`,
which proves the plugin's own ServiceAccount to Vault with no shared secret at all.
[docs/DESIGN.md](docs/DESIGN.md) states this in full.

## Identity shape

The SPIFFE ID is rendered from `SVIDLET_SPIFFE_ID_TEMPLATE`:

```
spiffe://{trust_domain}/cluster/{cluster}/ns/{namespace}/sa/{service_account}   (default)
spiffe://{trust_domain}/ns/{namespace}/sa/{service_account}                     (SPIRE shape)
spiffe://{trust_domain}/node/{node_name}/ns/{namespace}/pod/{pod_name}
```

Placeholders: `{trust_domain}`, `{cluster}`, `{namespace}`, `{service_account}`,
`{pod_name}`, `{pod_uid}`, `{node_name}`. A template is compiled at start-up — a bad
one stops the process rather than failing the first pod — and it both renders IDs and
parses them back, which is how restart recovery reads an identity out of a certificate
instead of keeping state on disk.

`SVIDLET_SPIFFE_ID_PATTERN` is a second, independent gate: an anchored regex every
issued ID must match. The template says what svidlet builds; the pattern says what it
is allowed to build. An ID that fails it is refused with `PermissionDenied` and never
sent to the PKI backend.

Values substituted into a template are restricted to `[A-Za-z0-9._-]`, so a
ServiceAccount named `x/ns/kube-system/sa/admin` cannot extend the path into somebody
else's identity.

## Policy

Two sources, behind one seam, writing to the same `policy/` directory. Most
deployments want one or the other.

| | gRPC stream | OCI bundle |
|---|---|---|
| Granularity | per SPIFFE ID | fleet-wide, one bundle per ring |
| Direction | backend pushes | node polls |
| Convergence | sub-second | one polling interval |
| Staged rollout | no | rings, bake time, freeze |
| Provenance | transport trust only | signed artifact, content-addressed |

A per-identity bundle from the stream takes precedence over the fleet bundle for that
identity. `SVIDLET_POLICY_ENABLED=false` switches off both.

### Pulled: signed OCI bundles with a ring rollout

Designed in [docs/POLICY.md](docs/POLICY.md). CI turns each reviewed commit into a
signed OCI artifact; nodes poll a small signed **rollout manifest** that assigns bundle
digests to **rings**, work out their own ring, and converge.

```toml
schema = 1
freeze = false               # the kill switch: halts every change, including rollbacks

[[ring]]
name = "canary"
match = { node_hash_percent = 1 }
bundle = "sha256:…a1"

[[ring]]
name = "all"
bundle = "sha256:…9f"        # everyone else stays here until promotion
```

Rings are evaluated top to bottom, first match wins. A node's bucket is
`SHA-256(cluster, node) mod 100`, so membership is stable across restarts and the *same*
nodes are the canary for every rollout — which is the point of a canary.

The trust chain is one signature:

```
trusted Ed25519 public key → rollout.toml signature → bundle digest → bundle bytes
```

Nodes hold only the public key, so verification is fully offline. Promotion is a Git
change; rollback is the same change in reverse and needs **no network**, because the
previous versions are still unpacked on the node.

Everything fails **stale, not open and not closed**. An unreachable registry, a bad
signature, a bundle that fails validation — in every case the node keeps what it has and
`svidlet_bundle_age_seconds` climbs. That gauge is what to alert on.

```sh
./hack/build-bundle.sh keygen                 # once per fleet
./hack/build-bundle.sh bundle ./policy/bundle # prints the digest for rollout.toml
./hack/build-bundle.sh rollout ./rollout.toml # signs and pushes
```

Extraction is deliberately narrow: the tar reader accepts regular files with ordinary
relative names and refuses everything else — absolute paths, `..`, symlinks, hard links,
device nodes, setuid bits. A malicious bundle cannot write outside its version directory.
The design's optional `selftest/` cases are **not** implemented; running code from a
downloaded artifact on every node is a large thing to add, and the design does not say
what a test case is.

### Streamed: per-identity policy over gRPC

Point `SVIDLET_POLICY_ENDPOINT` at a gRPC service implementing
[`proto/policy.proto`](crates/svidlet/proto/policy.proto) — typically a service fronting
a git repository. The node opens **one bidirectional stream**, subscribes to the
identities it hosts, and writes each bundle it receives into that workload's `policy/`
directory. Upstream changes are pushed and land in the volume without restarting the pod.

- Certificates do not depend on policy. If the backend is down, the certificate is
  still issued and the policy already on disk is left alone.
- `SVIDLET_POLICY_REQUIRED=true` inverts that: publishing waits
  `SVIDLET_POLICY_INITIAL_TIMEOUT` for a bundle and fails with `Unavailable` if none
  arrives, so a pod that would run unpoliced does not start.
- A document name containing a path separator is rejected outright rather than
  sanitised, and an update with no documents that is not explicitly marked `empty` is
  refused rather than silently clearing what is published.

`SVIDLET_POLICY_ENABLED=false` switches the whole feature off while leaving the
endpoint configured — no stream, no subscriptions, no policy directory, and no waiting
even if `SVIDLET_POLICY_REQUIRED` is set. That is the flag to use for local runs and
for bisecting whether the policy stream is involved in a problem: the manifest stays as
it is in production and one variable takes the backend out of the picture.

```sh
SVIDLET_POLICY_ENABLED=false cargo run -p svidlet     # no policy backend needed
```

## Try it

```sh
cargo test                  # 219 tests, no cluster and no Vault needed
./hack/coverage.sh          # coverage report; fails under 80%
./hack/bench-memory.sh      # resident memory under load

# Against a real Vault on this machine:
./hack/local-vault.sh start
eval "$(./hack/local-vault.sh env)"
cargo test -p svidlet-issue -- --ignored     # 6 tests against real Vault
./hack/local-vault.sh stop

./hack/kind-e2e.sh          # kind + dev Vault + DaemonSet + a workload, end to end
```

`cargo test` needs nothing external: a stub HTTP Vault covers the signing paths a real
Vault will not produce on demand (expired token, sealed server, a certificate for the
wrong identity), a real in-process gRPC server covers the policy stream including
reconnect and resubscribe, and a stub OCI registry covers the whole bundle rollout —
promotion, rollback without network, freeze, a manifest signed by the wrong key, a
bundle that does not match its signed digest, and a registry that goes away. The `--ignored` tests are the ones that need a real Vault:
that the CSR svidlet builds is one Vault actually signs, and that the per-cluster role
really refuses an identity outside its prefix.

`hack/kind-e2e.sh` asserts the whole path: a pod's `app` container gets a certificate
whose SPIFFE ID matches its ServiceAccount, its `sidecar` container cannot read that
certificate, and the volume is a real tmpfs on the node.

## Deploy

```sh
# One-time, per cluster. Prints the role ID and secret ID to configure.
VAULT_ADDR=… VAULT_TOKEN=… ./deploy/vault-bootstrap.sh example.org cluster-a

kubectl apply -f deploy/csidriver.yaml
kubectl apply -f deploy/daemonset.yaml     # then set the ConfigMap and Secret
```

Then give a workload an identity by declaring the volume and mounting it into
only the containers that should hold it — see [deploy/example-workload.yaml](deploy/example-workload.yaml):

```yaml
volumes:
  - name: svid
    csi:
      driver: csi.svidlet.io
      readOnly: true
```

`tls.key` is written mode `0640`, so a non-root workload needs `fsGroup` set; the
CSIDriver's `fsGroupPolicy: File` makes the kubelet apply it.

## Credentials

Nothing secret belongs in this repository, and `.gitignore` is written to make an
accidental commit hard rather than to tidy up afterwards.

| Secret | Where it lives | Never |
|---|---|---|
| Vault AppRole secret ID | a Kubernetes Secret, mounted at `SVIDLET_SECRET_ID_FILE` | in Git, in the image, in a ConfigMap |
| Vault token (dev only) | `.local-vault/`, written by `hack/local-vault.sh` | anywhere but a workstation |
| Bundle signing key (private) | Vault Transit, or a CI secret store | on a node, in Git — nodes only ever need the public half |
| Bundle signing key (public) | `SVIDLET_BUNDLE_PUBLIC_KEY`, a ConfigMap, or this repo | — it is safe to publish |

`.gitignore` therefore excludes `/.local-vault` and `/.bundle-keys` — the two
directories the local tooling writes real key material into — plus `*.key`, `*.p12`,
`*.pfx` and `secret-id`, which are the shapes that get dropped into a repository by
accident. Nothing in svidlet reads those paths; they are there so a stray copy cannot be
committed without noticing.

Two things follow from the design that are worth stating plainly:

- **The AppRole secret ID is the most valuable secret in the system.** Whoever can read
  it can mint any identity in that cluster, from anywhere, until it is rotated. This is
  the weakest part of the design and [docs/DESIGN.md](docs/DESIGN.md) says so at length;
  `SVIDLET_VAULT_AUTH=kubernetes` removes it entirely where Vault can validate
  ServiceAccount tokens.
- **Nodes never hold a signing key.** Bundle verification is offline against a public
  key, so compromising a node yields no ability to sign a bundle for anyone else.
  `hack/build-bundle.sh keygen` writes a private key to a local file because that is
  the right shape for a demo and the wrong shape for production, and the script says so
  in its header.

The manifests in `deploy/` carry `replace-me` placeholders rather than working values,
so applying them unedited fails loudly instead of running with a checked-in credential.

## Configuration

All configuration is environment variables, so one image and one manifest differ
between clusters only by a ConfigMap.

| Variable | Default | Meaning |
|---|---|---|
| `SVIDLET_TRUST_DOMAIN` | *required* | Trust domain in every SPIFFE ID |
| `SVIDLET_CLUSTER` | *required* | Cluster segment of the SPIFFE path |
| `NODE_NAME` | *required* | Node name, from `spec.nodeName` |
| `VAULT_ADDR` | *required* | Vault address |
| `SVIDLET_VAULT_AUTH` | `approle` | `approle`, `kubernetes` or `token` |
| `SVIDLET_ROLE_ID` | required for `approle` | AppRole role ID (not a secret) |
| `SVIDLET_SECRET_ID_FILE` | `/etc/svidlet/vault/secret-id` | Mounted secret ID; re-read on every login, so rotation needs no restart |
| `SVIDLET_VAULT_K8S_ROLE` | required for `kubernetes` | Vault role for Kubernetes auth |
| `SVIDLET_VAULT_K8S_MOUNT` | `kubernetes` | Kubernetes auth mount path |
| `SVIDLET_VAULT_TOKEN_FILE` | `/etc/svidlet/vault/token` | Token file for `SVIDLET_VAULT_AUTH=token` |
| `SVIDLET_SPIFFE_ID_TEMPLATE` | see [Identity shape](#identity-shape) | Shape of every issued SPIFFE ID |
| `SVIDLET_SPIFFE_ID_PATTERN` | — | Anchored regex every issued ID must match |
| `SVIDLET_POLICY_ENABLED` | `true` | Master switch. `false` ignores a configured endpoint entirely |
| `SVIDLET_POLICY_ENDPOINT` | — | gRPC policy backend; unset also disables policy |
| `SVIDLET_POLICY_REQUIRED` | `false` | Refuse to publish a volume until policy arrives |
| `SVIDLET_POLICY_INITIAL_TIMEOUT` | `10s` | How long publishing waits for the first bundle |
| `SVIDLET_POLICY_DIR` | `policy` | Directory inside the volume for policy documents |
| `SVIDLET_POLICY_CACERT` | — | PEM file for the policy backend's TLS certificate |
| `SVIDLET_BUNDLE_ROLLOUT_REF` | — | `registry/repo:tag` of the signed rollout manifest; setting it enables the pull source |
| `SVIDLET_BUNDLE_PUBLIC_KEY` / `_FILE` | required with the above | Trusted Ed25519 key, as base64, hex or PEM |
| `SVIDLET_BUNDLE_REPO` | the rollout's repo | Repository bundles are pulled from by digest |
| `SVIDLET_BUNDLE_POLL_INTERVAL` | `60s` | Manifest poll interval |
| `SVIDLET_BUNDLE_POLL_JITTER` | `30s` | Polls land at interval ± this |
| `SVIDLET_BUNDLE_DIR` | `/var/lib/svidlet/policy` | Node-local version cache |
| `SVIDLET_BUNDLE_KEEP_VERSIONS` | `2` | Superseded versions kept for a network-free rollback |
| `SVIDLET_BUNDLE_MAX_BYTES` | `10485760` | Refuse a bundle larger than this |
| `SVIDLET_BUNDLE_CACERT` | — | PEM file for the registry's TLS certificate |
| `SVIDLET_BUNDLE_TOKEN_FILE` | — | Bearer token for the registry; re-read per request |
| `VAULT_CACERT` | — | PEM file for a private Vault CA |
| `VAULT_NAMESPACE` | — | Vault Enterprise namespace |
| `SVIDLET_PKI_MOUNT` | `pki` | PKI mount path |
| `SVIDLET_PKI_ROLE` | `spiffe-$SVIDLET_CLUSTER` | PKI role to sign with |
| `SVIDLET_APPROLE_MOUNT` | `approle` | AppRole auth mount path |
| `SVIDLET_CERT_TTL` | `24h` | Requested certificate lifetime |
| `SVIDLET_RENEW_MIN_FRACTION` / `_MAX_` | `0.5` / `0.7` | Renewal jitter window, as a fraction of lifetime |
| `SVIDLET_RENEW_CHECK_INTERVAL` | `30s` | How often the renewal loop wakes |
| `SVIDLET_STARTUP_SPREAD` | `300s` | Window over which already-due renewals are spread after a restart |
| `SVIDLET_CA_REFRESH_INTERVAL` | `1h` | Trust-bundle refresh interval |
| `SVIDLET_KEY_MODE` / `SVIDLET_CERT_MODE` | `0640` / `0644` | File modes |
| `SVIDLET_TMPFS_SIZE` | `1m` | tmpfs `size=` per volume |
| `SVIDLET_METRICS_ADDR` | `0.0.0.0:9464` | Prometheus endpoint; empty disables |
| `SVIDLET_DRIVER_NAME` | `csi.svidlet.io` | CSI driver name |
| `SVIDLET_KUBELET_ROOT` | `/var/lib/kubelet` | Where restart recovery looks |
| `SVIDLET_LOG_LEVEL` | `info` | `error`, `warn`, `info`, `debug` |

Durations accept `30s`, `10m`, `24h`, `3d`, or a bare number of seconds. Every value is
validated at start-up: a bad template, regex, duration, file mode or log level stops
the process with a message naming the variable, rather than being silently ignored.

## Errors

Every failure carries a stable error code, used both in logs (`code=…`) and as a
Prometheus label. These are part of the interface — alert on them rather than on log text.

| Code | Meaning | Retried |
|---|---|---|
| `config` | Bad template, regex or credential path. Operator error. | no |
| `identity` | The pod's attributes cannot form a valid SPIFFE ID | no |
| `policy` | The ID is well formed but `SVIDLET_SPIFFE_ID_PATTERN` refuses it | no |
| `crypto` | Key generation or CSR construction failed | no |
| `transport` | The PKI backend could not be reached | yes |
| `backend_status` | Non-2xx from the PKI backend (429 and 5xx are retried) | some |
| `protocol` | The backend's answer had the wrong shape | no |
| `certificate` | Unparsable, or signed for the wrong identity | no |
| `auth` | The credential was rejected | yes |
| `io` | A local filesystem operation failed | yes |

The kubelet sees `InvalidArgument` for `identity`, `PermissionDenied` for `policy`,
`Unavailable` when required policy never arrives, and `Internal` otherwise — so
`kubectl describe pod` distinguishes "your pod spec is wrong" from "we are broken".

## Metrics

`GET :9464/metrics`, and `GET :9464/healthz` for the liveness probe. Neither is tied
to the PKI backend: a Vault outage must not restart nodes whose certificates are still
valid for hours.

Every label combination is exported from process start, including the zero ones, so a
`rate()` alert works before the first failure ever happens.

| Metric | Notes |
|---|---|
| `svidlet_certificates_issued_total{reason}` | `publish` and `renew` |
| `svidlet_issue_failures_total{reason,code}` | labelled by the codes above |
| `svidlet_issue_duration_seconds{reason}` | histogram, keygen through to on disk |
| `svidlet_certificates_active` | certificates this node is renewing |
| `svidlet_earliest_certificate_expiry_seconds` | **the one to alert on** |
| `svidlet_renewals_due` | deadlines passed but not yet renewed |
| `svidlet_volumes_recovered_total` | adopted after a restart, not re-issued |
| `svidlet_volumes_adoption_skipped_total` | non-zero means certificates are being re-issued that need not be |
| `svidlet_ca_refresh_total`, `…_failures_total` | trust bundle |
| `svidlet_policy_stream_connected` | 0 means policy changes have stopped arriving |
| `svidlet_policy_bundles_applied_total` | bundles written into a volume |
| `svidlet_policy_updates_rejected_total` | non-zero means the backend is sending something svidlet will not publish |
| `svidlet_bundle_version{digest,ring}` | always 1; which bundle and ring this node is on |
| `svidlet_bundle_age_seconds` | **alert on this** — the only signal that policy stopped moving |
| `svidlet_bundle_rejected_total{reason}` | `fetch`, `signature`, `malformed`, `rejected`, `config`, `io` |
| `svidlet_bundle_swap_total` | bundle changes applied |
| `svidlet_rollout_manifest_invalid_total` | unsigned, mis-signed or unparsable manifests |
| `svidlet_registry_fetch_errors_total` | failed registry requests |
| `svidlet_bundle_node_bucket` | this node's stable 0..100 position, so its ring is predictable |
| `svidlet_build_info{version,backend,auth}` | always 1 |

Alert on `svidlet_earliest_certificate_expiry_seconds`: renewal starts at half the
certificate's lifetime, so it only approaches zero after renewal has been failing for a
very long time.

## Footprint

Measured with `./hack/bench-memory.sh`, which runs the real release binary against a
real Vault and drives it over the real CSI protocol with `svidlet-bench` standing in for
the kubelet:

| Certificates on the node | Resident | Marginal cost per certificate |
|---|---|---|
| 0 (idle) | 2.2 MB | — |
| 100 | 3.4 MB | ~1.2 KB |
| 500 | 4.2 MB | ~1.7 KB |
| 2000 | 5.9 MB | ~1.9 KB |

That is inside the design's 5–8 MB target with room to spare: the design's planning
ceiling is 20–50 containers per node, where this sits at ~2.3 MB. The binary is ~2.5 MB,
statically linked against musl, with no API-server client and no sidecars.

Two caveats. These numbers are from macOS, where the volumes are plain directories rather
than tmpfs and RSS is accounted differently — treat them as an order of magnitude and
measure on a real node before quoting them to anyone. And the ~10/s publish rate the
benchmark reports is the dev-mode Vault and the sequential load generator, not svidlet;
it says nothing about issuance throughput.

The dependency tree is a compromise worth naming: the design says "no Tokio-heavy
dependency tree", but CSI is gRPC, and `tonic` brings `tokio`, `hyper` and `h2`. The
reactor is single-threaded with at most four blocking threads, and the metrics endpoint,
the logger and the TOML-adjacent plumbing are hand-rolled rather than pulled in. The
measurements above say that compromise cost less than feared.

Unsafe code is denied crate-wide. `svidlet-issue` is `#![forbid(unsafe_code)]`; the
plugin has exactly two `unsafe` blocks, both `libc` FFI for `mount`/`umount2`, each
`#[allow]`ed individually with a SAFETY note. A tmpfs cannot be mounted without them,
and shelling out to `mount(8)` would trade two audited lines for a process spawn.

## Layout

```
crates/
  svidlet/                CSI node plugin
    src/csi/              Identity, Node and kubelet-registration gRPC services
    src/issue.rs          Key → CSR → backend → files, shared by publish and renewal
    src/renew.rs          Renewal, trust-bundle refresh, policy apply and reaper loops
    src/policy/           Policy: the manager, the gRPC stream client
    src/policy/oci/       Signed OCI bundles: registry, rollout rings, verify, tar, store
    src/recover.rs        Rebuilding the renewal list from the kubelet's records
    src/volume.rs         tmpfs mounts and atomic publication of tls.crt/tls.key/ca.crt
    src/store.rs          Published volumes, renewal deadlines, backoff
    tests/e2e.rs          Publish → renew → recover → unpublish, against a real CA
    tests/rollout.rs      Bundle rollout against a stub registry: promote, roll back,
                          freeze, bad signature, offline, restart
    src/bin/svidlet-bench.rs  A load generator that stands in for the kubelet
  svidlet-issue/          Issuance library
    src/template.rs       SPIFFE ID templates and the operator's ID pattern
    src/issuer.rs         The PKI-engine seam
    src/auth.rs           The authentication seam, and the token cache every backend needs
    src/error.rs          The stable error-code taxonomy
    src/vault/            Vault PKI: HTTP, three auth methods, the issuer
deploy/                   CSIDriver, DaemonSet, example workload, Vault bootstrap
hack/local-vault.sh       A dev-mode Vault on this machine, configured for svidlet
hack/kind-e2e.sh          End-to-end check on kind against a dev Vault
hack/bench-memory.sh      Resident memory against a real Vault under real CSI load
hack/build-bundle.sh      What CI does: package, sign and push a bundle and rollout
hack/coverage.sh          Coverage report with an 80% floor
docs/DESIGN.md            Design document
docs/POLICY.md            Policy bundle distribution: rings, signing, rollout
```

`svidlet-issue` knows nothing about CSI or Kubernetes. It is the piece that survives the
migration to `PodCertificateRequest` signing on Kubernetes 1.35+, when the kubelet takes
over key generation and mounting and the node component is retired.

## License

Apache-2.0. See [LICENSE](LICENSE).
