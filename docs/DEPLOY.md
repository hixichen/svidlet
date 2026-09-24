# Deploying svidlet

svidlet deploys on its own, or together with
[svidlet-node-bootstrap](https://github.com/hixichen/svidlet-node-bootstrap), which attests each
node and gives it a certificate to authenticate to Vault with. The two differ only in how a node
proves itself to Vault; the DaemonSet, the CSIDriver, the volumes workloads mount and every
certificate svidlet issues are the same.

**Depends on:** [DESIGN.md](DESIGN.md) · [ROADMAP.md](ROADMAP.md) §3 · [config.md](config.md)

---

## Choosing a variant

| | `deploy/standalone` | `deploy/with-node-bootstrap` | `deploy/dev` |
|---|---|---|---|
| Node authenticates with | the svidlet ServiceAccount token (Vault Kubernetes auth) | its own node certificate (Vault cert auth) | an AppRole secret ID |
| What Vault can tell apart | clusters | nodes | clusters |
| Credential bound to hardware | no | yes, on TPM nodes (Tier A/B) | no |
| Something shared to steal | no | no | yes: the secret ID works from anywhere |
| Extra moving parts | a TokenReview binding | step-ca, the EK inventory, two containers in the pod | a Secret |
| Use it for | clusters without node attestation | production on rented hosts | kind and local clusters only |

```sh
kubectl apply -k deploy/standalone            # or: make deploy
kubectl apply -k deploy/with-node-bootstrap   # or: make deploy VARIANT=with-node-bootstrap
```

`deploy/base` holds everything the variants share and is not deployable by itself.
`deploy/components/node-bootstrap` is a kustomize component, so an overlay of your own can
include it too. `make manifests` renders every variant and validates it against the Kubernetes
1.31 API.

Each variant has a matching Vault configuration, written by `deploy/vault-bootstrap.sh`:

```sh
# deploy/standalone: Vault reviews svidlet's token against this cluster's API server.
AUTH=kubernetes K8S_HOST=https://api.cluster-a.internal:6443 K8S_CA_FILE=cluster-a-ca.crt \
  ./deploy/vault-bootstrap.sh example.org cluster-a

# deploy/with-node-bootstrap: Vault trusts the step-ca root that issues node certificates.
AUTH=cert NODE_CA_FILE=step-ca-root.pem ./deploy/vault-bootstrap.sh example.org cluster-a
```

Both leave the PKI role — which pins the cluster's SPIFFE prefix — exactly as it is. Moving a
cluster from standalone to node bootstrap is a Vault auth role and a `kubectl apply -k`; no
workload notices.

## With node bootstrap: the interface

svidlet does not attest nodes and contains no TPM logic. svidlet-node-bootstrap does that, in
two containers in svidlet's own pod, and hands over a certificate through a shared volume. This
is what each side can rely on.

### What node bootstrap provides

| | |
|---|---|
| Volume | `emptyDir` with `medium: Memory`, mounted at `/node` — read-write in the bootstrap containers, read-only in `svidlet`, absent from `svidlet-policy` |
| `/node/node.crt` | PEM; the node certificate first, then any intermediates |
| `/node/node.key` | PEM private key for it |
| URI SAN | exactly one: `spiffe://<trust-domain>/cluster/<cluster>/node/<node-name>`, `<node-name>` being `spec.nodeName` |
| Subject | `CN=<node-name>`. **Required**: Vault's cert auth method names the login's entity alias after the CN and refuses a certificate without one |
| Key usage | `digitalSignature`; extended key usage `clientAuth` — it is a TLS client certificate |
| Lifetime | at most 24 hours, renewed well before it ends |
| Ordering | `node-enroll` runs as an init container and exits only once both files are in place; `node-renew` is a native sidecar (`restartPolicy: Always`) |
| Replacement | atomic: write both files beside the old ones, then rename, so a reader never sees a certificate with the wrong key |

The component in `deploy/components/node-bootstrap` wires exactly this: the volume, the two
containers, the environment they read (`NODE_NAME`, `SVIDLET_TRUST_DOMAIN`, `SVIDLET_CLUSTER`
from svidlet's ConfigMap; `STEP_CA_URL`, `STEP_FINGERPRINT`, `STEPPATH` from
`svidlet-node-bootstrap`'s), and a projected ServiceAccount token with audience `step-ca` for
nodes without a TPM. The container images and arguments are svidlet-node-bootstrap's to define;
the component follows them.

### What svidlet does with it

- **Logs in with it.** `SVIDLET_VAULT_AUTH=cert`, with the defaults `SVIDLET_NODE_CERT_FILE=/node/node.crt`
  and `SVIDLET_NODE_KEY_FILE=/node/node.key`. Vault tokens last an hour; each new login re-reads
  both files, so a renewal is picked up without a restart and without coordination.
- **Checks it at start-up.** svidlet logs whether the certificate names *this* node in *this*
  cluster, carries a CN and is unexpired. Vault refuses a certificate for another cluster, but it
  cannot tell one node of a cluster from another — this check is the only place that mismatch is
  seen. A missing file is logged as "waiting for node bootstrap", not treated as fatal: a node
  whose bootstrap is late keeps serving the certificates it already published.
- **Reports its expiry.** `svidlet_node_certificate_expiry_seconds` is read from the file on every
  scrape. It falling towards zero means renewal has stopped; alert on it the way you alert on
  `svidlet_earliest_certificate_expiry_seconds`.
- **Survives a restart of the pod.** When enrolment has to start again — a certificate expired
  during a long outage, or a revoked node — the pod restarts. svidlet adopts every certificate
  already published on the node rather than re-issuing them, so this costs nothing to running
  workloads.

### What neither side does

- svidlet never reads the TPM, the EK inventory or step-ca. The node key is a PEM file today;
  a TPM-resident key needs a signer in its place (ROADMAP.md §3.3), which will be a change to
  the key half of this interface only.
- svidlet-node-bootstrap never talks to Vault's PKI or sees a workload key.
- `svidlet-policy` never sees `/node`.

## Standalone

Every node presents the same ServiceAccount token, so Vault authorizes the cluster, not the
node, and the credential is not bound to hardware. Nothing shared sits in the cluster, though:
the token is short-lived, projected per pod, and useless outside the cluster's own trust.

`deploy/standalone` adds one ClusterRoleBinding, to `system:auth-delegator`. svidlet itself still
never calls the API server; Vault does, reviewing svidlet's token with that same token, as a
Vault outside the cluster has to. `vault-bootstrap.sh` sets `disable_local_ca_jwt=true` so a
Vault running inside the cluster behaves the same way.

## Development

`deploy/dev` uses AppRole: a secret ID in a Kubernetes Secret that anyone who can read it can use
from anywhere. It exists because a kind cluster has neither a registration CA nor a Vault that
can review its tokens. `hack/kind-e2e.sh` runs any variant end to end against an in-cluster Vault;
for `with-node-bootstrap` it stands a busybox copy step in for the bootstrap containers, with
Vault issuing the node certificate:

```sh
make e2e                                 # dev
make e2e VARIANT=standalone
make e2e VARIANT=with-node-bootstrap
```
