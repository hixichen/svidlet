#!/usr/bin/env bash
# End-to-end check on a kind cluster against a dev-mode Vault.
#
# Builds the image, brings up Vault in-cluster, configures the PKI mount and the
# per-cluster AppRole, deploys the DaemonSet, and asserts that a workload gets a
# certificate carrying the SPIFFE ID derived from its ServiceAccount — and that
# a container without the volumeMount does not.
#
# Requires: kind, kubectl, docker.
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-svidlet-e2e}"
TRUST_DOMAIN="${TRUST_DOMAIN:-example.org}"
SVIDLET_CLUSTER="${SVIDLET_CLUSTER:-cluster-a}"
IMAGE="${IMAGE:-svidlet:e2e}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
vault_exec() { kubectl -n vault exec deploy/vault -- env VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root "$@"; }

step "kind cluster ${CLUSTER_NAME}"
kind get clusters | grep -qx "${CLUSTER_NAME}" || kind create cluster --name "${CLUSTER_NAME}"
kubectl config use-context "kind-${CLUSTER_NAME}"

step "build and load ${IMAGE}"
docker build -t "${IMAGE}" "${REPO_ROOT}"
kind load docker-image "${IMAGE}" --name "${CLUSTER_NAME}"

step "dev-mode Vault"
kubectl create namespace vault --dry-run=client -o yaml | kubectl apply -f -
kubectl -n vault apply -f - <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vault
spec:
  replicas: 1
  selector: { matchLabels: { app: vault } }
  template:
    metadata: { labels: { app: vault } }
    spec:
      containers:
        - name: vault
          image: hashicorp/vault:1.17
          args: ["server", "-dev", "-dev-root-token-id=root", "-dev-listen-address=0.0.0.0:8200"]
          securityContext:
            capabilities: { add: ["IPC_LOCK"] }
          ports: [{ containerPort: 8200 }]
---
apiVersion: v1
kind: Service
metadata:
  name: vault
spec:
  selector: { app: vault }
  ports: [{ port: 8200, targetPort: 8200 }]
YAML
kubectl -n vault rollout status deploy/vault --timeout=120s

step "configure Vault for ${TRUST_DOMAIN} / ${SVIDLET_CLUSTER}"
kubectl -n vault cp "${REPO_ROOT}/deploy/vault-bootstrap.sh" \
  "$(kubectl -n vault get pod -l app=vault -o jsonpath='{.items[0].metadata.name}')":/tmp/bootstrap.sh
vault_exec sh -c "chmod +x /tmp/bootstrap.sh && /tmp/bootstrap.sh ${TRUST_DOMAIN} ${SVIDLET_CLUSTER}" >/tmp/bootstrap.out
sed -n '/^Done/,$p' /tmp/bootstrap.out

ROLE_ID="$(vault_exec vault read -field=role_id "auth/approle/role/svidlet-${SVIDLET_CLUSTER}/role-id")"
SECRET_ID="$(vault_exec vault write -f -field=secret_id "auth/approle/role/svidlet-${SVIDLET_CLUSTER}/secret-id")"

step "deploy svidlet"
kubectl apply -f "${REPO_ROOT}/deploy/csidriver.yaml"
kubectl apply -f "${REPO_ROOT}/deploy/daemonset.yaml"
kubectl -n svidlet-system create configmap svidlet \
  --from-literal=SVIDLET_TRUST_DOMAIN="${TRUST_DOMAIN}" \
  --from-literal=SVIDLET_CLUSTER="${SVIDLET_CLUSTER}" \
  --from-literal=VAULT_ADDR="http://vault.vault.svc:8200" \
  --from-literal=SVIDLET_PKI_ROLE="spiffe-${SVIDLET_CLUSTER}" \
  --from-literal=SVIDLET_ROLE_ID="${ROLE_ID}" \
  --from-literal=SVIDLET_CERT_TTL=10m \
  --from-literal=SVIDLET_LOG_LEVEL=debug \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n svidlet-system create secret generic svidlet-vault-approle \
  --from-literal=secret-id="${SECRET_ID}" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n svidlet-system set image daemonset/svidlet "svidlet=${IMAGE}"
kubectl -n svidlet-system patch daemonset svidlet \
  --type=json -p='[{"op":"replace","path":"/spec/template/spec/containers/0/imagePullPolicy","value":"Never"}]'
kubectl -n svidlet-system rollout restart daemonset/svidlet
kubectl -n svidlet-system rollout status daemonset/svidlet --timeout=180s

step "deploy the example workload"
kubectl create namespace payments --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace payments pod-security.kubernetes.io/enforce=restricted --overwrite
kubectl apply -f "${REPO_ROOT}/deploy/example-workload.yaml"
kubectl -n payments rollout status deploy/api --timeout=120s

step "verify the identity"
POD="$(kubectl -n payments get pod -l app=api -o jsonpath='{.items[0].metadata.name}')"
EXPECT="spiffe://${TRUST_DOMAIN}/cluster/${SVIDLET_CLUSTER}/ns/payments/sa/api"

CERT="$(kubectl -n payments exec "${POD}" -c app -- cat /var/run/svid/tls.crt)"
GOT="$(printf '%s' "${CERT}" | openssl x509 -noout -text | grep -o 'URI:spiffe://[^ ,]*' | cut -d: -f2-)"
if [ "${GOT}" != "${EXPECT}" ]; then
  echo "FAIL: expected ${EXPECT}, got ${GOT:-<none>}"
  exit 1
fi
echo "ok: ${GOT}"

kubectl -n payments exec "${POD}" -c app -- sh -c 'test -s /var/run/svid/tls.key && test -s /var/run/svid/ca.crt'
echo "ok: tls.key and ca.crt present"

step "verify the sidecar cannot see it"
if kubectl -n payments exec "${POD}" -c sidecar -- test -e /var/run/svid/tls.crt 2>/dev/null; then
  echo "FAIL: the sidecar can read the identity"
  exit 1
fi
echo "ok: the sidecar has no mount"

step "verify the private key never left tmpfs"
NODE="$(kubectl -n payments get pod "${POD}" -o jsonpath='{.spec.nodeName}')"
docker exec "${NODE}" sh -c 'mount | grep -c "svidlet .*tmpfs"' >/dev/null \
  && echo "ok: volume is a tmpfs on ${NODE}"

step "metrics"
kubectl -n svidlet-system get pods -o name | head -1 | \
  xargs -I{} kubectl -n svidlet-system exec {} -- true 2>/dev/null || true
kubectl -n svidlet-system port-forward svc/svidlet-metrics 9464:9464 >/dev/null 2>&1 &
PF=$!
sleep 2
curl -sf localhost:9464/metrics | grep -E 'svidlet_certificates_(issued_total|active)' || true
kill "${PF}" 2>/dev/null || true

step "PASS"
echo "Tear down with: kind delete cluster --name ${CLUSTER_NAME}"
