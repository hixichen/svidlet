#!/usr/bin/env bash
# End-to-end check on a kind cluster against an in-cluster dev-mode Vault.
#
# Builds the image, brings up Vault (with TLS, as certificate auth requires),
# configures it for one deploy/ variant, deploys that variant, and asserts that
# a workload gets a certificate carrying the SPIFFE ID derived from its
# ServiceAccount — and that a container without the volumeMount does not.
#
#   ./hack/kind-e2e.sh                               # VARIANT=dev: AppRole
#   VARIANT=standalone ./hack/kind-e2e.sh            # Vault Kubernetes auth
#   VARIANT=with-node-bootstrap ./hack/kind-e2e.sh   # node certificate auth
#
# with-node-bootstrap runs the real deploy/with-node-bootstrap wiring — the
# shared /node volume, the init container before svidlet, the native renew
# sidecar, cert auth — with a stand-in for the bootstrap containers: Vault
# plays step-ca and issues the node certificate, and busybox copies it into
# /node. What svidlet-node-bootstrap does to obtain the certificate is that
# repository's to test; what svidlet does with it is this one's.
#
# Requires: kind, kubectl, docker, openssl.
set -euo pipefail

VARIANT="${VARIANT:-dev}"
CLUSTER_NAME="${CLUSTER_NAME:-svidlet-e2e}"
TRUST_DOMAIN="${TRUST_DOMAIN:-example.org}"
SVIDLET_CLUSTER="${SVIDLET_CLUSTER:-cluster-a}"
IMAGE="${IMAGE:-svidlet:e2e}"
VAULT_IMAGE="${VAULT_IMAGE:-hashicorp/vault:1.20}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The generated overlay lives in the repository so it can refer to deploy/ by
# relative path, which is all kustomize allows. Ignored by git.
OVERLAY="${REPO_ROOT}/.e2e/${VARIANT}"

case "${VARIANT}" in
  dev | standalone | with-node-bootstrap) ;;
  *) echo "VARIANT must be dev, standalone or with-node-bootstrap; got ${VARIANT}" >&2; exit 2 ;;
esac

step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
vault_exec() {
  kubectl -n vault exec deploy/vault -- env VAULT_ADDR=https://127.0.0.1:8200 \
    VAULT_CACERT=/vault/tls/vault-ca.pem VAULT_TOKEN=root "$@"
}

step "kind cluster ${CLUSTER_NAME}"
kind get clusters | grep -qx "${CLUSTER_NAME}" || kind create cluster --name "${CLUSTER_NAME}"
kubectl config use-context "kind-${CLUSTER_NAME}"
NODE_NAME="$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}')"

step "build and load ${IMAGE}"
docker build -t "${IMAGE}" "${REPO_ROOT}"
kind load docker-image "${IMAGE}" --name "${CLUSTER_NAME}"

# Everything else the cluster runs is pulled here and loaded, so the kind node
# needs no registry access of its own — only the machine running this does.
WORKLOAD_IMAGE="cgr.dev/chainguard/busybox:latest"
STUB_IMAGE="busybox:1.36"
for image in "${VAULT_IMAGE}" "${WORKLOAD_IMAGE}" "${STUB_IMAGE}"; do
  docker image inspect "${image}" >/dev/null 2>&1 || docker pull -q "${image}" >/dev/null
  kind load docker-image "${image}" --name "${CLUSTER_NAME}"
done

step "dev-mode Vault, with TLS"
kubectl create namespace vault --dry-run=client -o yaml | kubectl apply -f -
kubectl -n vault apply -f - <<YAML
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
          image: ${VAULT_IMAGE}
          imagePullPolicy: IfNotPresent
          args:
            - server
            - -dev
            - -dev-root-token-id=root
            - -dev-listen-address=0.0.0.0:8200
            - -dev-tls
            - -dev-tls-san=vault.vault.svc
            - -dev-tls-cert-dir=/vault/tls
          securityContext:
            capabilities: { add: ["IPC_LOCK"] }
          ports: [{ containerPort: 8200 }]
          volumeMounts: [{ name: tls, mountPath: /vault/tls }]
      volumes: [{ name: tls, emptyDir: {} }]
---
apiVersion: v1
kind: Service
metadata:
  name: vault
spec:
  selector: { app: vault }
  ports: [{ port: 8200, targetPort: 8200 }]
YAML
kubectl -n vault rollout status deploy/vault --timeout=180s
until vault_exec vault status >/dev/null 2>&1; do sleep 1; done
VAULT_POD="$(kubectl -n vault get pod -l app=vault -o jsonpath='{.items[0].metadata.name}')"
VAULT_CA="$(kubectl -n vault exec "${VAULT_POD}" -- cat /vault/tls/vault-ca.pem)"

step "configure Vault for ${TRUST_DOMAIN} / ${SVIDLET_CLUSTER} (${VARIANT})"
kubectl -n vault cp "${REPO_ROOT}/deploy/vault-bootstrap.sh" "${VAULT_POD}":/tmp/bootstrap.sh
case "${VARIANT}" in
  dev)
    AUTH_ENV="AUTH=approle"
    ;;
  standalone)
    # Vault reviews svidlet's token against this cluster's API server, using
    # the CA its own pod is given.
    AUTH_ENV="AUTH=kubernetes K8S_HOST=https://kubernetes.default.svc \
K8S_CA_FILE=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    ;;
  with-node-bootstrap)
    # A second PKI mount stands in for step-ca, the node registration CA.
    vault_exec sh -c '
      vault secrets list -format=json | grep -q "\"pki-node/\"" || {
        vault secrets enable -path=pki-node pki >/dev/null
        vault write -field=certificate pki-node/root/generate/internal \
          common_name="node registration CA" key_type=ec key_bits=256 ttl=87600h \
          > /tmp/node-ca.pem
        vault write pki-node/roles/node allowed_uri_sans="spiffe://*" \
          allowed_domains="" allow_any_name=false cn_validations=disabled \
          use_csr_common_name=false use_csr_sans=false server_flag=false \
          client_flag=true key_type=ec key_bits=256 no_store=true max_ttl=24h >/dev/null
      }'
    AUTH_ENV="AUTH=cert NODE_CA_FILE=/tmp/node-ca.pem"
    ;;
esac
vault_exec sh -c "${AUTH_ENV} sh /tmp/bootstrap.sh ${TRUST_DOMAIN} ${SVIDLET_CLUSTER}" >/tmp/bootstrap.out
sed -n '/^Done/,$p' /tmp/bootstrap.out

step "generate the ${VARIANT} overlay"
rm -rf "${OVERLAY}"
mkdir -p "${OVERLAY}"
cat > "${OVERLAY}/config.yaml" <<YAML
apiVersion: v1
kind: ConfigMap
metadata:
  name: svidlet
  namespace: svidlet-system
data:
  SVIDLET_TRUST_DOMAIN: ${TRUST_DOMAIN}
  SVIDLET_CLUSTER: ${SVIDLET_CLUSTER}
  VAULT_ADDR: https://vault.vault.svc:8200
  VAULT_CACERT: /etc/svidlet/vault-ca/ca.crt
  SVIDLET_PKI_ROLE: spiffe-${SVIDLET_CLUSTER}
  SVIDLET_CLOUD_PROFILE: aws,gcp
  SVIDLET_CERT_TTL: 10m
  SVIDLET_LOG_LEVEL: debug
YAML
cat > "${OVERLAY}/daemonset.yaml" <<'YAML'
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: svidlet
  namespace: svidlet-system
spec:
  template:
    spec:
      containers:
        - name: svidlet
          imagePullPolicy: Never
          volumeMounts:
            - name: vault-ca
              mountPath: /etc/svidlet/vault-ca
              readOnly: true
        - name: svidlet-policy
          imagePullPolicy: Never
      volumes:
        - name: vault-ca
          configMap:
            name: vault-ca
YAML
PATCHES="  - path: config.yaml
  - path: daemonset.yaml"

case "${VARIANT}" in
  dev)
    ROLE_ID="$(vault_exec vault read -field=role_id "auth/approle/role/svidlet-${SVIDLET_CLUSTER}/role-id")"
    SECRET_ID="$(vault_exec vault write -f -field=secret_id "auth/approle/role/svidlet-${SVIDLET_CLUSTER}/secret-id")"
    printf '  SVIDLET_ROLE_ID: %s\n' "${ROLE_ID}" >> "${OVERLAY}/config.yaml"
    ;;
  standalone)
    printf '  SVIDLET_VAULT_K8S_MOUNT: kubernetes-%s\n' "${SVIDLET_CLUSTER}" >> "${OVERLAY}/config.yaml"
    ;;
  with-node-bootstrap)
    NODE_JSON="$(vault_exec vault write -format=json pki-node/issue/node \
      common_name="${NODE_NAME}" exclude_cn_from_sans=true private_key_format=pkcs8 ttl=24h \
      uri_sans="spiffe://${TRUST_DOMAIN}/cluster/${SVIDLET_CLUSTER}/node/${NODE_NAME}")"
    printf '%s' "${NODE_JSON}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["certificate"])' > "${OVERLAY}/node.crt"
    printf '%s' "${NODE_JSON}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["private_key"])' > "${OVERLAY}/node.key"
    # The stand-in: the real containers' volumes, env and ordering, with
    # busybox doing what enrolment and renewal would.
    cat > "${OVERLAY}/bootstrap-stub.yaml" <<'YAML'
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: svidlet
  namespace: svidlet-system
spec:
  template:
    spec:
      initContainers:
        - name: node-enroll
          image: busybox:1.36
          imagePullPolicy: IfNotPresent
          command: ["sh", "-c", "cp /seed/node.crt /seed/node.key /node/ && chmod 0400 /node/node.key"]
          args: []
          volumeMounts:
            - name: node-seed
              mountPath: /seed
              readOnly: true
        - name: node-renew
          image: busybox:1.36
          imagePullPolicy: IfNotPresent
          command: ["sh", "-c", "exec sleep 2147483647"]
          args: []
      volumes:
        - name: node-seed
          secret:
            secretName: node-seed
YAML
    PATCHES="${PATCHES}
  - path: bootstrap-stub.yaml"
    ;;
esac

cat > "${OVERLAY}/kustomization.yaml" <<YAML
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../../deploy/${VARIANT}
images:
  - name: ghcr.io/hixichen/svidlet
    newName: ${IMAGE%:*}
    newTag: ${IMAGE##*:}
patches:
${PATCHES}
YAML

step "deploy svidlet (${VARIANT})"
kubectl create namespace svidlet-system --dry-run=client -o yaml | kubectl apply -f -
printf '%s\n' "${VAULT_CA}" > "${OVERLAY}/vault-ca.crt"
kubectl -n svidlet-system create configmap vault-ca --from-file=ca.crt="${OVERLAY}/vault-ca.crt" \
  --dry-run=client -o yaml | kubectl apply -f -
if [ "${VARIANT}" = dev ]; then
  kubectl -n svidlet-system create secret generic svidlet-vault-approle \
    --from-literal=secret-id="${SECRET_ID}" --dry-run=client -o yaml | kubectl apply -f -
fi
if [ "${VARIANT}" = with-node-bootstrap ]; then
  kubectl -n svidlet-system create secret generic node-seed \
    --from-file=node.crt="${OVERLAY}/node.crt" --from-file=node.key="${OVERLAY}/node.key" \
    --dry-run=client -o yaml | kubectl apply -f -
fi
kubectl apply -k "${OVERLAY}"
kubectl -n svidlet-system rollout restart daemonset/svidlet
kubectl -n svidlet-system rollout status daemonset/svidlet --timeout=180s

step "deploy the example workload"
kubectl create namespace payments --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace payments pod-security.kubernetes.io/enforce=restricted --overwrite
kubectl apply -f "${REPO_ROOT}/deploy/example-workload.yaml"
kubectl -n payments rollout restart deploy/api
kubectl -n payments rollout status deploy/api --timeout=180s

step "verify the identity"
POD="$(kubectl -n payments get pod -l app=api --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}')"
EXPECT="spiffe://${TRUST_DOMAIN}/cluster/${SVIDLET_CLUSTER}/ns/payments/sa/api"

CERT="$(kubectl -n payments exec "${POD}" -c app -- cat /var/run/svid/tls.crt)"
GOT="$(printf '%s' "${CERT}" | openssl x509 -noout -ext subjectAltName | grep -o 'URI:spiffe://[^ ,]*' | cut -d: -f2-)"
if [ "${GOT}" != "${EXPECT}" ]; then
  echo "FAIL: expected ${EXPECT}, got ${GOT:-<none>}"
  exit 1
fi
echo "ok: ${GOT}"
SUBJECT="$(printf '%s' "${CERT}" | openssl x509 -noout -subject)"
case "${SUBJECT}" in
  *"CN = ${POD}"* | *"CN=${POD}"*) echo "ok: ${SUBJECT}" ;;
  *) echo "FAIL: expected CN=${POD}, got ${SUBJECT}"; exit 1 ;;
esac

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
kubectl -n svidlet-system port-forward svc/svidlet-metrics 19464:9464 >/dev/null 2>&1 &
PF=$!
trap 'kill "${PF}" 2>/dev/null || true' EXIT
for _ in $(seq 1 20); do curl -sf localhost:19464/healthz >/dev/null && break; sleep 0.5; done
METRICS="$(curl -sf localhost:19464/metrics)"
printf '%s\n' "${METRICS}" | grep -E '^svidlet_(build_info|certificates_issued_total|node_certificate_expiry_seconds|cloud_profile_findings_total\{cloud="aws",rule="subject"\})'

WANT_AUTH="$(case "${VARIANT}" in dev) echo approle ;; standalone) echo kubernetes ;; *) echo cert ;; esac)"
printf '%s\n' "${METRICS}" | grep -q "auth=\"${WANT_AUTH}\"" \
  || { echo "FAIL: svidlet is not using ${WANT_AUTH} auth"; exit 1; }
echo "ok: authenticating with ${WANT_AUTH}"
if printf '%s\n' "${METRICS}" | grep -E '^svidlet_cloud_profile_findings_total' | grep -qv ' 0$'; then
  echo "FAIL: an issued certificate would be refused by a cloud"
  exit 1
fi
echo "ok: no cloud-profile findings"
if [ "${VARIANT}" = with-node-bootstrap ]; then
  printf '%s\n' "${METRICS}" | grep -E '^svidlet_node_certificate_expiry_seconds [0-9]' >/dev/null \
    || { echo "FAIL: the node certificate expiry is not reported"; exit 1; }
  kubectl -n svidlet-system logs daemonset/svidlet -c svidlet | grep -q "node certificate ready" \
    || { echo "FAIL: svidlet did not accept the node certificate"; exit 1; }
  echo "ok: node certificate from bootstrap accepted and reported"
fi

step "PASS (${VARIANT})"
echo "Tear down with: kind delete cluster --name ${CLUSTER_NAME}"
