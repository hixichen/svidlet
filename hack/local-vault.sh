#!/usr/bin/env bash
# Run a dev-mode Vault on this machine, configured the way svidlet expects, and
# print the environment that points the tests and the binary at it.
#
#   ./hack/local-vault.sh start     # start Vault and configure it
#   ./hack/local-vault.sh env       # print the environment to eval
#   ./hack/local-vault.sh stop      # stop it and clean up
#   eval "$(./hack/local-vault.sh env)" && cargo test -p svidlet-issue -- --ignored
#
# Dev mode keeps everything in memory. It is for development only: the root
# token is a constant and there is no storage. It listens with TLS (-dev-tls),
# because Vault's certificate auth method — how a registered node logs in —
# only exists over TLS; the CA Vault generates for itself is exported as
# VAULT_CACERT.
#
# A second PKI mount, pki-node, stands in for the node registration CA (step-ca
# or the go-attestation service in production) and issues this machine a node
# certificate, spiffe://<td>/cluster/<c>/node/<hostname>, so that
# SVIDLET_VAULT_AUTH=cert can be exercised end to end without a TPM.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_DIR="${SVIDLET_LOCAL_VAULT_DIR:-${REPO_ROOT}/.local-vault}"
LISTEN="${SVIDLET_LOCAL_VAULT_LISTEN:-127.0.0.1:8200}"
ADDR="https://${LISTEN}"
ROOT_TOKEN="root"
TRUST_DOMAIN="${TRUST_DOMAIN:-example.org}"
CLUSTER="${CLUSTER:-cluster-a}"

PID_FILE="${STATE_DIR}/vault.pid"
LOG_FILE="${STATE_DIR}/vault.log"
SECRET_ID_FILE="${STATE_DIR}/secret-id"
TOKEN_FILE="${STATE_DIR}/token"
ENV_FILE="${STATE_DIR}/env"
TLS_DIR="${STATE_DIR}/tls"
NODE_DIR="${STATE_DIR}/node"

need() { command -v "$1" >/dev/null || { echo "$1 is required but not installed" >&2; exit 1; }; }

start() {
  need vault
  need openssl
  mkdir -p "${STATE_DIR}" "${TLS_DIR}" "${NODE_DIR}"
  export VAULT_ADDR="${ADDR}" VAULT_CACERT="${TLS_DIR}/vault-ca.pem"

  if [ -f "${PID_FILE}" ] && kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
    echo "vault already running (pid $(cat "${PID_FILE}"))"
  else
    echo "==> starting dev-mode Vault on ${ADDR}"
    vault server -dev "-dev-root-token-id=${ROOT_TOKEN}" \
      -dev-tls "-dev-tls-cert-dir=${TLS_DIR}" \
      "-dev-listen-address=${LISTEN}" >"${LOG_FILE}" 2>&1 &
    echo $! > "${PID_FILE}"

    for _ in $(seq 1 50); do
      if [ -f "${VAULT_CACERT}" ] && vault status >/dev/null 2>&1; then break; fi
      sleep 0.2
    done
    vault status >/dev/null || {
      echo "vault did not come up; see ${LOG_FILE}" >&2
      exit 1
    }
  fi
  export VAULT_TOKEN="${ROOT_TOKEN}"

  # The node certificate carries CN=<node name> as well as its URI SAN: Vault's
  # cert auth method names the entity alias after the Subject CN and refuses a
  # login without one.
  echo "==> a node registration CA, and a node certificate for this machine"
  local node_name node_id
  node_name="$(hostname)"
  node_id="spiffe://${TRUST_DOMAIN}/cluster/${CLUSTER}/node/${node_name}"
  if ! vault secrets list -format=json | grep -q '"pki-node/"'; then
    vault secrets enable -path=pki-node pki >/dev/null
    vault secrets tune -max-lease-ttl=87600h pki-node >/dev/null
    vault write -field=certificate pki-node/root/generate/internal \
      common_name="${TRUST_DOMAIN} node registration CA" \
      key_type=ec key_bits=256 ttl=87600h > "${NODE_DIR}/ca.crt"
    vault write pki-node/roles/node \
      allowed_uri_sans="spiffe://${TRUST_DOMAIN}/cluster/*/node/*" \
      allowed_domains="" allow_any_name=false cn_validations=disabled \
      use_csr_common_name=false use_csr_sans=false \
      server_flag=false client_flag=true \
      key_type=ec key_bits=256 no_store=true max_ttl=24h ttl=24h >/dev/null
  fi
  openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null \
    | openssl pkcs8 -topk8 -nocrypt -out "${NODE_DIR}/tls.key"
  openssl req -new -key "${NODE_DIR}/tls.key" -subj "/CN=${node_name}" \
    -out "${NODE_DIR}/tls.csr"
  vault write -field=certificate pki-node/sign/node \
    csr=@"${NODE_DIR}/tls.csr" uri_sans="${node_id}" common_name="${node_name}" \
    exclude_cn_from_sans=true ttl=24h > "${NODE_DIR}/tls.crt"
  chmod 0600 "${NODE_DIR}/tls.key"

  echo "==> configuring the PKI mount, role, AppRole and certificate auth"
  # The quota is lifted here: hack/bench-memory.sh publishes as fast as the
  # machine allows, which on Linux is well past the production 200/s.
  AUTH=approle,cert NODE_CA_FILE="${NODE_DIR}/ca.crt" RATE_LIMIT=100000 \
    "${REPO_ROOT}/deploy/vault-bootstrap.sh" "${TRUST_DOMAIN}" "${CLUSTER}" >/dev/null

  local role_id secret_id
  role_id="$(vault read -field=role_id "auth/approle/role/svidlet-${CLUSTER}/role-id")"
  secret_id="$(vault write -f -field=secret_id "auth/approle/role/svidlet-${CLUSTER}/secret-id")"

  umask 077
  printf '%s' "${secret_id}" > "${SECRET_ID_FILE}"
  printf '%s' "${ROOT_TOKEN}" > "${TOKEN_FILE}"

  cat > "${ENV_FILE}" <<VARS
export VAULT_ADDR=${ADDR}
export VAULT_CACERT=${VAULT_CACERT}
export SVIDLET_TEST_VAULT=1
export SVIDLET_TRUST_DOMAIN=${TRUST_DOMAIN}
export SVIDLET_CLUSTER=${CLUSTER}
export SVIDLET_PKI_MOUNT=pki
export SVIDLET_PKI_ROLE=spiffe-${CLUSTER}
export SVIDLET_APPROLE_MOUNT=approle
export SVIDLET_ROLE_ID=${role_id}
export SVIDLET_SECRET_ID_FILE=${SECRET_ID_FILE}
export SVIDLET_VAULT_TOKEN_FILE=${TOKEN_FILE}
export SVIDLET_VAULT_CERT_MOUNT=cert
export SVIDLET_VAULT_CERT_ROLE=svidlet-${CLUSTER}
export SVIDLET_NODE_CERT_FILE=${NODE_DIR}/tls.crt
export SVIDLET_NODE_KEY_FILE=${NODE_DIR}/tls.key
export NODE_NAME=${node_name}
VARS

  echo
  echo "Vault is up. To point the tests at it:"
  echo
  echo "    eval \"\$(${BASH_SOURCE[0]} env)\""
  echo "    cargo test -p svidlet-issue -- --ignored --nocapture"
  echo
  echo "Logs: ${LOG_FILE}"
}

env_cmd() {
  [ -f "${ENV_FILE}" ] || { echo "not started; run '$0 start' first" >&2; exit 1; }
  cat "${ENV_FILE}"
}

stop() {
  if [ -f "${PID_FILE}" ]; then
    local pid
    pid="$(cat "${PID_FILE}")"
    if kill -0 "${pid}" 2>/dev/null; then
      echo "==> stopping vault (pid ${pid})"
      kill "${pid}" || true
      # Not our child, so `wait` cannot help. Poll until it has really gone: a
      # dev-tls Vault deletes its certificate files as it exits, and one still
      # shutting down would delete the files of the next one started.
      for _ in $(seq 1 100); do
        kill -0 "${pid}" 2>/dev/null || break
        sleep 0.1
      done
    fi
  fi
  rm -rf "${STATE_DIR}"
}

case "${1:-start}" in
  start) start ;;
  env) env_cmd ;;
  stop) stop ;;
  *) echo "usage: $0 {start|env|stop}" >&2; exit 2 ;;
esac
