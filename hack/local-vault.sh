#!/usr/bin/env bash
# Run a dev-mode Vault on this machine, configured the way svidlet expects, and
# print the environment that points the tests and the binary at it.
#
#   ./hack/local-vault.sh start     # start Vault and configure it
#   ./hack/local-vault.sh env       # print the environment to eval
#   ./hack/local-vault.sh stop      # stop it and clean up
#   eval "$(./hack/local-vault.sh env)" && cargo test -p svidlet-issue -- --ignored
#
# Dev mode keeps everything in memory and listens on localhost without TLS. It
# is for development only: the root token is a constant and there is no storage.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_DIR="${SVIDLET_LOCAL_VAULT_DIR:-${REPO_ROOT}/.local-vault}"
ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
ROOT_TOKEN="root"
TRUST_DOMAIN="${TRUST_DOMAIN:-example.org}"
CLUSTER="${CLUSTER:-cluster-a}"

PID_FILE="${STATE_DIR}/vault.pid"
LOG_FILE="${STATE_DIR}/vault.log"
SECRET_ID_FILE="${STATE_DIR}/secret-id"
TOKEN_FILE="${STATE_DIR}/token"
ENV_FILE="${STATE_DIR}/env"

need() { command -v "$1" >/dev/null || { echo "$1 is required but not installed" >&2; exit 1; }; }

start() {
  need vault
  mkdir -p "${STATE_DIR}"

  if [ -f "${PID_FILE}" ] && kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
    echo "vault already running (pid $(cat "${PID_FILE}"))"
  else
    echo "==> starting dev-mode Vault on ${ADDR}"
    vault server -dev "-dev-root-token-id=${ROOT_TOKEN}" \
      "-dev-listen-address=${ADDR#http://}" >"${LOG_FILE}" 2>&1 &
    echo $! > "${PID_FILE}"

    for _ in $(seq 1 50); do
      if VAULT_ADDR="${ADDR}" vault status >/dev/null 2>&1; then break; fi
      sleep 0.2
    done
    VAULT_ADDR="${ADDR}" vault status >/dev/null || {
      echo "vault did not come up; see ${LOG_FILE}" >&2
      exit 1
    }
  fi

  echo "==> configuring the PKI mount, role and AppRole"
  VAULT_ADDR="${ADDR}" VAULT_TOKEN="${ROOT_TOKEN}" \
    "${REPO_ROOT}/deploy/vault-bootstrap.sh" "${TRUST_DOMAIN}" "${CLUSTER}" >/dev/null

  local role_id secret_id
  role_id="$(VAULT_ADDR="${ADDR}" VAULT_TOKEN="${ROOT_TOKEN}" \
    vault read -field=role_id "auth/approle/role/svidlet-${CLUSTER}/role-id")"
  secret_id="$(VAULT_ADDR="${ADDR}" VAULT_TOKEN="${ROOT_TOKEN}" \
    vault write -f -field=secret_id "auth/approle/role/svidlet-${CLUSTER}/secret-id")"

  umask 077
  printf '%s' "${secret_id}" > "${SECRET_ID_FILE}"
  printf '%s' "${ROOT_TOKEN}" > "${TOKEN_FILE}"

  cat > "${ENV_FILE}" <<VARS
export VAULT_ADDR=${ADDR}
export SVIDLET_TEST_VAULT=1
export SVIDLET_TRUST_DOMAIN=${TRUST_DOMAIN}
export SVIDLET_CLUSTER=${CLUSTER}
export SVIDLET_PKI_MOUNT=pki
export SVIDLET_PKI_ROLE=spiffe-${CLUSTER}
export SVIDLET_APPROLE_MOUNT=approle
export SVIDLET_ROLE_ID=${role_id}
export SVIDLET_SECRET_ID_FILE=${SECRET_ID_FILE}
export SVIDLET_VAULT_TOKEN_FILE=${TOKEN_FILE}
export NODE_NAME=$(hostname)
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
      wait "${pid}" 2>/dev/null || true
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
