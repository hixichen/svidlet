#!/usr/bin/env bash
# How much memory does one svidlet actually use?
#
# The design targets 5–8 MB resident per node. This measures the real release
# binary, serving the real CSI protocol over a real socket, signing against a
# real Vault — so the number is comparable to what a node would show, minus the
# tmpfs mounts (which cost the process nothing) and the kubelet's own traffic.
#
#   ./hack/bench-memory.sh            # 0, 100, 500, 2000 certificates
#   COUNTS="0 5000" ./hack/bench-memory.sh
#
# Requires: vault, cargo.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

COUNTS="${COUNTS:-0 100 500 2000}"
# A short path on purpose: a Unix socket path is capped at about 104 bytes, and
# the default temp directory on macOS is long enough to blow past it.
WORK="$(mktemp -d /tmp/svidlet-bench.XXXXXX)"
SVIDLET_PID=""

cleanup() {
  if [ -n "${KEEP_LOG}" ] && [ -f "${WORK}/svidlet.log" ]; then
    echo "--- svidlet log ---" >&2
    cat "${WORK}/svidlet.log" >&2
  fi
  [ -n "${SVIDLET_PID}" ] && kill "${SVIDLET_PID}" 2>/dev/null || true
  ./hack/local-vault.sh stop >/dev/null 2>&1 || true
  rm -rf "${WORK}"
}
trap cleanup EXIT
KEEP_LOG="${KEEP_LOG:-}"

# Resident set size in KB. Works on both macOS and Linux.
rss_kb() { ps -o rss= -p "$1" | tr -d ' '; }

mb() { python3 -c "print(f'{$1/1024:.1f}')"; }

echo "==> building the release binary"
cargo build --release --bins >/dev/null 2>&1

echo "==> starting a local Vault"
./hack/local-vault.sh start >/dev/null
# shellcheck disable=SC1090
eval "$(./hack/local-vault.sh env)"

echo "==> starting svidlet"
mkdir -p "${WORK}/kubelet/plugins" "${WORK}/kubelet/plugins_registry" "${WORK}/targets"
env \
  NODE_NAME=bench-node \
  SVIDLET_CLUSTER="${SVIDLET_CLUSTER}" \
  SVIDLET_TRUST_DOMAIN="${SVIDLET_TRUST_DOMAIN}" \
  VAULT_ADDR="${VAULT_ADDR}" \
  SVIDLET_VAULT_AUTH=token \
  SVIDLET_VAULT_TOKEN_FILE="${SVIDLET_VAULT_TOKEN_FILE}" \
  SVIDLET_PKI_ROLE="${SVIDLET_PKI_ROLE}" \
  SVIDLET_KUBELET_ROOT="${WORK}/kubelet" \
  SVIDLET_CSI_SOCKET="${WORK}/kubelet/plugins/csi.sock" \
  SVIDLET_REGISTRATION_SOCKET="${WORK}/kubelet/plugins_registry/svidlet-reg.sock" \
  SVIDLET_METRICS_ADDR=127.0.0.1:19464 \
  SVIDLET_CERT_TTL=24h \
  SVIDLET_LOG_LEVEL=warn \
  ./target/release/svidlet > "${WORK}/svidlet.log" 2>&1 &
SVIDLET_PID=$!

for _ in $(seq 1 50); do
  [ -S "${WORK}/kubelet/plugins/csi.sock" ] && break
  sleep 0.2
done
[ -S "${WORK}/kubelet/plugins/csi.sock" ] || {
  echo "svidlet did not start:" >&2
  cat "${WORK}/svidlet.log" >&2
  exit 1
}
sleep 1

printf '\n%-12s %-12s %-12s %s\n' "CERTIFICATES" "RSS (MB)" "PER CERT" "PUBLISH RATE"
printf -- '---------------------------------------------------------------\n'

baseline=""
published=0
for target in ${COUNTS}; do
  rate="—"
  if [ "${target}" -gt 0 ]; then
    to_add=$(( target - published ))
    if [ "${to_add}" -gt 0 ]; then
      out=$(./target/release/svidlet-bench \
        "${WORK}/kubelet/plugins/csi.sock" \
        "${WORK}/targets/batch-${target}" \
        "${to_add}" 2>>"${WORK}/bench.log")
      rate=$(echo "${out}" | sed -E 's/.*\(([0-9]+)\/s\).*/\1\/s/')
      published="${target}"
    fi
  fi

  # Let any transient allocation settle before sampling.
  sleep 2
  rss=$(rss_kb "${SVIDLET_PID}" || true)
  if [ -z "${rss}" ]; then
    echo "svidlet exited during the run; its log follows" >&2
    cat "${WORK}/svidlet.log" >&2
    exit 1
  fi
  [ -z "${baseline}" ] && baseline="${rss}"

  if [ "${target}" -gt 0 ]; then
    per_cert=$(python3 -c "print(f'{(${rss}-${baseline})*1024/${target}:.0f} B')")
  else
    per_cert="—"
  fi
  printf '%-12s %-12s %-12s %s\n' "${target}" "$(mb "${rss}")" "${per_cert}" "${rate}"
done

echo
echo "active certificates according to the process itself:"
curl -s localhost:19464/metrics | grep -E '^svidlet_(certificates_active|certificates_issued_total)' | sed 's/^/  /'

echo
case "$(uname -s)" in
  Darwin) echo "note: macOS — volumes are plain directories, not tmpfs, and RSS accounting" ;;
  *)      echo "note: tmpfs pages belong to the filesystem, not to this process, so bundle" ;;
esac
echo "      differs from Linux. Treat this as an order of magnitude, and measure on"
echo "      a real node for a number to hold anyone to."
