#!/usr/bin/env bash
# What CI does: package a policy bundle, sign a rollout manifest, push both to
# an OCI registry.
#
#   ./hack/build-bundle.sh keygen                       # once, per fleet
#   ./hack/build-bundle.sh bundle ./policy-repo/bundle  # prints the digest
#   ./hack/build-bundle.sh rollout ./rollout.toml       # signs and pushes
#
# The signing key here is a local file, which is right for a demo and wrong for
# production: hold the private half in Vault Transit (or an equivalent) with a
# policy that only the release pipeline's identity can use, so a compromised
# runner cannot sign a bundle outside a recorded pipeline run. The envelope
# format below is all svidlet cares about; how the signature is produced is
# entirely CI's business.
#
# Requires: oras, openssl, python3.
set -euo pipefail

REGISTRY="${REGISTRY:?set REGISTRY, e.g. registry.example.com/policy}"
KEY_DIR="${KEY_DIR:-./.bundle-keys}"
PRIVATE_KEY="${KEY_DIR}/signing.pem"
PUBLIC_KEY="${KEY_DIR}/signing.pub"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

need() { command -v "$1" >/dev/null || { echo "$1 is required" >&2; exit 1; }; }

keygen() {
  mkdir -p "${KEY_DIR}"
  [ -f "${PRIVATE_KEY}" ] && { echo "${PRIVATE_KEY} already exists" >&2; exit 1; }
  openssl genpkey -algorithm ed25519 -out "${PRIVATE_KEY}"
  chmod 600 "${PRIVATE_KEY}"
  openssl pkey -in "${PRIVATE_KEY}" -pubout -out "${PUBLIC_KEY}"
  echo "==> private key: ${PRIVATE_KEY}   (never leaves CI)"
  echo "==> public key:  ${PUBLIC_KEY}    (goes to every node)"
  echo
  echo "Configure the DaemonSet with:"
  echo
  echo "  SVIDLET_BUNDLE_PUBLIC_KEY: |"
  sed 's/^/    /' "${PUBLIC_KEY}"
}

# Package a directory as an uncompressed tar and push it as an artifact whose
# single layer is that tar. Prints the digest for rollout.toml to reference.
bundle() {
  local dir="${1:?usage: $0 bundle <directory>}"
  [ -f "${dir}/bundle.toml" ] || { echo "${dir}/bundle.toml is required" >&2; exit 1; }

  # Reproducible: sorted names, zeroed mtime/uid/gid, so the same content is
  # always the same digest and an unchanged bundle is never re-rolled out.
  tar --format=ustar --sort=name --numeric-owner --owner=0 --group=0 \
      --mtime='@0' -cf "${WORK}/bundle.tar" -C "${dir}" .

  local digest
  digest="sha256:$(openssl dgst -sha256 -binary "${WORK}/bundle.tar" | xxd -p -c 256)"

  ( cd "${WORK}" && oras push "${REGISTRY}/rollout:${digest#sha256:}" \
      --artifact-type application/vnd.svidlet.bundle.v1 \
      bundle.tar:application/vnd.svidlet.bundle.v1.tar >/dev/null )

  echo "${digest}"
}

# Sign rollout.toml into the envelope svidlet verifies, and push it to the tag
# nodes poll.
rollout() {
  local file="${1:?usage: $0 rollout <rollout.toml>}"
  [ -f "${PRIVATE_KEY}" ] || { echo "no signing key; run '$0 keygen'" >&2; exit 1; }

  openssl pkeyutl -sign -inkey "${PRIVATE_KEY}" -rawin \
    -in "${file}" -out "${WORK}/sig"

  python3 - "${file}" "${WORK}/sig" > "${WORK}/rollout.json" <<'PY'
import base64, json, sys
payload = open(sys.argv[1], "rb").read()
signature = open(sys.argv[2], "rb").read()
json.dump({
    "svidlet_signature": 1,
    "algorithm": "ed25519",
    "key_id": "release",
    "payload": base64.b64encode(payload).decode(),
    "signature": base64.b64encode(signature).decode(),
}, sys.stdout)
PY

  ( cd "${WORK}" && oras push "${REGISTRY}/rollout:current" \
      --artifact-type application/vnd.svidlet.rollout.v1 \
      rollout.json:application/vnd.svidlet.rollout.v1+json >/dev/null )

  echo "==> pushed ${REGISTRY}/rollout:current"
  echo "    nodes converge within one polling interval"
}

need openssl
need python3
case "${1:-}" in
  keygen) keygen ;;
  bundle) need oras; bundle "${2:-}" ;;
  rollout) need oras; rollout "${2:-}" ;;
  *) echo "usage: $0 {keygen|bundle <dir>|rollout <file>}" >&2; exit 2 ;;
esac
