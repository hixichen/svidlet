#!/usr/bin/env bash
# One-time Vault configuration for a cluster.
#
# The PKI mount and its intermediate CA are shared by every cluster in the trust
# domain — one ca.crt everywhere, no federation. What is per-cluster is the role
# and the node credential: the role pins allowed_uri_sans to this cluster's
# SPIFFE prefix, and the policy grants nothing else. A compromised node can
# therefore mint any identity in its own cluster and none outside it.
#
# Usage: VAULT_ADDR=... VAULT_TOKEN=... ./vault-bootstrap.sh <trust-domain> <cluster>
#
# How nodes authenticate is chosen with AUTH, a comma-separated list:
#
#   AUTH=cert NODE_CA_FILE=registration-ca.pem ./vault-bootstrap.sh td c
#       Production. Vault trusts the node registration CA (step-ca or the
#       go-attestation service) and binds the cluster from the node
#       certificate's URI SAN, spiffe://<td>/cluster/<c>/node/<n>. Nothing
#       shared, nothing to rotate by hand.
#   AUTH=approle ./vault-bootstrap.sh td c                         (the default)
#       Dev and kind only: a shared bearer secret in a Kubernetes Secret.
set -euo pipefail

TRUST_DOMAIN="${1:?usage: $0 <trust-domain> <cluster>}"
CLUSTER="${2:?usage: $0 <trust-domain> <cluster>}"

PKI_MOUNT="${PKI_MOUNT:-pki}"
# Pod SVIDs default to 6h (SVIDLET_CERT_TTL). The ceiling leaves room for an
# operator to lengthen that without reconfiguring Vault, and no further.
MAX_TTL="${MAX_TTL:-24h}"
ROLE="spiffe-${CLUSTER}"
AUTH="${AUTH:-approle}"
# Signatures per second this cluster's role may request. Well above steady
# state and pod-rollout peaks; it exists to bound a plugin bug.
RATE_LIMIT="${RATE_LIMIT:-200}"
CERT_MOUNT="${CERT_MOUNT:-cert}"

# POSIX on purpose: the kind e2e runs this inside the Vault container.
has_auth() { case ",${AUTH}," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }
if has_auth cert && [ -z "${NODE_CA_FILE:-}" ]; then
  echo "AUTH includes cert, so NODE_CA_FILE must name the node registration CA (PEM)" >&2
  exit 2
fi

echo "==> PKI mount (shared by all clusters in ${TRUST_DOMAIN})"
if ! vault secrets list -format=json | grep -q "\"${PKI_MOUNT}/\""; then
  vault secrets enable -path="${PKI_MOUNT}" pki
  vault secrets tune -max-lease-ttl=87600h "${PKI_MOUNT}"

  # A self-signed root for a demo. In production, sign this mount's CSR with an
  # offline root and import the certificate instead.
  vault write -field=certificate "${PKI_MOUNT}/root/generate/internal" \
    common_name="${TRUST_DOMAIN} SPIFFE CA" \
    issuer_name="spiffe-root" \
    key_type=ec key_bits=256 \
    ttl=87600h > /dev/null
fi

echo "==> PKI role ${ROLE}"
# allowed_uri_sans is the whole enforcement story: Vault, not the node, decides
# that a certificate requested by cluster ${CLUSTER} carries a ${CLUSTER} path.
# no_store keeps issuance out of Vault storage — required at this request rate.
#
# The Subject CN (the pod name, by default) is a label, not an identity: AWS IAM
# Roles Anywhere refuses an empty Subject and copies the CN into CloudTrail's
# sourceIdentity. cn_validations=disabled accepts any CN without making it a
# hostname — svidlet sends exclude_cn_from_sans=true, and a node that did not
# would be refused, because the CN would then be a DNS SAN and allowed_domains
# is empty with allow_any_name=false. No certificate from this role can ever be
# valid for a host name. require_cn=false keeps SVIDLET_CERT_SUBJECT=none legal.
vault write "${PKI_MOUNT}/roles/${ROLE}" \
  allowed_uri_sans="spiffe://${TRUST_DOMAIN}/cluster/${CLUSTER}/ns/*/sa/*" \
  allowed_domains="" \
  allow_any_name=false \
  allow_bare_domains=false \
  allow_subdomains=false \
  allow_ip_sans=false \
  require_cn=false \
  cn_validations=disabled \
  use_csr_common_name=false \
  use_csr_sans=false \
  server_flag=true \
  client_flag=true \
  key_type=ec \
  key_bits=256 \
  no_store=true \
  max_ttl="${MAX_TTL}" \
  ttl=6h

echo "==> Policy svidlet-${CLUSTER}"
vault policy write "svidlet-${CLUSTER}" - <<POLICY
path "${PKI_MOUNT}/sign/${ROLE}" {
  capabilities = ["update"]
}

path "${PKI_MOUNT}/ca_chain" {
  capabilities = ["read"]
}
POLICY

if has_auth approle; then
  echo "==> AppRole svidlet-${CLUSTER} (dev and kind only)"
  vault auth list -format=json | grep -q '"approle/"' || vault auth enable approle
  # A periodic token: svidlet renews it in the background and never logs in per
  # certificate.
  vault write "auth/approle/role/svidlet-${CLUSTER}" \
    token_policies="svidlet-${CLUSTER}" \
    token_period=24h \
    secret_id_ttl=0 \
    secret_id_num_uses=0
fi

if has_auth cert; then
  echo "==> Certificate auth role svidlet-${CLUSTER}"
  vault auth list -format=json | grep -q "\"${CERT_MOUNT}/\"" \
    || vault auth enable -path="${CERT_MOUNT}" cert
  # The node certificate's URI SAN is what binds a login to this cluster: a node
  # registered into another cluster presents another prefix and is refused, so
  # the policy below is reachable only from this cluster's nodes. Tokens are
  # short and not renewed in place — svidlet logs in again, which re-reads a
  # node certificate the registration agent has rotated, and a node removed from
  # the EK inventory loses Vault within the hour even if its CRL entry is late.
  vault write "auth/${CERT_MOUNT}/certs/svidlet-${CLUSTER}" \
    display_name="svidlet-${CLUSTER}" \
    certificate=@"${NODE_CA_FILE}" \
    allowed_uri_sans="spiffe://${TRUST_DOMAIN}/cluster/${CLUSTER}/node/*" \
    token_policies="svidlet-${CLUSTER}" \
    token_ttl=1h \
    token_max_ttl=1h
fi

echo "==> Rate-limit quota (bounds the blast radius of a plugin bug)"
vault write "sys/quotas/rate-limit/svidlet-${CLUSTER}" \
  path="${PKI_MOUNT}/sign/${ROLE}" \
  rate="${RATE_LIMIT}" || echo "    (skipped: requires Vault Enterprise or a recent OSS build)"

cat <<SUMMARY

Done. Configure the DaemonSet with:

  kubectl -n svidlet-system create configmap svidlet \\
    --from-literal=SVIDLET_TRUST_DOMAIN=${TRUST_DOMAIN} \\
    --from-literal=SVIDLET_CLUSTER=${CLUSTER} \\
    --from-literal=VAULT_ADDR=${VAULT_ADDR} \\
    --from-literal=SVIDLET_PKI_ROLE=${ROLE} \\
SUMMARY

if has_auth cert; then
  cat <<SUMMARY
    --from-literal=SVIDLET_VAULT_AUTH=cert \\
    --from-literal=SVIDLET_VAULT_CERT_MOUNT=${CERT_MOUNT} \\
    --from-literal=SVIDLET_VAULT_CERT_ROLE=svidlet-${CLUSTER} \\
    --dry-run=client -o yaml | kubectl apply -f -

Each node needs its registration certificate at /etc/svidlet/node/tls.crt and
its key at /etc/svidlet/node/tls.key (SVIDLET_NODE_CERT_FILE / _KEY_FILE),
with URI SAN spiffe://${TRUST_DOMAIN}/cluster/${CLUSTER}/node/<node-name>.
SUMMARY
fi

if has_auth approle; then
  ROLE_ID="$(vault read -field=role_id "auth/approle/role/svidlet-${CLUSTER}/role-id")"
  SECRET_ID="$(vault write -f -field=secret_id "auth/approle/role/svidlet-${CLUSTER}/secret-id")"
  cat <<SUMMARY
    --from-literal=SVIDLET_VAULT_AUTH=approle \\
    --from-literal=SVIDLET_ROLE_ID=${ROLE_ID} \\
    --dry-run=client -o yaml | kubectl apply -f -

  kubectl -n svidlet-system create secret generic svidlet-vault-approle \\
    --from-literal=secret-id=${SECRET_ID} \\
    --dry-run=client -o yaml | kubectl apply -f -

Rotate the secret ID on a fixed cadence by repeating the second command;
svidlet re-reads the file on its next login and needs no restart. AppRole is
for dev and kind clusters: in production, use AUTH=cert.
SUMMARY
fi
