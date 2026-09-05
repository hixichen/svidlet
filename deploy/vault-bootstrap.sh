#!/usr/bin/env bash
# One-time Vault configuration for a cluster.
#
# The PKI mount and its intermediate CA are shared by every cluster in the trust
# domain — one ca.crt everywhere, no federation. What is per-cluster is the role
# and the AppRole: the role pins allowed_uri_sans to this cluster's SPIFFE
# prefix, and the policy grants nothing else. A compromised node can therefore
# mint any identity in its own cluster and none outside it.
#
# Usage: VAULT_ADDR=... VAULT_TOKEN=... ./vault-bootstrap.sh <trust-domain> <cluster>
set -euo pipefail

TRUST_DOMAIN="${1:?usage: $0 <trust-domain> <cluster>}"
CLUSTER="${2:?usage: $0 <trust-domain> <cluster>}"

PKI_MOUNT="${PKI_MOUNT:-pki}"
MAX_TTL="${MAX_TTL:-72h}"
ROLE="spiffe-${CLUSTER}"

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
# require_cn=false because svidlet sends an empty subject: the SPIFFE URI SAN is
# the identity.
vault write "${PKI_MOUNT}/roles/${ROLE}" \
  allowed_uri_sans="spiffe://${TRUST_DOMAIN}/cluster/${CLUSTER}/ns/*/sa/*" \
  allowed_domains="" \
  allow_any_name=false \
  allow_bare_domains=false \
  allow_subdomains=false \
  allow_ip_sans=false \
  require_cn=false \
  use_csr_common_name=false \
  use_csr_sans=false \
  server_flag=true \
  client_flag=true \
  key_type=ec \
  key_bits=256 \
  no_store=true \
  max_ttl="${MAX_TTL}" \
  ttl=24h

echo "==> Policy svidlet-${CLUSTER}"
vault policy write "svidlet-${CLUSTER}" - <<POLICY
path "${PKI_MOUNT}/sign/${ROLE}" {
  capabilities = ["update"]
}

path "${PKI_MOUNT}/ca_chain" {
  capabilities = ["read"]
}
POLICY

echo "==> AppRole svidlet-${CLUSTER}"
vault auth list -format=json | grep -q '"approle/"' || vault auth enable approle
# A periodic token: svidlet renews it in the background and never logs in per
# certificate.
vault write "auth/approle/role/svidlet-${CLUSTER}" \
  token_policies="svidlet-${CLUSTER}" \
  token_period=24h \
  secret_id_ttl=0 \
  secret_id_num_uses=0

echo "==> Rate-limit quota (bounds the blast radius of a plugin bug)"
vault write "sys/quotas/rate-limit/svidlet-${CLUSTER}" \
  path="${PKI_MOUNT}/sign/${ROLE}" \
  rate=200 || echo "    (skipped: requires Vault Enterprise or a recent OSS build)"

ROLE_ID="$(vault read -field=role_id "auth/approle/role/svidlet-${CLUSTER}/role-id")"
SECRET_ID="$(vault write -f -field=secret_id "auth/approle/role/svidlet-${CLUSTER}/secret-id")"

cat <<SUMMARY

Done. Configure the DaemonSet with:

  kubectl -n svidlet-system create configmap svidlet \\
    --from-literal=SVIDLET_TRUST_DOMAIN=${TRUST_DOMAIN} \\
    --from-literal=SVIDLET_CLUSTER=${CLUSTER} \\
    --from-literal=VAULT_ADDR=${VAULT_ADDR} \\
    --from-literal=SVIDLET_PKI_ROLE=${ROLE} \\
    --from-literal=SVIDLET_ROLE_ID=${ROLE_ID} \\
    --dry-run=client -o yaml | kubectl apply -f -

  kubectl -n svidlet-system create secret generic svidlet-vault-approle \\
    --from-literal=secret-id=${SECRET_ID} \\
    --dry-run=client -o yaml | kubectl apply -f -

Rotate the secret ID on a fixed cadence by repeating the second command;
svidlet re-reads the file on its next login and needs no restart.
SUMMARY
