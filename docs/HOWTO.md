# Using a Svidlet certificate

What a workload actually does with the files in its volume: read them, verify a peer,
serve and dial mTLS, exchange the certificate for cloud credentials, and get rid of one.

**Depends on:** [DESIGN.md](DESIGN.md) · [POLICY.md](POLICY.md)

---

## 1. What is in the volume

```
/var/run/svid/
  tls.crt          leaf certificate, then any intermediates
  tls.key          PKCS#8 P-256 private key, mode 0640
  ca.crt           trust bundle for the whole trust domain
  policy/          policy documents         (only if a policy source is configured)
  policy.revision  the upstream revision of that bundle
```

The identity is the URI SAN, not the subject — the subject is deliberately empty:

```sh
openssl x509 -in /var/run/svid/tls.crt -noout -text | grep -A1 'Subject Alternative Name'
#     URI:spiffe://example.org/cluster/cluster-a/ns/payments/sa/api
```

### Reading the files correctly

Two rules, both consequences of how the volume is published.

**Read `tls.crt` and `tls.key` as a pair, and reload both together.** They are swapped
atomically as a set, but an application that opens one, then the other, resolves the
`..data` symlink twice and can straddle a renewal — getting a certificate from one
generation and a key from the next. Svidlet keeps the previous generation on disk so the
second read does not fail outright, but the pair would not match. Every mainstream TLS
library rejects a mismatched pair loudly, so the practical rule is: **load both, and if
loading fails, retry once.** This is the same caveat that applies to Kubernetes Secret
volumes.

**Do not read `tls.key` once at start-up.** Certificates are renewed roughly every half
lifetime — twice a day at the default 24 h — and a process holding the first key it ever
read will be presenting an expired certificate within days.

```go
// Go: reload on change, and let the library reject a torn pair.
cert, err := tls.LoadX509KeyPair("/var/run/svid/tls.crt", "/var/run/svid/tls.key")
if err != nil {
    // Almost always a renewal landing mid-read. Retry once before giving up.
    time.Sleep(50 * time.Millisecond)
    cert, err = tls.LoadX509KeyPair("/var/run/svid/tls.crt", "/var/run/svid/tls.key")
}
```

Watch the directory with inotify (`fsnotify`, `notify`, `inotifywait`) and reload on any
event. Watch the *directory*, not the file: the visible entries are symlinks, and a
renewal replaces what they point at rather than the files themselves.

### Permissions

`tls.key` is `0640`. A workload running as a non-root user can only read it if it is in
the file's group, so set both sides:

```yaml
# The DaemonSet's ConfigMap
SVIDLET_KEY_GID: "1000"
```
```yaml
# The workload
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000        # must match SVIDLET_KEY_GID
```

Do not reach for `SVIDLET_KEY_MODE=0644` when a workload cannot read its key. That makes
the private key readable by every process that can see the volume, which defeats the
point of per-container mounting.

---

## 2. Verifying a peer

**A certificate signed by your CA is not an authorization.** Every workload in the trust
domain has one. mTLS that checks only the CA proves that the peer is *somebody* in your
fleet — not that it is the somebody that may call this endpoint. Checking the peer's
SPIFFE ID is the entire point; a deployment that skips it has bought very little.

The rules:

1. Verify the chain against `ca.crt`.
2. Extract the peer's URI SAN. There must be **exactly one**, and it must start with
   `spiffe://`.
3. Compare it against what this endpoint allows — an exact string, or a prefix if you
   mean a whole namespace. Compare bytes, not a parsed structure.
4. Ignore the subject, the DNS SANs and the serial. They carry nothing.

### Go

```go
import "github.com/spiffe/go-spiffe/v2/spiffeid"

func peerID(cs tls.ConnectionState) (spiffeid.ID, error) {
    if len(cs.PeerCertificates) == 0 {
        return spiffeid.ID{}, errors.New("no peer certificate")
    }
    uris := cs.PeerCertificates[0].URIs
    if len(uris) != 1 {
        return spiffeid.ID{}, fmt.Errorf("expected exactly one URI SAN, got %d", len(uris))
    }
    return spiffeid.FromURI(uris[0])
}

// In the server, after the handshake:
id, err := peerID(r.TLS)
if err != nil || id.String() != "spiffe://example.org/cluster/cluster-a/ns/payments/sa/gateway" {
    http.Error(w, "forbidden", http.StatusForbidden)
    return
}
```

Prefer [`go-spiffe`](https://github.com/spiffe/go-spiffe)'s `tlsconfig` helpers, which do
the chain and ID check together. They read a SPIFFE Workload API socket by default;
point them at the files instead, or do the check by hand as above.

### Rust

```rust
// rustls: verify the chain normally, then check the ID after the handshake.
let (_, cert) = x509_parser::parse_x509_certificate(peer_der)?;
let uris: Vec<_> = cert
    .subject_alternative_name()?
    .into_iter()
    .flat_map(|san| san.value.general_names.iter())
    .filter_map(|name| match name {
        x509_parser::extensions::GeneralName::URI(u) => Some(*u),
        _ => None,
    })
    .collect();
if uris.len() != 1 || uris[0] != expected_spiffe_id {
    return Err(Error::Forbidden);
}
```

### Envoy / service mesh

If a sidecar terminates TLS, put the check in its configuration rather than the
application. Envoy matches URI SANs directly:

```yaml
validation_context:
  trusted_ca: { filename: /var/run/svid/ca.crt }
  match_typed_subject_alt_names:
    - san_type: URI
      matcher:
        prefix: "spiffe://example.org/cluster/cluster-a/ns/payments/sa/"
```

### Verifying by hand

```sh
# Chain: does the CA in this volume actually vouch for this certificate?
openssl verify -CAfile /var/run/svid/ca.crt /var/run/svid/tls.crt

# Identity and remaining lifetime.
openssl x509 -in /var/run/svid/tls.crt -noout -dates -ext subjectAltName

# Does the key go with the certificate? (Both hashes must match.)
openssl x509 -in /var/run/svid/tls.crt -noout -pubkey | openssl sha256
openssl pkey -in /var/run/svid/tls.key -pubout | openssl sha256

# A live peer, from inside the pod.
openssl s_client -connect billing:8443 \
  -CAfile /var/run/svid/ca.crt \
  -cert /var/run/svid/tls.crt -key /var/run/svid/tls.key </dev/null 2>/dev/null |
  openssl x509 -noout -ext subjectAltName
```

---

## 3. Reaching cloud resources

All three clouds can be told to trust an external certificate authority and exchange a
client certificate for their own short-lived credentials. That removes the long-lived
cloud key from the pod: the workload holds only a certificate that expires in a day and
renews itself.

This is configuration on the cloud side plus a token exchange in the workload. Svidlet's
part is over once the files are in the volume — it does not call any cloud API. The
snippets below are a starting point, not a substitute for each provider's own docs; none
of them is exercised by this repository's tests.

### AWS — IAM Roles Anywhere

Best fit of the three: it is designed for exactly this.

```sh
# One-time, per trust domain. The bundle is your intermediate, not a leaf.
aws rolesanywhere create-trust-anchor \
  --name svidlet \
  --source 'sourceType=CERTIFICATE_BUNDLE,sourceData={x509CertificateData="'"$(cat ca.crt)"'"}'

aws rolesanywhere create-profile \
  --name payments-api --role-arns arn:aws:iam::123456789012:role/payments-api
```

Scope the IAM role's trust policy to one SPIFFE ID, so the trust anchor does not grant
every workload in the fleet the same access. IAM Roles Anywhere exposes the certificate's
SANs as condition keys:

```json
{
  "Effect": "Allow",
  "Principal": { "Service": "rolesanywhere.amazonaws.com" },
  "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
  "Condition": {
    "StringEquals": {
      "aws:PrincipalTag/x509SAN/URI":
        "spiffe://example.org/cluster/cluster-a/ns/payments/sa/api"
    }
  }
}
```

In the pod, the credential helper turns the certificate into normal AWS credentials:

```sh
aws_signing_helper credential-process \
  --certificate /var/run/svid/tls.crt \
  --private-key /var/run/svid/tls.key \
  --trust-anchor-arn "$TRUST_ANCHOR_ARN" \
  --profile-arn "$PROFILE_ARN" \
  --role-arn "$ROLE_ARN"
```

Wire it into `~/.aws/config` as a `credential_process` and every AWS SDK picks it up
without application changes. The helper re-reads the certificate on each call, so
renewals are handled for free.

### GCP — Workload Identity Federation with X.509

```sh
gcloud iam workload-identity-pools create svidlet --location=global
gcloud iam workload-identity-pools providers create-x509 spiffe \
  --workload-identity-pool=svidlet --location=global \
  --trust-store-config-path=trust-store.json     # contains your ca.crt
```

Map the SPIFFE ID to the federated principal, then grant that principal — not the whole
pool — access to a resource:

```sh
gcloud storage buckets add-iam-policy-binding gs://payments-data \
  --role=roles/storage.objectViewer \
  --member="principal://iam.googleapis.com/projects/$NUM/locations/global/workloadIdentityPools/svidlet/subject/spiffe://example.org/cluster/cluster-a/ns/payments/sa/api"
```

In the pod, a credential configuration file pointing at the two files lets the Google
SDKs do the exchange:

```json
{
  "type": "external_account",
  "audience": "//iam.googleapis.com/projects/NUM/locations/global/workloadIdentityPools/svidlet/providers/spiffe",
  "subject_token_type": "urn:ietf:params:oauth:token-type:mtls",
  "token_url": "https://sts.googleapis.com/v1/token",
  "credential_source": {
    "certificate": {
      "certificate_config_location": "/etc/gcp/certificate-config.json"
    }
  }
}
```

Set `GOOGLE_APPLICATION_CREDENTIALS` to that file.

### Azure — no first-party equivalent yet

Azure has no certificate-based workload federation that accepts an arbitrary CA the way
the other two do. The options, in order of preference:

1. **Federated identity credentials with OIDC** — the supported path, but it takes a JWT,
   not an X.509 certificate. Use the cluster's projected ServiceAccount token for Azure
   and keep svidlet's certificate for service-to-service mTLS. Two credentials, each
   doing what it is good at.
2. **A certificate on an app registration** — works, but the certificate must be uploaded
   to the app registration in advance. Svidlet's certificates last a day and are minted
   on the node, so this does not fit without an upload loop, which is worse than option 1.

Do not contort the design to make option 2 work. Using the platform's own token for the
platform's own API is the right answer.

### The general shape

Whichever cloud, the same rules apply:

- **Trust the intermediate, not a leaf.** Leaves change daily.
- **Scope by SPIFFE ID.** A trust anchor alone says "someone in this fleet". Condition the
  role on the exact URI SAN, or you have granted every workload the same access.
- **Point the exchange at the files, not a copy.** Anything that reads the certificate
  once at start-up breaks at the first renewal.

---

## 4. Revocation

**Svidlet does not implement revocation, and this is deliberate** — short lifetimes
replace it. There is no CRL and no OCSP responder. The question "how do I revoke a
certificate" therefore has a different answer depending on what actually went wrong.

### The certificate is still in a running pod

Delete the pod. The kubelet calls `NodeUnpublishVolume`, svidlet unmounts the tmpfs and
removes the directory, and the key is gone from the node. The certificate remains
cryptographically valid until it expires, so this only helps if the key never left the
pod.

```sh
kubectl delete pod -n payments api-7d9f
```

### A key has leaked

The certificate is valid until `notAfter` — at most 24 h at the default, and you can see
exactly how long:

```sh
openssl x509 -in tls.crt -noout -enddate
```

There is no way to invalidate it before then short of a CA rotation. What you can do
immediately is stop the *identity* from being useful:

- Revoke the identity at the authorization layer. If peers check SPIFFE IDs — as they
  must — removing that ID from the policy bundle stops it being accepted fleet-wide
  within one polling interval, without touching PKI at all. **This is the fast path, and
  it is the reason policy distribution exists.**
- For a cloud role, remove the IAM condition or the federated principal binding. Takes
  effect on the next credential exchange.
- Delete the ServiceAccount or the workload so no *new* certificate is issued for it.

### Stopping issuance for a namespace or identity

Tighten `SVIDLET_SPIFFE_ID_PATTERN`, or the Vault role's `allowed_uri_sans`, and the next
request for that identity is refused — by the node and by Vault respectively. Existing
certificates are unaffected until they expire.

### A node is compromised

The node can mint any identity in its cluster, so the certificate is the smaller problem.

1. Cordon and drain the node.
2. Rotate that cluster's AppRole secret ID — the attacker may have copied it. Svidlet
   re-reads the secret on its next login, so healthy nodes do not need a restart.
3. Consider whether the blast radius justifies rotating the cluster's PKI role or the
   intermediate CA.

### Rotating the CA

The full stop, for when a leaked key must actually be invalidated. Cross-sign or add the
new intermediate to the trust bundle first: `ca.crt` is refreshed on every node on the CA
refresh interval (1 h by default), and workloads must trust the new root *before* leaves
signed by it appear, or every handshake in the fleet fails.

1. Add the new intermediate to Vault's CA chain. Wait for `ca.crt` to propagate
   everywhere — check `svidlet_ca_refresh_total` on every node.
2. Switch the PKI role to issue from the new intermediate.
3. After one full certificate lifetime, every leaf is from the new intermediate.
4. Remove the old intermediate from the chain.

Skipping step 1's wait is the way to break a whole fleet at once.

---

## 5. Troubleshooting

| Symptom | Where to look |
|---|---|
| Pod stuck `ContainerCreating` | `kubectl describe pod` — svidlet's error is in the mount failure. `InvalidArgument` means the volume context is missing a field (check `podInfoOnMount`); `PermissionDenied` means `SVIDLET_SPIFFE_ID_PATTERN` refused the identity; `Unavailable` means `SVIDLET_POLICY_REQUIRED` is set and no policy arrived. |
| `permission denied` reading `tls.key` | `SVIDLET_KEY_GID` does not match the workload's `runAsGroup`. |
| Handshake fails after ~12 h | The application read the key once at start-up and never reloaded. |
| Intermittent handshake failures at renewal | Certificate and key loaded separately across a swap. Retry the load once. |
| Peer accepted that should not be | The peer's SPIFFE ID is not being checked — only the CA. See §2. |
| `svidlet_earliest_certificate_expiry_seconds` falling | Renewal is failing. `svidlet_issue_failures_total{code=…}` says why. |
| Policy not updating | `svidlet_bundle_age_seconds` on the `svidlet-policy` container (port 9465), and `svidlet_policy_stream_connected`. |

```sh
kubectl -n svidlet-system logs -l app.kubernetes.io/name=svidlet -c svidlet --tail=50
kubectl -n svidlet-system logs -l app.kubernetes.io/name=svidlet -c svidlet-policy --tail=50
```
