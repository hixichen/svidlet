# Using the Svidlet certificate

What a workload can do with the files in its volume — all of it, in one list.

**Depends on:** [DESIGN.md](DESIGN.md) · [../svidlet-policy/authz-management-plane.md](../svidlet-policy/authz-management-plane.md) · [../svidlet-policy/authz-enforcement-plane.md](../svidlet-policy/authz-enforcement-plane.md)

---

## 1. What you hold

```
/var/run/svid/
  tls.crt          leaf certificate, then any intermediates
  tls.key          PKCS#8 P-256 private key, mode 0640
  ca.crt           trust bundle for the whole trust domain
  jwt/<name>       a JWT-SVID per declared audience, same mode as tls.key
                   (only if the volume declares audiences — §3, "JWT-SVIDs")
  policy/          authorization rules        (only if a policy source is configured)
  policy.revision  upstream revision of those rules
```

The identity is the **URI SAN**, not the subject. The subject is a label — `CN=<pod name>` by default (`SVIDLET_CERT_SUBJECT`) — there because AWS IAM Roles Anywhere refuses a certificate without one and writes the CN into CloudTrail as `sourceIdentity`. Never authorize on it:

```sh
openssl x509 -in /var/run/svid/tls.crt -noout -subject -ext subjectAltName
# subject=CN=api-7d9f8c-x2x4q
# X509v3 Subject Alternative Name:
#     URI:spiffe://example.org/cluster/cluster-a/ns/payments/sa/api
```

Properties worth knowing before anything else:

| Property | Value |
|---|---|
| Key | P-256, generated on the node, never leaves the tmpfs |
| Lifetime | short (6 h by default), renewed at a random point between 50 % and 70 % |
| Chain | `tls.crt` = leaf + intermediates; `ca.crt` = the fleet's trust bundle |
| Updates | files are swapped atomically as a set — reload, don't re-read once |
| Group | `tls.key` is `0640`, owned by `SVIDLET_KEY_GID` = the workload's `runAsGroup` |

## 2. Reading the files without tripping on rotation

Four rules, all consequences of how the volume is published.

**Read `tls.crt` and `tls.key` as a pair.** They are swapped as a set, but an application that opens one, then the other, can straddle a renewal. Retry once before giving up:

```go
cert, err := tls.LoadX509KeyPair("/var/run/svid/tls.crt", "/var/run/svid/tls.key")
if err != nil {
    time.Sleep(50 * time.Millisecond) // a renewal landing mid-read
    cert, err = tls.LoadX509KeyPair("/var/run/svid/tls.crt", "/var/run/svid/tls.key")
}
```

**Never read `tls.key` once at start-up.** The key it holds expires with the certificate — days at most.

**Watch the directory, not the files.** The visible entries are symlinks; a renewal replaces what they point at. inotify (`fsnotify`, `notify`, `inotifywait`) on the directory catches both the certificate swap and the policy swap.

**For policy, stat `policy.revision`.** One file, changed on every upstream update — no directory walk needed.

Permissions, for completeness:

```yaml
# DaemonSet ConfigMap
SVIDLET_KEY_GID: "1000"
```
```yaml
# Workload
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000        # must match SVIDLET_KEY_GID
```

Do not reach for `SVIDLET_KEY_MODE=0644` when a workload cannot read its key — that makes the private key readable by every process that can see the volume.

## 3. What you can do with it

### Serve — be reachable only by your fleet

Any TLS server can use the pair: the server presents `tls.crt`, requires a client certificate, and verifies it against `ca.crt`. Everything outside the trust domain fails the handshake before your code runs.

```go
srv := &http.Server{
    Addr: ":8443",
    TLSConfig: &tls.Config{
        Certificates: []tls.Certificate{cert},      // the mounted pair
        ClientCAs:    caPool,                       // from /var/run/svid/ca.crt
        ClientAuth:   tls.RequireAnyClientCert,     // mTLS: demand an identity
        MinVersion:   tls.VersionTLS12,
    },
}
```

Works the same for gRPC, HTTP/2, and raw TCP-with-TLS.

### Verify who is calling you — the step that makes mTLS mean anything

**A certificate signed by your CA is not an authorization.** Every workload in the trust domain has one. Checking only the CA proves the peer is *somebody* in your fleet — not the somebody that may call this endpoint.

The rules: verify the chain against `ca.crt`; extract the URI SAN (there must be **exactly one**); compare it against what this endpoint allows — bytes, not a parsed structure; ignore the subject, DNS SANs and serial, they carry nothing.

```go
import "github.com/spiffe/go-spiffe/v2/spiffeid"

func peerID(cs tls.ConnectionState) (spiffeid.ID, error) {
    if len(cs.PeerCertificates) == 0 {
        return spiffeid.ID{}, errors.New("no peer certificate")
    }
    if len(cs.PeerCertificates[0].URIs) != 1 {
        return spiffeid.ID{}, fmt.Errorf("expected exactly one URI SAN, got %d",
            len(cs.PeerCertificates[0].URIs))
    }
    return spiffeid.FromURI(cs.PeerCertificates[0].URIs[0])
}
```

### Decide what the caller may do — three tiers

1. **Hand-rolled allow-list** — compare `peerID` against an exact string or a namespace prefix right after the handshake. Fine for one service, does not scale to a fleet: per-team formats cannot be reviewed, rolled out, or revoked centrally.
2. **The SDK** — `svidlet-sdk-go` loads `policy/authz.toml` from the same volume, evaluates CEL rules per request, and reloads on change. Shadow mode, fleet-wide revocation, staged rollout — this is the intended path. [../svidlet-policy/authz-enforcement-plane.md](../svidlet-policy/authz-enforcement-plane.md).
3. **The mesh** — if Envoy/Istio/Linkerd terminates TLS, put the check in the proxy and don't distribute policy at all:

```yaml
validation_context:
  trusted_ca: { filename: /var/run/svid/ca.crt }
match_typed_subject_alt_names:
  - san_type: URI
    matcher:
      prefix: "spiffe://example.org/cluster/cluster-a/ns/payments/sa/"
```

### Call other services — be the somebody on the other side

The same pair is a client certificate. Dial peers that require mTLS and your identity travels with you:

```go
client := &http.Client{Transport: &http.Transport{
    TLSClientConfig: &tls.Config{
        Certificates: []tls.Certificate{cert}, // presented to the server
        RootCAs:      caPool,                  // verify the server's fleet membership
    },
}}
```

The server you call matches your SPIFFE ID against its own policy — you are, by construction, a principal in somebody else's rule.

### Authenticate to any backend that takes a TLS client certificate

Not just your own services: anything that accepts a client certificate over TLS can be handed this pair — from service code or from the CLIs you already run in the pod.

- **PostgreSQL:** `sslcert=/var/run/svid/tls.crt sslkey=/var/run/svid/tls.key sslrootcert=/var/run/svid/ca.crt`. Honest caveat: Postgres's `cert` authentication maps the CN, and the CN here is the pod name — different for every replica — so this gives you a *known-fleet* client cert plus an encrypted channel, not per-identity database users. `SVIDLET_CERT_SUBJECT=service_account` makes the CN stable per ServiceAccount, which a `pg_ident.conf` map can use, but the CN is not namespace- or cluster-qualified: treat it as a convenience, not an identity. Identity-scoped database auth properly needs an auth hook or a proxy that reads the URI SAN.
- **Kafka, brokers, private registries, internal dashboards:** same shape — client certificate for transport, with the caveat that ACL systems that key on CN rather than URI SAN see a pod name, not an identity. The identity signal is in the SAN; use it where the product reads it.

### Exchange it for AWS credentials

[IAM Roles Anywhere](https://docs.aws.amazon.com/rolesanywhere/) is designed for exactly this: a trust anchor for your CA, a profile mapping to an IAM role, and a credential helper that turns the certificate into normal AWS credentials — no long-lived cloud key in the pod.

```sh
# One-time, per account: anchor on the ROOT. Intermediates travel in tls.crt,
# so rotating an intermediate never touches AWS.
aws rolesanywhere create-trust-anchor --name svidlet \
  --source 'sourceType=CERTIFICATE_BUNDLE,sourceData={x509CertificateData=<root PEM>}'

# In the pod: every AWS SDK picks this up via ~/.aws/config credential_process.
aws_signing_helper credential-process \
  --certificate /var/run/svid/tls.crt --private-key /var/run/svid/tls.key \
  --trust-anchor-arn "$TRUST_ANCHOR_ARN" --profile-arn "$PROFILE_ARN" --role-arn "$ROLE_ARN"
```

The helper re-reads the certificate on every call, so renewals are free. **Scope every role's trust policy to a cluster-qualified SPIFFE path** — a trust anchor alone grants every workload in the fleet the role, and `cluster/*` grants every cluster:

```json
"Condition": {
  "StringLike": {
    "aws:PrincipalTag/x509SAN/URI": "spiffe://example.org/cluster/prod-*/ns/payments/sa/api"
  }
}
```

Two certificate rules Roles Anywhere enforces, both met by default: the Subject must not be empty (`SVIDLET_CERT_SUBJECT=none` breaks this), and only the first URI SAN is mapped (svidlet issues exactly one). The CN appears in CloudTrail as `sourceIdentity`, which is how an AWS call is traced back to a pod.

### Exchange it for GCP credentials

[Workload Identity Federation with X.509](https://cloud.google.com/iam/docs/workload-identity-federation-with-x509-certificates): an X.509 provider with your root as the trust anchor, and the SPIFFE ID mapped into attributes. `google.subject` is capped at 127 bytes, so map the cluster-relative path into it and keep the whole ID as an attribute:

```sh
gcloud iam workload-identity-pools providers create-x509 svidlet \
  --location=global --workload-identity-pool=svidlet \
  --trust-store-config-path=trust_store.yaml \
  --attribute-mapping="google.subject=assertion.san.uri.extract('spiffe://example.org/cluster/{id}'),attribute.spiffe_id=assertion.san.uri" \
  --attribute-condition="assertion.san.uri.startsWith('spiffe://example.org/cluster/prod-')"

gcloud storage buckets add-iam-policy-binding gs://payments-data \
  --role=roles/storage.objectViewer \
  --member="principal://iam.googleapis.com/projects/$NUM/locations/global/\
workloadIdentityPools/svidlet/subject/cluster-a/ns/payments/sa/api"
```

In the pod, a certificate-based credential configuration pointing at the two files lets the Google client libraries do the mTLS token exchange themselves (`google-auth` ≥ 2.39, `cloud.google.com/go/auth` ≥ 0.16).

Whether a given certificate would pass either cloud is something svidlet can tell you before a pod finds out: set `SVIDLET_CLOUD_PROFILE=aws,gcp` and watch `svidlet_cloud_profile_findings_total`.

### Azure — keep two credentials, each doing what it is good at

Azure has no first-party certificate federation that accepts an arbitrary CA. The supported path is federated identity credentials with OIDC: use the cluster's projected ServiceAccount token for Azure, and keep the svidlet certificate for service-to-service mTLS. Do not contort the design to upload six-hourly certificates to an app registration. Where the node runs the token issuer, a JWT-SVID with `aud=api://AzureADTokenExchange` replaces the ServiceAccount token — see the next section.

### JWT-SVIDs — for relying parties that only speak OIDC

Declare the audiences in the volume, the way a projected ServiceAccount token does:

```yaml
volumes:
  - name: svid
    csi:
      driver: csi.svidlet.io
      readOnly: true
      volumeAttributes:
        audiences: "azure=api://AzureADTokenExchange,snowflake"
```

Each entry is `name=audience`, or a bare audience that is itself a valid file name; at most eight. The pod then holds `jwt/azure` and `jwt/snowflake`: compact ES256 JWTs with `sub` = your SPIFFE ID, `aud` = the audience, `iss` = the trust domain's token issuer, and `exp` no later than your certificate's. They are swapped together with the certificate at every renewal, so the rules of §2 apply unchanged — read the file when you need the token, never once at start-up.

```sh
# Azure: a federated identity credential with issuer = the token issuer's URL,
# subject = your SPIFFE ID, audience = api://AzureADTokenExchange. Then:
export AZURE_FEDERATED_TOKEN_FILE=/var/run/svid/jwt/azure
```

Declaring an audience is a request, not a grant: the issuer's grants say which SPIFFE IDs may have which audiences, and a pod asking for one it is not granted does not start (`PermissionDenied`). Tokens need the node to run with node bootstrap and `SVIDLET_TOKEN_ISSUER` set ([DEPLOY.md](DEPLOY.md#token-issuer-the-interface)).

### Prove your own identity, to yourself

The debugging toolkit:

```sh
openssl verify -CAfile /var/run/svid/ca.crt /var/run/svid/tls.crt   # does the CA vouch for me?
openssl x509 -in /var/run/svid/tls.crt -noout -dates -ext subjectAltName
openssl x509 -in /var/run/svid/tls.crt -noout -pubkey | openssl sha256   # do cert and key
openssl pkey -in /var/run/svid/tls.key -pubout | openssl sha256         # …match?

# A live peer, from inside the pod.
openssl s_client -connect billing:8443 -CAfile /var/run/svid/ca.crt \
  -cert /var/run/svid/tls.crt -key /var/run/svid/tls.key </dev/null 2>/dev/null |
  openssl x509 -noout -ext subjectAltName
```

## 4. What you cannot do with it

Just as important, and each of these has bitten someone:

- **Sign things.** The key is a TLS authentication key (`digitalSignature` in a TLS handshake), not a code-signing key. No artifact signing, no commit signing, no JWT-SVIDs signed by the node — JWTs are minted by the central token issuer (§3), never with this key. The key only proves to the issuer that the request is yours.
- **Issue certificates.** The leaf is not a CA, and nothing in the volume will make it one.
- **Act as a bearer secret.** Pasting the PEM into a header or a cookie is a misuse: any receiver would have to treat it as a long-lived password, which is exactly what the 6 h rotation exists to avoid.
- **Prove what you run.** The cert proves *who* runs — namespace and ServiceAccount per the kubelet. Whether that workload should exist is admission control's half of the chain, still future work ([DESIGN.md](DESIGN.md)).
- **Be trusted outside the trust domain.** A peer must hold your `ca.crt` to verify you. There is no federation with external trust domains; external systems need your bundle (as in the AWS/GCP exchanges above) or nothing.
- **Stand in for authorization.** The certificate answers "who is calling". Whether that caller may do it is a policy decision — §3, tier 2 or 3.

## 5. What "revoke" means — there is no CRL

No revocation, deliberately; short lifetimes replace it. So the answer depends on what went wrong:

**The certificate is in a pod you control.** Delete the pod. The kubelet unmounts the tmpfs, the key leaves the node, and the cert is gone. It remains valid until expiry, so this only helps if the key never left the pod.

**A key has leaked.** The cert is valid until `notAfter` — check it: `openssl x509 -in tls.crt -noout -enddate`. What stops the *identity* being useful, immediately, is policy:

- Remove the SPIFFE ID from the policy bundle — one PR, one ring cycle, peers refuse it fleet-wide before the cert expires. **This is the fast path, and it is the reason policy distribution exists.**
- For a cloud role, remove the IAM condition or the federated principal binding — takes effect on the next credential exchange.
- Delete the ServiceAccount so no new certificate is issued for it.

**Stopping issuance for a namespace or identity.** Tighten `SVIDLET_SPIFFE_ID_PATTERN` (the node refuses the next request) or the Vault role's `allowed_uri_sans` (Vault refuses it). Existing certificates are unaffected until they expire.

**A node is compromised.** The node can mint any identity in its cluster, so the certificate is the smaller problem: cordon and drain; remove its EK hash from the inventory and revoke its node certificate at the registration CA — its Vault token lasts at most an hour, and the node certificate at most a day, so it loses Vault even if the CRL step is late ([ROADMAP.md](ROADMAP.md) §3.4). On a dev cluster still on AppRole, rotate the secret ID instead (healthy nodes re-read it without a restart). Consider rotating the cluster's PKI role or the intermediate.

**Rotating the CA — the full stop**, for when a leaked key must actually be invalidated. Cross-sign or add the new intermediate first; `ca.crt` refreshes on every node within the CA refresh interval, and workloads must trust the new root *before* leaves signed by it appear, or every handshake in the fleet fails. Then switch the PKI role, wait out one full certificate lifetime, and remove the old intermediate. Skipping the wait is how you break a whole fleet at once.

## 6. Troubleshooting

| Symptom | Where to look |
|---|---|
| Pod stuck `ContainerCreating` | `kubectl describe pod` — the mount error is svidlet's. `InvalidArgument`: volume context missing a field (check `podInfoOnMount`); `PermissionDenied`: `SVIDLET_SPIFFE_ID_PATTERN` refused the identity; `Unavailable`: `SVIDLET_POLICY_REQUIRED` is set and no policy arrived. |
| Pod stuck, `PermissionDenied` naming an audience | No grant at the token issuer for this SPIFFE ID and audience. `FailedPrecondition`: the node has no `SVIDLET_TOKEN_ISSUER`. `Unavailable`: the issuer is unreachable; the kubelet retries. |
| `permission denied` reading `tls.key` | `SVIDLET_KEY_GID` does not match the workload's `runAsGroup`. |
| Handshake fails ~6 h after start | The application read the key once at start-up and never reloaded. |
| AWS `CreateSession` or GCP STS refuses the certificate | `svidlet_cloud_profile_findings_total{cloud,rule}` with `SVIDLET_CLOUD_PROFILE` set — the `rule` label names the problem (`subject`, `uri_san`, `chain_order`, …). |
| Intermittent handshake failures at renewal | Certificate and key loaded separately across a swap. Retry the load once. |
| Peer accepted that should not have been | The peer's SPIFFE ID is not being checked — only the CA. §3. |
| `svidlet_earliest_certificate_expiry_seconds` falling | Renewal is failing; `svidlet_issue_failures_total{code=…}` says why. |
| Policy not updating | `svidlet_bundle_age_seconds` on the `svidlet-policy` container (port 9465), and `svidlet_policy_stream_connected`. |

```sh
kubectl -n svidlet-system logs -l app.kubernetes.io/name=svidlet -c svidlet --tail=50
kubectl -n svidlet-system logs -l app.kubernetes.io/name=svidlet -c svidlet-policy --tail=50
```
