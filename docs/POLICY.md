# Svidlet — Policy Bundle Distribution

**Status:** Design draft · **Date:** 2026-09-05 · **Depends on:** [DESIGN.md](DESIGN.md)

## TL;DR

Alongside each workload's certificate, Svidlet mounts a **policy bundle**: a signed, versioned, content-addressed set of files (authorization rules, trust configuration, feature flags — Svidlet does not interpret them) that applications read from the same volume. The source of truth is a Git repository; CI turns each reviewed commit into a signed OCI artifact; nodes pull artifacts from a registry, verify them, and swap them in atomically.

Rollout is not "push the latest": a small signed **rollout manifest** assigns bundle versions to **rings** (dev clusters → 1 % of nodes → 25 % → 100 %). Each node computes its ring deterministically and converges to whatever the manifest says. Promotion between rings is a Git change gated by bake time and health metrics; rollback is the same change in reverse and takes one polling interval. A node that cannot fetch, verify, or validate a new bundle keeps the one it has and reports why — a bad bundle can never take a fleet down.

## Problem

- Identity without authorization is half a system: services need to know *which* SPIFFE IDs may call them. Today that configuration ships inside application images or ConfigMaps, so a policy change is either an image rebuild or an unversioned, unreviewed, cluster-local edit.
- Fleet-wide configuration changes are the most common cause of large outages. A distribution mechanism that reaches every node must be able to stop, stage, and reverse itself.
- Git is the right place to review policy, but it is the wrong thing for 20k nodes to fetch from: no atomic snapshot delivery, no CDN, credential sprawl.
- Svidlet already has a per-pod volume, a per-node process, and a signed trust model. Reusing them avoids a second agent.

## Requirements

- Bundle content is opaque to Svidlet; it only guarantees integrity, provenance, atomicity, and version visibility.
- Every bundle a node applies is signed by a key the fleet trusts; unsigned or mis-signed bundles are never written to a pod volume.
- Staged rollout by ring, with deterministic node assignment, bake times, automatic halt on health signals, and one-step rollback.
- Nodes fail **stale, not open and not closed**: on any error they keep the current bundle and alert on age.
- No Kubernetes API server access from the node plugin (same constraint as certificate issuance).
- Load on the registry scales with node count × polling interval, not with pod count.

## Design

### 1. Source of truth: Git

A `policy` repository holds the bundle content under `bundle/` plus `bundle.toml` (schema version, human description). Changes go through pull requests. CI on the default branch:

1. validates schema and runs the repository's own tests against the bundle;
2. packages `bundle/` as a tar, computes its digest;
3. signs the digest (Sigstore/cosign keyless, or an Ed25519 key held in Vault Transit — one choice per fleet);
4. pushes it as an OCI artifact (`oras push`) tagged with the Git commit SHA;
5. records `sha → digest` in `releases.json` in the same repository.

Git is never contacted by nodes. The registry is the distribution plane; Git is the audit and review plane.

### 2. Rollout manifest

A second file in the same repository, `rollout.toml`, is also CI-signed and pushed to the registry under a fixed tag. It is the only thing nodes poll unconditionally.

```toml
schema = 1
freeze = false               # true halts all changes fleet-wide (kill switch)

[[ring]]
name = "dev"
match = { clusters = ["dev-*"] }
bundle = "sha256:…a1"

[[ring]]
name = "canary"
match = { node_hash_percent = 1 }
bundle = "sha256:…a1"

[[ring]]
name = "broad"
match = { node_hash_percent = 25 }
bundle = "sha256:…a1"

[[ring]]
name = "all"
match = { node_hash_percent = 100 }
bundle = "sha256:…9f"       # previous version still here until promotion
```

- A node evaluates rings top to bottom and takes the first match. `node_hash_percent` compares `hash(cluster, node_name) mod 100` against the threshold, so ring membership is stable across restarts and the same node is always the canary for every rollout — which is what you want for a canary.
- Promotion = editing `rollout.toml` in a PR (or a bot doing so after bake time and health checks). Rollback = the same edit pointing an earlier ring back to the previous digest.
- `freeze = true` stops nodes from applying any change, including rollbacks; it is the "stop everything, humans are looking" switch.

### 3. Node behaviour (Svidlet)

Every 60 s ± 30 s jitter, per node (not per pod):

1. Fetch `rollout.toml` by tag with an `If-None-Match` ETag; unchanged → done.
2. Verify its signature; on failure keep current state and raise `svidlet_rollout_manifest_invalid`.
3. Compute this node's ring and target digest. If equal to current, done.
4. Pull the target bundle **by digest**, verify the signature over that digest, unpack to `versions/<digest>/` in a node-local tmpfs.
5. Run node-side validation: schema version supported, size limit, and the bundle's optional `selftest/` cases if present. Failure → keep current, raise `svidlet_bundle_rejected{reason}`.
6. Atomically swap a `current` symlink to the new version. The pod volume contains `policy/ → current/`, so every pod on the node sees the new bundle at the same instant, with no partially written state ever visible.
7. Keep the previous two versions on disk so a rollback needs no network.
8. Report `svidlet_bundle_version{digest, ring}` and `svidlet_bundle_age_seconds`.

Applications read `policy/` from the same CSI volume that carries their certificate and reload on inotify, exactly as they do for certificate rotation. Bundles carry an `enforce = true|false` flag in their own manifest so a new rule set can be rolled out in shadow mode (evaluated and logged, not enforced) before the switch is flipped in a second, tiny rollout.

### 4. Rollout safety, end to end

| Failure | What happens |
|---|---|
| Registry unreachable | Node keeps current bundle; `bundle_age` climbs; alert at a configured max age (e.g. 24 h). Traffic unaffected. |
| Bundle fails signature or validation on some nodes | Those nodes keep current; `bundle_rejected` fires; promotion bot refuses to advance while any ring reports rejections. |
| Bundle valid but wrong (breaks traffic) | Canary ring (1 %) shows the error rate first; bot halts; humans roll back by editing `rollout.toml`; nodes converge within one polling interval from local disk. |
| Manifest itself is bad | Signature fails → ignored. Well-formed but wrong → `freeze` in the previous manifest cannot help; this is why manifest edits go through PR review and CI validation like bundles. |
| Compromised CI | Can push a bundle it signs. Mitigation: signing key in Vault Transit with a policy allowing only the release pipeline's identity; audit log of every signature; optionally two keys (build and release) with nodes requiring both. |

Promotion gate (bot or human) between rings: minimum bake time per ring (dev 1 h, canary 4 h, broad 12 h), zero `bundle_rejected` in the current ring, and application-level error rate on ring members within tolerance of the rest of the fleet. All three are Prometheus queries; the bot is a scheduled job that opens the promotion PR when they pass and comments why when they don't.

## Out of Scope

- Policy language, evaluation, or enforcement. Svidlet delivers bytes.
- Per-pod or per-namespace targeting. Rings are clusters and nodes; if a bundle must differ per tenant, that is a policy-language concern (the bundle can contain all tenants' rules).
- Delta or compressed updates beyond what OCI layers already provide. Bundles are expected to be small (< 10 MB).

## Open Questions

1. **Signing scheme.** Sigstore keyless gives transparency-log auditability but adds a network dependency on Fulcio/Rekor at verification time (mitigable with bundled verification material); an Ed25519 key in Vault Transit is simpler and fully offline-verifiable. Lean: Vault Transit, since Vault is already a dependency.
2. **Registry.** Any OCI registry works; for very large fleets a pull-through cache per cluster (or per region) keeps registry load at cluster count, not node count.
3. **Should nodes ever "pre-pull" the next ring's bundle** so a promotion is instant? Cheap to add, reduces convergence time from one interval to near zero. Defer until needed.
4. **Ring definition for multi-cluster fleets.** `clusters` globs plus `node_hash_percent` cover most cases; a `ring = "manual"` list of node names may be wanted for one-off debugging.

## Appendix

### A. On-disk layout (node)

```
/var/lib/svidlet/policy/
  versions/sha256-…a1/   unpacked bundle
  versions/sha256-…9f/   previous
  current -> versions/sha256-…a1
  rollout.toml           last verified manifest
  state.json             ring, digest, last success, last error
```

### B. Bundle manifest (`bundle.toml`, inside the artifact)

```toml
schema = 1
description = "allow inference-gateway -> model-runner; deny all else"
enforce = true
created = 2026-09-05T00:00:00Z
git_sha = "…"
```

### C. Metrics

`svidlet_bundle_version{digest,ring}`, `svidlet_bundle_age_seconds`, `svidlet_bundle_rejected_total{reason}`, `svidlet_rollout_manifest_invalid_total`, `svidlet_registry_fetch_errors_total`, `svidlet_bundle_swap_total`.

### D. Milestones

1. Manifest + bundle fetch, signature verification, atomic swap, metrics. Single ring.
2. Rings, node hashing, `freeze`, shadow-mode flag, previous-version retention.
3. Promotion bot with bake time and health gates; pull-through cache guidance.

---

## Implementation notes

Three places where the implementation had to make the design concrete, and one where it deviates.

### The trust chain is one signature, not two

Section 3 step 4 says "verify the signature over that digest". The implementation gets that property without a second signing operation: the rollout manifest is signed, and the rollout manifest names each ring's bundle **by digest**. So the chain is

```
trusted Ed25519 public key  →  rollout.toml signature  →  bundle digest  →  bundle bytes
```

A node verifies the manifest signature, then checks that the SHA-256 of the blob it pulled equals the digest the signed manifest named. Tampering with a bundle changes its digest, which no longer matches the signed manifest. Tampering with the manifest breaks its signature. There is nothing a per-bundle signature would add, and one fewer signing step is one fewer thing for CI to get wrong.

The signed envelope carrying `rollout.toml` is deliberately boring, so CI can produce it with a few lines of shell:

```json
{
  "svidlet_signature": 1,
  "algorithm": "ed25519",
  "key_id": "release-2026",
  "payload": "<base64 of rollout.toml>",
  "signature": "<base64 of Ed25519 over the raw rollout.toml bytes>"
}
```

Nodes hold only the public key (`SVIDLET_BUNDLE_PUBLIC_KEY`), so verification is fully offline — which resolves Open Question 1 in favour of Ed25519 for the node side regardless of how CI chooses to hold the private half. Vault Transit signing in CI produces exactly this envelope.

### Pods get a copy, not a symlink

Section 3 step 6 says the pod volume contains `policy/ → current/`. That cannot work: `current` lives in `/var/lib/svidlet/policy/` on the host, and a pod's mount namespace has no such path — the symlink would dangle inside every container.

The implementation keeps the node-local `versions/` + `current` layout exactly as designed, as the node's cache and rollback store, and **materialises** the bundle into each pod's tmpfs through the volume writer that already publishes `tls.crt`. That preserves the property the symlink was there for — every pod sees the whole new bundle at one instant, never a partial one — because the pod volume is itself swapped atomically through its `..data` symlink. It costs one copy per pod of a sub-10 MB bundle into tmpfs.

A consequence worth stating: pods converge on a new bundle as the plugin walks them, not literally simultaneously. The walk is local file writes with no network in it, so the window is milliseconds across a node's pods rather than the seconds a re-pull would take.

### Node-side validation

Step 5's "the bundle's optional `selftest/` cases" is not implemented: running arbitrary test cases from a downloaded artifact is a code-execution path on every node in the fleet, and the design does not say what a test case *is*. What is implemented is the rest of step 5 — schema version, size limit, `bundle.toml` well-formedness — plus strict extraction: the tar reader accepts regular files with ordinary relative names and refuses everything else (absolute paths, `..` components, symlinks, hard links, device nodes, setuid bits). A malicious bundle cannot write outside its version directory.

If executable self-tests are wanted later, they belong behind an explicit opt-in with a declared interpreter, not as a default.

### Relationship to the gRPC policy source

Svidlet already had a policy source: a bidirectional gRPC stream per node, subscribing per SPIFFE ID, described in [DESIGN.md](DESIGN.md). The two now sit behind one seam and write to the same `policy/` directory in the volume:

| | gRPC stream | OCI bundle (this document) |
|---|---|---|
| Granularity | per SPIFFE ID | fleet-wide, one bundle per ring |
| Direction | backend pushes | node polls |
| Latency to converge | sub-second | one polling interval |
| Staged rollout | no | rings, bake time, freeze |
| Provenance | transport trust only | signed artifact, content-addressed |

They can run together — a per-identity bundle from the stream takes precedence over the fleet bundle for that identity — but most deployments want one or the other. `SVIDLET_POLICY_ENABLED=false` still switches off both.
