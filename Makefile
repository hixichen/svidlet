# A thin front door to the repository's real tooling: cargo for build and test,
# hack/ scripts for the multi-step flows. Each target below wraps the exact
# command README.md documents — the Makefile never re-implements a script, so a
# target and its script cannot drift apart.
#
#   make            # list targets
#   make ci         # the gate a change must pass: fmt --check, clippy, tests

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

# rustup installs cargo in ~/.cargo/bin, which non-interactive shells may not
# have on PATH. Prefixing cargo lines with $(RUN) both adds the directory and —
# because the line then contains a `$` — forces make to run the recipe through
# the shell rather than exec it directly, which would bypass the exported
# environment on some make versions (3.81 included).
RUN := PATH="$(HOME)/.cargo/bin:$$PATH"

# Overridable: IMAGE=ghcr.io/me/svidlet:0.1.0 make image
IMAGE        ?= svidlet:dev
TRUST_DOMAIN ?= example.org
CLUSTER      ?= cluster-a
# Which deploy/ overlay `make deploy` and `make e2e` use:
#   standalone | with-node-bootstrap | dev
VARIANT      ?= standalone
BUNDLE_DIR   ?= ./policy/bundle
ROLLOUT_FILE ?= ./rollout.toml

.DEFAULT_GOAL := help

.PHONY: help
help: ## list the available targets
	@awk -F':.*## ' '/^[a-zA-Z0-9_-]+:.*## / \
		{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ---------------------------------------------------------------- build & test

.PHONY: build
build: ## debug build of the whole workspace
	$(RUN) cargo build --workspace

.PHONY: release
release: ## release build of the whole workspace
	$(RUN) cargo build --release --workspace

.PHONY: test
test: ## unit + integration tests (337; no cluster, no Vault needed; run as root)
	$(RUN) cargo test --workspace

.PHONY: test-vault
test-vault: ## the 10 live-Vault integration tests (starts and stops a dev Vault)
	./hack/local-vault.sh start
	@status=0; \
	eval "$$(./hack/local-vault.sh env)"; \
	$(RUN) cargo test -p svidlet-issue -- --ignored || status=$$?; \
	./hack/local-vault.sh stop; \
	exit $$status

.PHONY: ci
ci: fmt-check clippy test ## the gate a change must pass

# ------------------------------------------------------------------- style

.PHONY: fmt
fmt: ## rewrite all sources with rustfmt
	$(RUN) cargo fmt --all

.PHONY: fmt-check
fmt-check: ## fail if any source is not rustfmt-clean
	$(RUN) cargo fmt --all -- --check

.PHONY: clippy
clippy: ## clippy over the workspace, all targets; any warning fails (lint set: Cargo.toml)
	$(RUN) cargo clippy --workspace --all-targets -- -D warnings

.PHONY: msrv
msrv: ## build everything on the minimum supported Rust (rust-version in Cargo.toml)
	$(RUN) cargo +$$(sed -n 's/^rust-version = "\(.*\)"/\1/p' Cargo.toml) build --workspace --all-targets

# ---------------------------------------------------------------- measurement

.PHONY: coverage
coverage: ## line-coverage report; fails below the 80% floor (needs cargo-llvm-cov)
	$(RUN) ./hack/coverage.sh

.PHONY: bench
bench: ## resident memory under real CSI load (needs a running Vault)
	$(RUN) ./hack/bench-memory.sh

# ------------------------------------------------------------------- e2e

.PHONY: e2e
e2e: ## kind + in-cluster Vault + VARIANT (default dev) + a workload, end to end (needs kind, kubectl, docker)
	VARIANT=$(if $(filter command line,$(origin VARIANT)),$(VARIANT),dev) $(RUN) ./hack/kind-e2e.sh

.PHONY: image
image: ## build the static two-binary image (scratch, musl)
	docker build -t $(IMAGE) .

# ------------------------------------------------------------------- policy

.PHONY: bundle-keygen
bundle-keygen: ## generate the fleet's Ed25519 signing key pair (once per fleet)
	./hack/build-bundle.sh keygen

.PHONY: bundle
bundle: ## package + push BUNDLE_DIR as a signed OCI artifact; prints the digest
	./hack/build-bundle.sh bundle $(BUNDLE_DIR)

.PHONY: bundle-rollout
bundle-rollout: ## sign ROLLOUT_FILE and push it to the tag nodes poll
	./hack/build-bundle.sh rollout $(ROLLOUT_FILE)

# ------------------------------------------------------------------- deploy

.PHONY: vault-bootstrap
vault-bootstrap: ## one-time PKI setup for a cluster: VAULT_ADDR=… VAULT_TOKEN=… make vault-bootstrap
	./deploy/vault-bootstrap.sh $(TRUST_DOMAIN) $(CLUSTER)

.PHONY: deploy
deploy: ## apply deploy/$(VARIANT) to the current kubectl context (VARIANT=with-node-bootstrap for node attestation)
	kubectl apply -k deploy/$(VARIANT)

.PHONY: manifests
manifests: ## render every deploy/ variant and validate it against the Kubernetes 1.31 schemas (needs kubectl, kubeconform)
	@for v in standalone with-node-bootstrap with-tokens dev token-issuer; do \
		printf '%-22s' "$$v"; \
		kubectl kustomize deploy/$$v | kubeconform -strict -kubernetes-version 1.31.0 -summary -; \
	done

# ------------------------------------------------------------------- housekeeping

.PHONY: clean
clean: ## remove build artifacts
	$(RUN) cargo clean
