# A thin front door to the repository's real tooling: cargo for build and test,
# hack/ scripts for the multi-step flows. Each target below wraps the exact
# command README.md documents — the Makefile never re-implements a script, so a
# target and its script cannot drift apart.
#
#   make            # list targets
#   make ci         # the gate a change must pass: fmt --check, clippy, docs, tests
#   make tidy       # reclaim disk after a build, keeping the dependency cache

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
BUNDLE_DIR   ?= ./policy/bundle
ROLLOUT_FILE ?= ./rollout.toml

# The plugin's tests mount real tmpfs and bind mounts, so their binaries need
# root. As root, run them directly; otherwise cargo runs as you and only the
# test binaries go through sudo (hack/root-tests.toml), so target/ never ends
# up owned by root.
ifeq ($(shell id -u),0)
TEST_FLAGS :=
else
TEST_FLAGS := --config hack/root-tests.toml
endif

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
test: ## unit + integration tests (323; no cluster, no Vault; test binaries run as root)
	$(RUN) cargo test --workspace $(TEST_FLAGS)

.PHONY: test-broker
test-broker: ## the v0.2 broker path alone: rules, node through broker, the binaries
	$(RUN) cargo test -p svidlet-broker $(TEST_FLAGS)

.PHONY: test-vault
test-vault: ## the 6 live-Vault integration tests (starts and stops a dev Vault)
	./hack/local-vault.sh start
	@status=0; \
	eval "$$(./hack/local-vault.sh env)"; \
	$(RUN) cargo test -p svidlet-issue -- --ignored || status=$$?; \
	./hack/local-vault.sh stop; \
	exit $$status

.PHONY: ci
ci: fmt-check clippy doc test ## the gate a change must pass (what CI runs)

# ------------------------------------------------------------------- style

.PHONY: fmt
fmt: ## rewrite all sources with rustfmt
	$(RUN) cargo fmt --all

.PHONY: fmt-check
fmt-check: ## fail if any source is not rustfmt-clean
	$(RUN) cargo fmt --all -- --check

.PHONY: clippy
clippy: ## clippy over the workspace, all targets; warnings fail, as in CI
	$(RUN) cargo clippy --workspace --all-targets -- -D warnings

.PHONY: doc
doc: ## build the API docs; broken intra-doc links fail, as in CI
	RUSTDOCFLAGS="-D warnings" $(RUN) cargo doc --workspace --no-deps

# ---------------------------------------------------------------- measurement

.PHONY: coverage
coverage: ## line-coverage report; fails below the 80% floor (needs cargo-llvm-cov)
	$(RUN) ./hack/coverage.sh

.PHONY: bench
bench: ## resident memory under real CSI load (needs a running Vault)
	$(RUN) ./hack/bench-memory.sh

# ------------------------------------------------------------------- e2e

.PHONY: e2e
e2e: ## kind + dev Vault + DaemonSet + a workload, end to end (needs kind, kubectl, docker)
	$(RUN) ./hack/kind-e2e.sh

.PHONY: image
image: ## build the static image (scratch, musl): node plugin, policy daemon, broker, tools
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
deploy: ## v0.1: apply the CSIDriver and DaemonSet (nodes sign against Vault)
	kubectl apply -f deploy/csidriver.yaml
	kubectl apply -f deploy/daemonset.yaml

.PHONY: deploy-broker
deploy-broker: ## v0.2: apply the broker, the broker-mode CSIDriver and node DaemonSet
	kubectl apply -f deploy/broker/csidriver.yaml
	kubectl apply -f deploy/broker/broker.yaml
	kubectl apply -f deploy/broker/node.yaml

CATALOG ?= deploy/broker/catalog.toml

.PHONY: catalog
catalog: ## lint CATALOG and print CLUSTER's Vault policy and SPIFFE roles
	$(RUN) cargo run -q -p svidlet-broker --bin svidlet-catalog -- lint $(CATALOG)
	$(RUN) cargo run -q -p svidlet-broker --bin svidlet-catalog -- policy $(CATALOG) $(CLUSTER)
	$(RUN) cargo run -q -p svidlet-broker --bin svidlet-catalog -- roles $(CATALOG) $(CLUSTER)

# ------------------------------------------------------------------- housekeeping

.PHONY: tidy
tidy: ## reclaim disk after a build: drop incremental caches and this workspace's own artifacts, keep compiled dependencies
	rm -rf target/debug/incremental target/release/incremental
	$(RUN) cargo clean -p svidlet -p svidlet-issue -p svidlet-broker
	@du -sh target 2>/dev/null || true

.PHONY: size
size: ## how much disk target/ uses, and where
	@if [ -d target ]; then \
		du -sh target/*/deps target/*/incremental target/*/build 2>/dev/null || true; \
		du -sh target; \
	else echo "no target/"; fi

.PHONY: clean
clean: ## remove all build artifacts (the next build recompiles every dependency)
	$(RUN) cargo clean
