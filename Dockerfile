# Built natively for the target architecture rather than cross-compiled, so
# `ring` gets a real musl toolchain and the result is one static binary.
FROM rust:1-alpine AS build

RUN apk add --no-cache musl-dev protobuf-dev
# build.rs only vendors protoc when PROTOC is unset; the vendored binary is
# glibc-linked and would not run here.
ENV PROTOC=/usr/bin/protoc

WORKDIR /src
# Dependencies first, so a source-only change does not rebuild the world.
COPY Cargo.toml Cargo.lock ./
COPY crates/svidlet/Cargo.toml crates/svidlet/
COPY crates/svidlet-issue/Cargo.toml crates/svidlet-issue/
COPY crates/svidlet-broker/Cargo.toml crates/svidlet-broker/
RUN mkdir -p crates/svidlet/src crates/svidlet-issue/src crates/svidlet-broker/src \
 && echo 'fn main() {}' > crates/svidlet/src/main.rs \
 && echo 'fn main() {}' > crates/svidlet-broker/src/main.rs \
 && touch crates/svidlet/src/lib.rs crates/svidlet-issue/src/lib.rs crates/svidlet-broker/src/lib.rs \
 && echo 'fn main() {}' > crates/svidlet/build.rs \
 && cargo build --release --locked \
 && rm -rf crates/svidlet/src crates/svidlet-issue/src crates/svidlet-broker/src crates/svidlet/build.rs

COPY crates crates
# Touch the entry points so cargo rebuilds the workspace crates against the
# now-real sources — build.rs included: the copied one is older than the stub
# that ran above, so without the touch cargo keeps the stub's (empty) output
# and the generated gRPC code never appears.
RUN touch crates/svidlet/build.rs crates/svidlet/src/main.rs crates/svidlet-issue/src/lib.rs crates/svidlet-broker/src/lib.rs \
 && cargo build --release --locked \
 && strip target/release/svidlet target/release/svidlet-policy \
          target/release/svidlet-broker target/release/oidc-publisher target/release/svidlet-catalog

# The trust roots for reaching Vault are compiled in (webpki-roots), and a
# private Vault CA is supplied through VAULT_CACERT, so nothing else is needed.
# One image, every binary. svidlet and svidlet-policy run as two containers in
# the same DaemonSet pod, so identity issuance and policy distribution are
# separate processes with separate credentials (docs/DESIGN-v0.1.md, "Two
# processes, one volume"). svidlet-broker runs as its own Deployment
# (docs/DESIGN.md §4); oidc-publisher and svidlet-catalog are control-plane
# tools.
FROM scratch
COPY --from=build /src/target/release/svidlet /svidlet
COPY --from=build /src/target/release/svidlet-policy /svidlet-policy
COPY --from=build /src/target/release/svidlet-broker /svidlet-broker
COPY --from=build /src/target/release/oidc-publisher /oidc-publisher
COPY --from=build /src/target/release/svidlet-catalog /svidlet-catalog
ENTRYPOINT ["/svidlet"]
