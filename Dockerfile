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
COPY crates/svidlet-token/Cargo.toml crates/svidlet-token/
COPY crates/svidlet-token-issuer/Cargo.toml crates/svidlet-token-issuer/
RUN for c in svidlet svidlet-issue svidlet-token svidlet-token-issuer; do \
      mkdir -p crates/$c/src && touch crates/$c/src/lib.rs; \
    done \
 && echo 'fn main() {}' > crates/svidlet/src/main.rs \
 && echo 'fn main() {}' > crates/svidlet-token-issuer/src/main.rs \
 && echo 'fn main() {}' > crates/svidlet/build.rs \
 && echo 'fn main() {}' > crates/svidlet-token/build.rs \
 && cargo build --release --locked \
 && rm -rf crates/*/src crates/svidlet/build.rs crates/svidlet-token/build.rs

COPY crates crates
# COPY keeps the context's mtimes, which predate the stub build; touch every
# source so cargo rebuilds the workspace crates against the real ones.
RUN find crates -name '*.rs' -exec touch {} + \
 && cargo build --release --locked \
 && strip target/release/svidlet target/release/svidlet-policy \
          target/release/svidlet-token-issuer

# The Stage 2 token issuer: a central Deployment, not part of the node image.
#   docker build --target token-issuer -t svidlet-token-issuer .
FROM scratch AS token-issuer
COPY --from=build /src/target/release/svidlet-token-issuer /svidlet-token-issuer
ENTRYPOINT ["/svidlet-token-issuer"]

# The trust roots for reaching Vault are compiled in (webpki-roots), and a
# private Vault CA is supplied through VAULT_CACERT, so nothing else is needed.
# One image, two binaries. They run as two containers in the same DaemonSet pod
# so that identity issuance and policy distribution are separate processes with
# separate credentials — see docs/DESIGN.md, "Two processes, one volume".
FROM scratch
COPY --from=build /src/target/release/svidlet /svidlet
COPY --from=build /src/target/release/svidlet-policy /svidlet-policy
ENTRYPOINT ["/svidlet"]
