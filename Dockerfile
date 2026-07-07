# GraphHunter — reproducible Linux build for the agentic LLM-as-compiler
# path. Single-stage; intentionally Spartan. The image targets the
# cross-platform platform/* crates only — no Tauri (GUI), no
# libgraphmatch (AVX2/x86), no GNN models. What runs here is the
# auditable core: VRL compiler + constrained-decode (validator and
# xgrammar-backed sampler) + canonical projection + local-llm mock.
#
# Why a Dockerfile and not just the GitHub Actions matrix:
# the matrix proves the code builds on macOS+Linux runners. This image
# proves the code builds *and runs* on a fixed, redistributable Linux
# base. It's what BH Arsenal attendees pull and exercise without
# installing a Rust toolchain on their laptop.
#
# Build:    docker build -t graphhunter:dev .
# Smoke:    docker run --rm graphhunter:dev cargo test \
#               --manifest-path platform/constrained-decode/Cargo.toml \
#               --features xgrammar
# Demo:     docker run --rm graphhunter:dev cargo test \
#               --manifest-path platform/api/Cargo.toml \
#               --test agentic_ambiguous_fields

# Rust 1.88+ required: edition 2024 (stable in 1.85), llguidance 1.7 /
# toktrie 1.7 declare rust-version = "1.87", and time@0.3.47 (pulled
# transitively by evtx → chrono in the api crate) declares 1.88.
# Pinning the minimum supported toolchain so the image fails fast if
# a transitive dep ever raises the floor again.
FROM rust:1.88-slim-bookworm

# Build prerequisites for tokenizers (onig via cc), openssl-sys (pulled
# by the api crate's transitive HTTP/TLS deps), and anything else that
# touches a C compiler in transitive deps.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        pkg-config \
        cmake \
        build-essential \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

# Copy the platform/* and core/* sources plus the docs spec the test
# harness reads (vrl_subset.lark canary). Demo data is needed for the
# F12.4 fixtures.
COPY core ./core
COPY platform ./platform
COPY demo_data ./demo_data
COPY docs/spec ./docs/spec
COPY scripts ./scripts

# Pre-fetch every dependency once. From here on, `cargo test` is hermetic.
# The api crate is included so the F12.4 smoke (`agentic_ambiguous_fields`)
# does not need to re-resolve the dep graph at `docker run` time.
RUN cargo fetch --manifest-path platform/constrained-decode/Cargo.toml \
 && cargo fetch --manifest-path platform/vrl/Cargo.toml \
 && cargo fetch --manifest-path platform/local-llm/Cargo.toml \
 && cargo fetch --manifest-path platform/canonical/Cargo.toml \
 && cargo fetch --manifest-path platform/api/Cargo.toml

# Build (default features only — the xgrammar feature is exercised in
# the smoke command so the image stays slim). Failure here is
# load-bearing: we do not want a broken image to ship.
RUN cargo build --manifest-path platform/constrained-decode/Cargo.toml \
 && cargo build --manifest-path platform/vrl/Cargo.toml \
 && cargo build --manifest-path platform/local-llm/Cargo.toml \
 && cargo build --manifest-path platform/canonical/Cargo.toml \
 && cargo build --manifest-path platform/api/Cargo.toml --tests

# Default entry point: print a one-liner that points at the smoke
# commands. Override at `docker run` time as documented above.
CMD ["sh", "-c", "echo 'GraphHunter image ready. Run cargo test against any platform/*/Cargo.toml.'"]
