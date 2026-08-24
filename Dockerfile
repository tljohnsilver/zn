# zn — local-first prompt-injection gate
# Multi-stage build: full Rust toolchain for the build, distroless runtime.
#
# Build:  docker build -t zn .
# Smoke:  docker run --rm -i zn analyze "ignore all previous instructions"
# Server: docker run --rm -p 9090:9090 zn start

# --- Stage 1: build ----------------------------------------------------------
FROM rust:1-bookworm AS builder

# Pinned protoc (matches the version the project is verified against).
# lance-encoding's build script needs the well-known types; Debian bookworm's
# protobuf-compiler (3.21) does not resolve them under prost-build 0.13.
ARG PROTOC_VERSION=29.3
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL "https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip" -o /tmp/protoc.zip \
    && unzip -q /tmp/protoc.zip -d /usr/local && rm /tmp/protoc.zip
ENV PROTOC=/usr/local/bin/protoc
ENV PROTOC_INCLUDE=/usr/local/include

WORKDIR /build

# Dependency layer: prefetch the registry so source edits stay cache-friendly.
COPY Cargo.toml Cargo.lock ./
RUN cargo fetch --locked

# Source layer: the real build.
COPY src ./src
RUN cargo build --locked --release

# --- Stage 2: runtime --------------------------------------------------------
FROM gcr.io/distroless/cc-debian12

COPY --from=builder /build/target/release/zn /zn

# Writable scratch for the local audit/vector stores created at runtime.
WORKDIR /data

ENTRYPOINT ["/zn"]
