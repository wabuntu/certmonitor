# Multi-stage build: compile with the full Rust toolchain, ship only the
# resulting binary in a minimal runtime image.
FROM rust:1-slim-bookworm AS builder
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake \
    && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/certmonitor /usr/local/bin/certmonitor

EXPOSE 8080
ENTRYPOINT ["certmonitor"]
CMD ["--serve", "0.0.0.0:8080", "/etc/certmonitor/targets.txt"]
