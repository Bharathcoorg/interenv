# Multi-stage lightweight build for InterEnv
FROM rust:bookworm AS builder

WORKDIR /usr/src/interenv
RUN apt-get update && apt-get install -y libdbus-1-dev pkg-config

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY benches ./benches

RUN cargo build --release --bin interenv

# Production minimal runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates libdbus-1-3 tini && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/interenv/target/release/interenv /usr/local/bin/interenv

ENTRYPOINT ["/usr/bin/tini", "--", "interenv"]
CMD ["--help"]
