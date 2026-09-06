FROM rust:1.81-slim-bookworm AS builder
WORKDIR /build
COPY . .
RUN apt-get update && apt-get install -y --no-install-recommends libtss2-dev pkg-config libdbus-1-dev && rm -rf /var/lib/apt/lists/*
RUN cargo build --release --features tpm --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends libtss2-3.0.2-0 tini && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/interenv /usr/local/bin/interenv
COPY --from=builder /build/scripts/install.js /usr/local/lib/interenv/install.js
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/interenv"]
