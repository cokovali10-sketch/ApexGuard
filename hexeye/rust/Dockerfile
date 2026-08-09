# syntax=docker/dockerfile:1
# HexEye — статический анализатор (Rust core).
FROM rust:1.84-bookworm AS build
WORKDIR /src
COPY hexeye/rust/Cargo.toml hexeye/rust/Cargo.lock* ./
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs \
  && cargo build --release --locked 2>/dev/null || cargo build --release
COPY hexeye/rust/src ./src
RUN touch src/main.rs && cargo build --release --bin hexeye-core

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/hexeye-core /usr/local/bin/hexeye
ENTRYPOINT ["hexeye"]
