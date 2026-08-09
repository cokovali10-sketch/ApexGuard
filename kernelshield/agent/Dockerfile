# syntax=docker/dockerfile:1
# KernelShield agent (Rust). Требует собранный probes/kernelshield.bpf.o.
# Сборка BPF-объекта:  docker build -t apexguard/kernelshield-builder -f kernelshield/build/Dockerfile kernelshield
#                      docker run --rm -v $(pwd):/src apexguard/kernelshield-builder all
FROM rust:1.84-bookworm AS build
WORKDIR /src
COPY kernelshield/agent/Cargo.toml kernelshield/agent/Cargo.lock* ./
RUN mkdir -p src/bpf && echo 'fn main() {}' > src/main.rs \
  && cargo build --release 2>/dev/null || true
COPY kernelshield/agent/build.rs ./
COPY kernelshield/agent/src ./src
# BPF-объект монтируется через build context
COPY kernelshield/probes/kernelshield.bpf.o ./probes/ 2>/dev/null || true
RUN cargo build --release --bin apexguard-agent || \
    (echo "!! соберите probes/kernelshield.bpf.o: make -C kernelshield all" && exit 1)

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libelf1 libzstd1 iproute2 \
  && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/apexguard-agent /usr/local/bin/apexguard-agent
# привилегии для eBPF (в композе: privileged, /sys/kernel/btf mount)
ENTRYPOINT ["apexguard-agent"]
