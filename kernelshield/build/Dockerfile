# syntax=docker/dockerfile:1
# KernelShield — воспроизводимый build-контейнер для CO-RE BPF.
# Использование:
#   docker build -t apexguard/kernelshield-builder .
#   docker run --rm -v $(pwd):/src apexguard/kernelshield-builder
#
# vmlinux.h генерируется из BTF; в CI без /sys/kernel/btf используйте
# --build-arg VMLINUX_BTF=... (BTFHub: https://github.com/aquasecurity/btfhub)

FROM debian:bookworm-slim AS toolchain

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    clang-15 \
    llvm-15 \
    libclang-15-dev \
    libelf-dev \
    libbpf-dev \
    bpftool \
    zlib1g-dev \
    linux-libc-dev \
    make \
    curl \
    ca-certificates \
    git \
  && rm -rf /var/lib/apt/lists/*

# Единые имена без версионного суффикса
RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-15 100 \
  && update-alternatives --install /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-15 100

WORKDIR /src

# Точка входа: make с возможностью подставить BTF
ENTRYPOINT ["make"]
CMD ["all"]
