<div align="center">

# ApexGuard

### Autonomous Enterprise Defense Cluster

[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?logo=githubactions&logoColor=white)](#)
[![License](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.22-00ADD8?logo=go&logoColor=white)](core/go.mod)
[![Rust](https://img.shields.io/badge/Rust-stable-DEA584?logo=rust&logoColor=white)](kernelshield/agent/Cargo.toml)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](shadownet/requirements.txt)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5-3178C6?logo=typescript&logoColor=white)](apexconsole/tsconfig.json)
[![gRPC](https://img.shields.io/badge/gRPC-Protobuf-4285F4)](proto/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)](#)

A full-stack security operations platform that fuses **kernel-level eBPF threat detection**, an **AI deception honeynet**, **coverage-guided API fuzzing**, **binary reverse engineering**, and a **real-time 3D SOC console** — all streaming into a single normalized event bus.

</div>

---

## What It Is

ApexGuard turns a single host into a self-contained **deception + detection + analysis lab**. Every sensor — from a kernel eBPF probe to an AI-powered fake production server — speaks the same protobuf `ThreatEvent` schema and streams into one core, which visualizes attacks live in a Three.js command console.

```
                     ┌──────────────────────────────┐
                     │      APEXCONSOLE (3D UI)     │
                     │    WebSocket + gRPC-Gateway  │
                     └──────────────▲───────────────┘
  ┌───────────┐   ┌────────────────┴─────────────────┐   ┌────────────┐
  │KernelShield│  │                                  │◄──│   HexEye   │
  │ eBPF agent │──►│          AEGIS CORE             │   │  RE/static │
  └───────────┘   │    gRPC bus | WS bridge | REST   │   └────────────┘
  ┌───────────┐   │                                  │   ┌────────────┐
  │ PulseFuzz │──►│        metrics | airgap           │◄──│  ShadowNet │
  │ Go engine │   │                                  │   │ AI honeynet│
  └───────────┘   └────────────────┬─────────────────┘   └────────────┘
                                   │
                           Events → Console (live)
```

---

## Modules

### ApexCore (`core/`)
**Go · gRPC · grpc-gateway · WebSocket · Prometheus**

Central event bus and command router. Manages Panic/Air-Gap state, replay buffer, and mTLS (SPIFFE X509-SVID bundles). Every module connects here.

### KernelShield (`kernelshield/`)
**Rust + eBPF (CO-RE)**

Kernel-level syscall tracing (`execve`/`connect`/`ptrace`/`setuid`), kernel-level blocking, and container → cgroup resolution. Requires Linux with BTF support.

### PulseFuzz (`pulsefuzz/`)
**Go**

Coverage-guided API fuzzer with:
- Boundary, SQLi, SSTI, type-confusion, mass-assignment testing
- **IDOR cross-session** object-access checks with personal-data fingerprinting
- **JWT forgery** — `alg=none`, HS256 key confusion, HMAC-secret reuse
- Signature hashing, endpoint transitions, timing side-channel detection
- Energy-ranked seed corpus

### ShadowNet (`shadownet/`)
**Python 3 · asyncio · aiohttp**

AI deception honeynet:
- SSH emulator backed by a local LLM
- Docker-isolated honeypots (≤500 ms spawn)
- Honeytokens with campaign watermarking
- MITRE ATT&CK technique mapping

### HexEye (`hexeye/`)
**Python service · optional Rust core**

Static binary analysis:
- ELF/PE parsing and secrets scanning
- Dangerous-sink call-graph analysis
- Buffer overflow / use-after-free heuristics
- Risk scoring engine

### ApexConsole (`apexconsole/`)
**TypeScript · Vite · Three.js**

Real-time 3D SOC console:
- 3D network topology visualization
- 10k-events/s particle renderer (InstancedMesh, zero-alloc pooling)
- Live attack feed with source/severity filters
- **Panic Mode** — one-click environment isolation
- XSS-safe event rendering

---

## Highlights

| Feature | Details |
|---------|---------|
| **Unified Event Model** | Normalized `ThreatEvent` (`source`, `severity`, `mitre_technique`, `context`) from 5 sensor domains |
| **Command Bus with Air-Gap** | Single-click isolation broadcast to all agents (Panic Mode) with durable state |
| **Coverage-Guided Fuzzing** | State graph, signature hashing, timing side-channel detection, energy-ranked seeds |
| **Real IDOR Testing** | Cross-session object-access checks with personal-data fingerprinting |
| **JWT Attack Suite** | `alg=none`, HS256 key confusion, HMAC-secret reuse |
| **Deception with Watermarking** | Honeytokens embed campaign watermarks, register SHA-256 fingerprints |
| **3D SOC Console** | WebSocket → grpc-gateway → Protobuf at 60 fps |
| **Production Engineering** | Go + Python test suites, `-race` in CI, buf lint, Helm, dependabot, SECURITY/CONTRIBUTING/CoC |

---

## Quick Start

### Docker Compose (Recommended)

```bash
docker compose -f deploy/docker-compose.yml up --build
```

Open **http://localhost** — the console proxies `/v1/*`, `/ws/*` and `/metrics` to ApexCore.

> `kernelshield` runs behind a compose profile (`--profile kernel`) because it needs Linux with BTF and privileged access.

### Kubernetes (Helm)

```bash
helm install apexguard deploy/helm/apexguard
```

### Local Development

```bash
# Proto (requires buf)
buf generate

# Core
cd core && go run ./cmd/apexcore

# PulseFuzz (HTTP API :9091)
cd pulsefuzz && go run . -listen :9091 -spec api/openapi.json -target http://127.0.0.1:8080

# ShadowNet (SSH :2222 + HTTP API :8081)
python -m shadownet.honeypot.ssh_server --host 0.0.0.0 --port 2222 --docker

# HexEye (HTTP API :9092)
python hexeye/server.py --listen 0.0.0.0:9092

# Console
cd apexconsole && npm install && npm run dev
```

---

## Event Model

Every module emits the same normalized `ThreatEvent` (see [`proto/events.proto`](proto/events.proto)):

| Field | Values |
|-------|--------|
| `source` | `KERNELSHIELD` · `PULSEFUZZ` · `SHADOWNET` · `HEXEYE` · `CORE` |
| `severity` | `INFO` → `CRITICAL` |
| `mitre_technique` | e.g. `T1059.004`, `T1071.001`, `T1552.001` |
| `context` | Free-form key/value payload |

Commands flow the other way: `BlockIp`, `ReloadProbes`, `AirGap` (Panic Mode), plus proxied `TriggerFuzz`, `SpawnHoneypot`, `AnalyzeBinary`.

---

## Testing

```bash
make test        # go build + vet + test (core, pulsefuzz) + pytest (shadownet, hexeye)
make lint        # go vet + python compileall + yaml parse
make proto       # buf lint + buf generate
```

---

## Security

- **Panic Mode (Air-Gap)** — one click isolates the environment; state broadcast to agents and persisted in console
- **Metrics everywhere** — every service exposes `/metrics` for Prometheus
- **Hardened containers** — `no-new-privileges`, dropped capabilities, `read_only` rootfs, 128 MB / 0.5 CPU cgroup budget, no-egress deception network
- **Defense-in-depth** — WebSocket Origin checks (CSWSH), optional bearer auth, mTLS (SPIFFE)

---

## Documentation

- [`docs/TDD.md`](docs/TDD.md) — technical design & threat model
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — how to contribute
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)
- [`SECURITY.md`](SECURITY.md)

---

## Roadmap

- [x] Unified `ThreatEvent` bus + command router
- [x] Coverage-guided fuzzing with IDOR + JWT forgery
- [x] AI honeynet with honeytoken watermarking
- [x] Static analysis with risk scoring
- [x] 3D console with Panic Mode
- [ ] Real-time kernel blocklist propagation (eBPF map sync)
- [ ] NATS-backed event fan-out
- [ ] Threat-intel enrichment (MISP/OpenCTI)
- [ ] SOC playbook automation

---

## License

[Apache License 2.0](LICENSE)
