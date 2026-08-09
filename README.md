# 🛡️ ApexGuard

> **Autonomous Enterprise Defense Cluster** — a full-stack offensive/defensive security platform
> that fuses **kernel-level threat detection (eBPF)**, an **AI deception honeynet**, **coverage-guided
> API fuzzing**, **binary reverse engineering**, and a **real-time 3D SOC console** into a single
> normalized event bus.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.22-00ADD8?logo=go&logoColor=white)](core/go.mod)
[![Rust](https://img.shields.io/badge/Rust-stable-DEA584?logo=rust&logoColor=white)](kernelshield/agent/Cargo.toml)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](shadownet/requirements.txt)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5-3178C6?logo=typescript&logoColor=white)](apexconsole/tsconfig.json)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?logo=githubactions&logoColor=white)](.github/workflows/ci.yml)

---

## 🌟 What it is

ApexGuard is an **all-in-one security operations platform** that turns a single host into a
self-contained **deception + detection + analysis lab**. Every sensor — from a kernel eBPF probe to
an AI-powered fake production server — speaks the **same protobuf `ThreatEvent` schema** and streams
into one core, which visualizes attacks live in a Three.js command console.

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

## 🧩 Modules

| Module | Stack | What it does |
|---|---|---|
| **ApexCore** · `core/` | Go · gRPC · grpc-gateway · WebSocket · Prometheus | Central event bus, command router, Panic/Air-Gap state, replay buffer, mTLS (SPIFFE) |
| **KernelShield** · `kernelshield/` | Rust + eBPF (CO-RE) | Syscall tracing (`execve`/`connect`/`ptrace`/`setuid`), kernel-level block, container → cgroup resolution |
| **PulseFuzz** · `pulsefuzz/` | Go | Coverage-guided API fuzzer: boundary, SQLi, SSTI, type-confusion, mass-assignment, **IDOR cross-session**, **JWT forgery** (alg-none / key-confusion / HMAC) |
| **ShadowNet** · `shadownet/` | Python 3 · asyncio · aiohttp | AI deception honeynet: SSH emulator backed by a local LLM, Docker-isolated honeypots (≤500 ms spawn), **honeytokens + watermarking**, MITRE ATT&CK mapping |
| **HexEye** · `hexeye/` | Python service · optional Rust core | Static binary analysis: ELF/PE parsing, secrets scanner, dangerous-sink call-graph, BOF/UAF heuristics, risk scoring |
| **ApexConsole** · `apexconsole/` | TypeScript · Vite · Three.js | 3D network topology, 10k-events/s particle renderer (InstancedMesh), live attack feed, source/severity filters, **Panic Mode** |

## 🔥 Highlights

- **One event model, five sensors** — normalized `ThreatEvent`s (`source`, `severity`,
  `mitre_technique`, `context`) from kernel, network, fuzzer, and static-analysis domains.
- **Command bus with Air-Gap** — a single click broadcasts an isolation command to every agent
  (Panic Mode), with durable state in the console.
- **Coverage-guided fuzzing with a state graph** — signature hashing, endpoint transitions, timing
  side-channel anomaly detection, and an energy-ranked seed corpus.
- **Real IDOR testing** — cross-session object-access checks with personal-data fingerprinting to
  kill false positives.
- **JWT attack suite** — forged tokens via `alg=none`, HS256 key confusion, and HMAC-secret reuse.
- **Deception with watermarking** — honeytokens embed a campaign watermark, register SHA-256
  fingerprints, and flag exposure anywhere in ingested bodies.
- **3D SOC console** — WebSocket → grpc-gateway → Protobuf, rendered at 60 fps with zero-alloc
  particle pooling, XSS-safe event rendering, and live per-source stats.
- **GitHub-ready engineering** — Go + Python test suites, `-race` in CI, buf lint + deterministic
  codegen diff check, Helm lint, dependabot, SECURITY/CONTRIBUTING/CoC.

## 🚀 Quick start

### Docker Compose (recommended)

```bash
docker compose -f deploy/docker-compose.yml up --build
```

Open <http://localhost> — the console proxies `/v1/*`, `/ws/*` and `/metrics` to ApexCore.

> `kernelshield` runs behind a compose *profile* (`--profile kernel`) because it needs a Linux host
> with BTF (`CONFIG_DEBUG_INFO_BTF`) and privileged access.

### Kubernetes (Helm)

```bash
helm install apexguard deploy/helm/apexguard
```

### Local development

```bash
# proto (requires buf)
buf generate

# core
cd core && go run ./cmd/apexcore

# pulsefuzz (HTTP API on :9091)
cd pulsefuzz && go run . -listen :9091 -spec api/openapi.json -target http://127.0.0.1:8080

# shadownet (SSH :2222 + HTTP API :8081)
python -m shadownet.honeypot.ssh_server --host 0.0.0.0 --port 2222 --docker

# hexeye (HTTP API :9092)
python hexeye/server.py --listen 0.0.0.0:9092

# console
cd apexconsole && npm install && npm run dev
```

## 🧪 Testing

```bash
make test        # go build + vet + test (core, pulsefuzz) + pytest (shadownet, hexeye)
make lint        # go vet + python -m compileall + yaml parse
make proto       # buf lint + buf generate
```

## 📦 Event model

Every module emits the same normalized `ThreatEvent` (see [`proto/events.proto`](proto/events.proto)):

- `source` — `KERNELSHIELD | PULSEFUZZ | SHADOWNET | HEXEYE | CORE`
- `severity` — `INFO → CRITICAL`
- `mitre_technique` — e.g. `T1059.004`, `T1071.001`, `T1552.001`
- `context` — free-form key/value payload

Commands flow the other way: `BlockIp`, `ReloadProbes`, `AirGap` (Panic Mode), plus proxied
`TriggerFuzz`, `SpawnHoneypot`, `AnalyzeBinary`.

## 🛡️ Security

- **Panic Mode (Air-Gap)** — one click isolates the environment; state is broadcast to agents and
  persisted in the console.
- **Metrics everywhere** — every service exposes `/metrics` for Prometheus; ApexCore aggregates
  event rate, drops, and subscriber counts.
- **Hardened containers** — `no-new-privileges`, dropped capabilities, `read_only` rootfs for
  honeypots, 128 MB / 0.5 CPU cgroup budget, and a **no-egress** deception network.
- **Defense-in-depth on the wire** — WebSocket Origin checks (CSWSH), optional bearer auth, mTLS
  (SPIFFE X509-SVID bundles via `TLS_CERT`/`TLS_KEY`/`TLS_CA`).

Security issues should be reported privately — see [`SECURITY.md`](SECURITY.md).

## 📚 Documentation

- [`docs/TDD.md`](docs/TDD.md) — technical design & threat model
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — how to contribute
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)
- [`SECURITY.md`](SECURITY.md)

## 🗺️ Roadmap

- [x] Unified `ThreatEvent` bus + command router
- [x] Coverage-guided fuzzing with IDOR + JWT forgery
- [x] AI honeynet with honeytoken watermarking
- [x] Static analysis with risk scoring
- [x] 3D console with Panic Mode
- [ ] Real-time kernel blocklist propagation (eBPF map sync)
- [ ] NATS-backed event fan-out
- [ ] Threat-intel enrichment (MISP/OpenCTI)
- [ ] SOC playbook automation

## 📄 License

[Apache License 2.0](LICENSE)
