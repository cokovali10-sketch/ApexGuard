# Contributing to ApexGuard

Thanks for your interest! ApexGuard is a security platform — code quality and safety
matter more than feature count. Please read this before opening issues or PRs.

## Code of Conduct

All participants must follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## Repository layout

```
core/            AegisCore event bus (Go, gRPC)
kernelshield/    eBPF probes (C) + agent (Rust)
pulsefuzz/       API fuzzer (Go)
shadownet/       Deception honeynet (Python/asyncio)
hexeye/          Static analyzer (Python service + Rust core)
apexconsole/     3D console (TypeScript/Vite/Three.js)
proto/           ThreatEvent schemas (Protobuf v3)
deploy/          docker-compose + Helm chart
docs/            Technical design
```

## Getting started

1. Fork and clone the repo.
2. Install tooling: `go`, `python 3.11+`, `node 18+`, `docker`, `buf` + `protoc` (for proto changes), `pytest`.
3. Run the test suite before and after your changes:

```bash
make test
```

## What we look for in a PR

- **Small, focused changes.** One concern per PR.
- **Tests** for any new logic. Go: `go test ./...`. Python: `pytest`.
- **No secrets, ever.** Never commit keys, tokens, or `.env` files.
- **Security-conscious code.** Threat events are attacker-controlled data —
  treat them as untrusted input. No `innerHTML` with event data, no shell
  interpolation without quoting, no logging of sensitive values.
- **Regenerated proto** if you touch `proto/events.proto` (`buf generate`).

## Development notes

### Adding a new RPC to the bus

1. Add the message + RPC to `proto/events.proto` (with a `google.api.http`
   annotation for gRPC-Gateway).
2. Run `buf generate` to regenerate `core/gen/`.
3. Implement the handler in `core/internal/server/server.go`.
4. Add a console action in `apexconsole/src/main.ts` (REST via `/v1/<name>`).

### Running individual module tests

```bash
cd core && go test ./...
cd pulsefuzz && go test ./...
cd shadownet && python -m pytest
python hexeye/tests/test_analyzer.py
```

## Commit style

- Imperative subject line (`Add airgap metrics`, `Fix ws origin check`).
- Explain *why* in the body when non-obvious.
- No `fix`, `update`, `wip` by themselves.

## Reporting security issues

Do **not** open a public issue for security vulnerabilities. See
[`SECURITY.md`](SECURITY.md) for the private disclosure process.
