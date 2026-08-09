# Security Policy

ApexGuard is a security product; the security of the platform itself is a first-class
requirement. We take reports seriously and respond as fast as we can.

## Reporting a vulnerability

**Do not open a public GitHub issue.** Please report privately:

- GitHub Security Advisory ("Report a vulnerability" button on the repo)
- Or email: **security@apexguard.dev** (PGP fingerprint available on request)

Please include:

- Module + version affected (e.g. `apexcore@1.0.0`)
- A minimal reproduction (config, proto/event, or code snippet)
- Impact assessment (e.g. "unauthenticated RCE via WS handler")
- Any suggested fix, if you have one

You will receive an acknowledgement within **72 hours**. We keep you updated
until the issue is resolved and coordinated disclosure is complete.

## Scope

In scope:

- All services under `core/`, `pulsefuzz/`, `shadownet/`, `hexeye/`, `kernelshield/`, `apexconsole/`
- Deployment assets (`deploy/`) and event schemas (`proto/`)

Out of scope (by design):

- The 3D console is an *operator* dashboard; it assumes an authenticated, trusted
  network. Do not expose it to the public internet without an auth proxy.
- The honeynet deliberately serves fake credentials and fake data.
- fuzzing/analysis targets under test are external to the platform.

## Security model highlights

- Threat events are **untrusted input** — modules must never render them into
  privileged sinks (DOM, shell, SQL) without sanitization.
- ApexCore gRPC supports mTLS (SPIFFE X509-SVID); use it in production.
- KernelShield requires privileged/root access by design (eBPF). It runs with
  `CAP_BPF`-scope boundaries and a read-only rootfs where possible.
- Honeypot containers are spawned with `network_mode: internal`, no caps,
  memory/pids limits and `no-new-privileges`.

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | yes       |
| < 1.0   | no        |
