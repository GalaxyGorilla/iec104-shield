# CRA technical file — working outline

**Status:** working assumption, not a conformity claim. This document is the
outline the Shield appliance family will use for the EU Cyber Resilience Act
(CRA) technical file. It is deliberately explicit about what is implemented
and what is still evidence to collect. Legal classification and the final
scope belong to the manufacturer, not to this repository.

## 1. Product identification

- Product: IEC 104 Shield, a protocol-aware security gateway in the Shield
  appliance family.
- Version: v0.1 software prototype.
- Intended use: retrofit protection for a legacy IEC 60870-5-104 outstation
  that cannot authenticate or authorize its master. The gateway owns the
  master-visible address, moves the outstation behind it, forwards monitoring
  data, and enforces a command policy.
- Deployment: dedicated appliance or hardened Linux host at the substation
  boundary. It is not a general-purpose firewall and not a full IEC-104
  master/outstation stack.

## 2. Intended environment and users

- Trained utility/OT operators and integrators.
- Network position between the control-centre master and the RTU.
- Management access is local or on a separate management network; the
  metrics listener is bound to localhost or a management address.
- The device is expected to run unattended and to fail closed.

## 3. Architecture and data flow

```
master ──► old RTU address ──► iec104-shield ──► RTU at new address
```

- Terminating proxy, not a byte relay: independent N(S)/N(R) spaces per leg.
- One upstream connection per master; IEC-104 is stateful.
- APDU framing and ASDU parsing are in-house for strictness and fuzzing.
- Denied or rate-limited commands are answered with a negative activation
  confirmation and never forwarded.
- SIGHUP swaps the reloadable policy snapshot; listener/address changes need
  a restart and are reported.

## 4. Security requirements and evidence

| Requirement | Implementation | Evidence |
|---|---|---|
| Secure default | No command policy denies write-class ASDUs | `internal/config`, `internal/policy`, `TestDefaultDeniesWrites` |
| Deny never reaches the RTU | Negative activation confirmation built locally | `TestReadOnlyDeniesCommand`, interop scripts |
| Fail closed | Upstream/listener/session failure closes the master | `TestFailClosedWhenDeviceDown`, `TestOutstationRestart` |
| Unknown types fail closed | Private master types refused unless opted in | `TestUnknownMasterTypeDeniedByDefault` |
| Partial writes always refused | Unparseable write objects cannot be authorized | `TestFileTransferIsPolicyGated` |
| Sequence integrity | Independent spaces, wrap, k-window, t1, gap rejection | `internal/proxy` sequence tests |
| Shielding | Connection cap, IP allow-list, token bucket, pacing | `TestMaxClients`, `TestRateLimit*`, `TestPacing*` |
| Audit | Allowed and denied commands recorded | `TestAuditAllowedAndDeniedCommands` |
| Update/reload | SIGHUP applies one atomic snapshot; bad file kept | `TestReload*`, `scripts/smoke-reload.sh` |
| Cross-implementation interop | Two independent stacks | `scripts/interop-iec104.sh` |
| Master-leg transport security | IEC 62351-3 TLS, optional mTLS | `TestTLSGateway`, interop TLS scenario |
| Vulnerability handling | `govulncheck`, SBOM, grype scan | `make security`, `scripts/sbom.sh` |

## 5. Risk assessment (initial)

| Risk | Mitigation | Residual |
|---|---|---|
| Unauthorized breaker command | Default-deny write policy, deny-overrides, negative confirmation | Misconfigured explicit allow rules remain the operator's responsibility |
| Replay or spoofed master | IP allow-list; optional master-leg TLS/mTLS | No IEC 62351-5 ASDU authentication; network segmentation still required |
| Eavesdropping / MITM on the master leg | IEC 62351-3 TLS (option B) | RTU leg remains plaintext; upstream TLS not implemented |
| DoS against the RTU | Connection cap, rate limit, pacing | A determined master can still consume its own session |
| Compromised appliance | systemd hardening, minimal capabilities, no shell | Single box is a single point of failure; no HA |
| Supply-chain vulnerability | Pinned modules, govulncheck, SBOM | Signed releases and reproducible-build attestations still to add |
| Lost audit trail | JSON-lines audit with rotation | No remote syslog/forwarding in v0.1 |

## 6. Secure defaults

- No command policy means writes are denied.
- `allow_unknown_types` is off.
- `read_only` and `command_policy` are mutually exclusive.
- File/log transfer is write-class; variable-size 125/127 always fail closed.
- The process exits if the listener cannot bind; there is no fail-open mode.
- Metrics and audit paths are operator-configured; the example binds metrics
  to localhost.

## 7. Logging, monitoring and incident evidence

- Structured JSON audit events: connection accepted/rejected, upstream error,
  protocol error, command allowed/denied, ASDU denied, connection closed.
- Prometheus counters for connections, frames, forwarded/denied commands,
  parse errors, upstream errors and sequence errors.
- `/healthz` and `/readyz` for liveness/readiness.
- Audit rotation is size-based; the operator must ship or retain the files.

## 8. Update and vulnerability handling

- Release binaries are built with `make release-all`; SBOMs with
  `make release-assets` (syft).
- `govulncheck` and `grype` are part of the release gate; a HIGH finding
  blocks release.
- Dependency updates are ordinary Go module bumps with the full race suite,
  staticcheck, govulncheck and both interop peers re-run.
- Signed releases and an update-signing key are still to be added before a
  production claim.

## 9. Known gaps before a conformity claim

- No IEC 62351-5 ASDU authentication and no upstream TLS leg. Master-leg
  IEC 62351-3 TLS is implemented.
- No physical RTU lab or utility conformance suite.
- No real ARP/NDP takeover validation; the current proof is loopback only.
- No HA pair or state replication.
- No signed release artefacts or reproducible-build attestation.
- No formal penetration test or independent security assessment.
- CRA class II is a working assumption, not a legal determination.

## 10. Change control

This file is part of the repository. Update it when the architecture, security
requirements, dependencies, deployment unit or known limitations change. The
roadmap repository tracks the appliance-level decisions; this file tracks the
IEC-104 product evidence.
