# Backlog

## Done — v0.1

- APDU framing: I/S/U, sequence numbers, length bounds, malformed-frame
  rejection, fuzz target.
- ASDU parsing: header, COT, common address, IOA, fixed-size objects,
  sequence objects, optional zero-IOA system-command encoding.
- Command classification: process/system/parameter/file writes; read-only
  allows interrogation/read/test.
- Scoped command policy: type, common address, IOA range, select/execute,
  deny-overrides, default deny.
- Unknown master-to-RTU types refused by default.
- Terminating proxy: independent sequence spaces, S-frame acks, k window,
  t1 timeout, TESTFR termination, STARTDT/STOPDT forwarding.
- Negative activation confirmation for denied commands; denied commands never
  reach the outstation.
- IP allow-list, connection cap, per-master upstream connection.
- JSON audit, Prometheus metrics, health endpoints.
- `gateway`, `validate`, `selftest`, `version`.
- YAML and flags configuration with strict validation.
- Independent interop with `wendy512/iec104` master + outstation.
- Loopback address-takeover proof (old address disappears on stop).
- Coverage floors and release targets.

## Quality and test backlog (active)

The v0.1 happy path works. The next risk is the sequence/state machine and
peer behavior, not line coverage. Work in this order.

1. **Programmable peer harness.** Extended the in-process outstation/master:
   multiple connections, spontaneous frames, connection closes, partial
   frames, thread-safe sequence handling. Status: done.
2. **Sequence/state matrix.** Wrap, duplicate, gap, stale ack, ack beyond send,
   k-window saturation, t1 expiry, concurrent sends, outstation close,
   partial frame. Status: done.
3. **Policy matrix including SBO.** Every write family, read-only, default
   deny/allow, allow/deny rules, multi-object, no-IOA, select/execute. Status:
   done.
4. **Spontaneous and multi-master traffic.** Device-initiated data and two
   masters with separate upstream sessions. Status: done.
5. **Audit and metrics wiring.** Allowed/denied command records, audit file
   rotation, metric counters. Status: done.
6. **CLI and observability tests.** `probe`, `config.Load`, `Runner`, audit
   file, metrics serve, `gateway` context lifecycle, `validate` text/JSON and
   `selftest` success/failure. Status: done.
7. **Mutation checks.** Broke sequence validation, policy deny, P/N bit,
   unknown-type deny, ack validation and concurrent send ordering; each
   mutation was caught by a test. The concurrency check uses a deterministic
   send hook. Status: done.
8. **Independent peer expansion.** SBO select/execute and spontaneous data
   run through the interop script and assert at both ends. A second stack
   (`otfabric/go-iec104`) runs the full scenario alongside `wendy512/iec104`.
   Status: done for SBO, spontaneous data and the second implementation;
   outstation restart remains in Next.
9. **Coverage floors.** Raised to 80% overall, 84% proxy, 92% policy, 88%
   observability, 68% command. Status: done.

## Done — reload pass

- SIGHUP reload with an atomic `gatewayRuntime` snapshot: command policy,
  read_only, allow_unknown_types, allow-list, max_clients, dial/idle timeout,
  t1 and k. Policy revocation applies to an established session on its next
  frame; allow-list and max_clients apply to new connections.
  listen_addr, device_addr and adding/removing a device are reported as
  restart-only, never silently ignored.
- A bad file keeps the running configuration. `scripts/smoke-reload.sh`
  proves deny -> SIGHUP -> allow and broken-file retention with the real
  binary; `make acceptance` runs it with no skips.

## Done — shielding pass

- `rate_per_sec`: token bucket for master-to-outstation I-frames, shared
  across all masters on a device. An over-rate request gets a negative
  activation confirmation, is audited with reason `rate_limit`, and never
  reaches the RTU. RTU-to-master monitoring data is not limited.
- `min_interval_ms`: shared minimum gap between forwarded master I-frames,
  to protect a fragile RTU from a polling storm.
- Both are in the reloadable runtime snapshot, validated as non-negative,
  exposed as `--rate-per-sec` / `--min-interval-ms`, and covered by unit and
  end-to-end tests (burst denial, refill, pacing gap, reload).
- File/log transfer types 120–127 stay write-class: denied by the secure
  default, fixed-size types can be explicitly allowed, and variable-size
  125/127 always fail closed because their objects cannot be authorized.
  Content inspection remains out of scope.

## Done — peer expansion

- A second independent stack, `otfabric/go-iec104`, runs the full interop
  scenario (interrogation, spontaneous data, allowed/denied commands, SBO,
  address takeover) alongside `wendy512/iec104`.
- Outstation restart: the master session closes when the outstation dies, and
  a restarted outstation on the same address gets a fresh upstream connection
  for the next master.
- `docs/conformance-matrix.md` maps APCI, sequence, ASDU, command, shielding
  and interop behaviour to tests, and names the remaining lab-only gaps
  (t2/t3/w, physical RTU, real ARP/NDP, external conformance suite).

## Done — design decisions

- IEC 62351 posture: terminate TLS on the master leg first (option B), with a
  TLS upstream leg as the same code path (option C). IEC 62351-5 ASDU
  authentication is deferred until a design partner requires it. See
  `docs/iec62351-posture.md`.
- HA: active/standby with a shared service address and no session-state
  replication. The standby stays passive and never dials the RTU; failover
  loses the session and never replays an in-flight command. See
  `docs/ha-design.md`.

## Done — packaging

- Hardened systemd unit: dedicated user, `CAP_NET_BIND_SERVICE` only,
  `ProtectSystem=strict`, `ProtectHome`, no new privileges, address-family
  restriction, and `ExecReload` wired to SIGHUP.
- Release SBOMs (SPDX + CycloneDX) and a grype HIGH-or-worse gate in
  `scripts/sbom.sh` / `make security`.
- CRA technical-file working outline in `docs/cra-technical-file.md`.
- Operations runbook in `examples/operations.md`: install, validate, SIGHUP
  reload, shielding tuning, audit/metrics, fail-closed behaviour, upgrade and
  troubleshooting.
- Signed release artefacts and an update-signing key remain in Next.

## Next

1. **Real RTU lab.** One physical or vendor simulator: interrogation,
   spontaneous data, select-before-operate, clock sync, redundant channels.
2. **Real IP takeover.** Lab interface or two NICs; ARP/NDP, gratuitous ARP,
   duplicate-address detection, switch CAM, privileged port 2404.
3. **IEC 62351-3 TLS implementation.** Option B from
   `docs/iec62351-posture.md`: terminate TLS on the master leg, keep the RTU
   leg plaintext, and add the upstream TLS variant. IEC 62351-5 stays later.
4. **HA implementation.** Active/standby per `docs/ha-design.md`: shared
   service address, passive standby, no state replication, no command replay.
5. **Multi-master.** If an RTU accepts one connection, either enforce
   `max_clients: 1` or design safe session multiplexing.
6. **DNP3.** Only after IEC-104 has a design partner; separate protocol
   engine, not a port of this one.
7. **Signed releases and update channel.** Sign binaries and SBOMs, publish
   checksums, and define how an appliance verifies an update before installing
   it.
