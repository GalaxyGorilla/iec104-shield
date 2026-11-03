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
   file, metrics serve. Status: done for probe/config/Runner/observ; the
   `gateway`, `validate` and `selftest` command paths still need tests.
7. **Mutation checks.** Broke sequence validation, policy deny, P/N bit,
   unknown-type deny and ack validation; each mutation was caught by a test.
   Concurrent-send ordering still needs a deterministic mutation hook. Status:
   done for the five critical invariants; one follow-up.
8. **Independent peer expansion.** SBO, spontaneous data, outstation restart,
   a second implementation. Status: pending.
9. **Coverage floors.** Raised to 72% overall, 82% proxy, 92% policy, 88%
   observability. Status: done.

## Next

1. **Real RTU lab.** One physical or vendor simulator: interrogation,
   spontaneous data, select-before-operate, clock sync, redundant channels.
2. **Real IP takeover.** Lab interface or two NICs; ARP/NDP, gratuitous ARP,
   duplicate-address detection, switch CAM, privileged port 2404.
3. **IEC 62351 posture.** Decide transparent vs terminating TLS; decide
   whether the proxy is an IEC 62351-5 authentication endpoint.
4. **SIGHUP reload.** Whole-snapshot policy swap, like the other Shield
   projects; never a half-applied mix.
5. **Conformance matrix.** Use IEC TS 60870-5-604 as the reference for test
   cases; add the cases the lab can run.
6. **HA.** Active/standby pair without state replication; define what happens
   to an in-flight command during failover.
7. **Multi-master.** If an RTU accepts one connection, either enforce
   `max_clients: 1` or design safe session multiplexing.
8. **Rate limiting and pacing.** Protect a fragile RTU from polling storms
   and bound per-master request rates, as the other Shield proxies do.
9. **File transfer.** Inspect or explicitly block file/log transfer types;
   v0.1 blocks them in read-only and otherwise treats them as writes.
10. **DNP3.** Only after IEC-104 has a design partner; separate protocol
    engine, not a port of this one.
11. **Packaging.** systemd hardening, SBOM, signed releases, CRA technical
    documentation.
