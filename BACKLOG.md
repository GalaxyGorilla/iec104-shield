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
   now run through the interop script and assert at both ends. Outstation
   restart and a second independent implementation remain. Status: partial.
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

## Next

1. **Real RTU lab.** One physical or vendor simulator: interrogation,
   spontaneous data, select-before-operate, clock sync, redundant channels.
2. **Real IP takeover.** Lab interface or two NICs; ARP/NDP, gratuitous ARP,
   duplicate-address detection, switch CAM, privileged port 2404.
3. **IEC 62351 posture.** Decide transparent vs terminating TLS; decide
   whether the proxy is an IEC 62351-5 authentication endpoint.
4. **Conformance matrix.** Use IEC TS 60870-5-604 as the reference for test
   cases; add the cases the lab can run.
5. **HA.** Active/standby pair without state replication; define what happens
   to an in-flight command during failover.
6. **Multi-master.** If an RTU accepts one connection, either enforce
   `max_clients: 1` or design safe session multiplexing.
7. **Rate limiting and pacing.** Protect a fragile RTU from polling storms
   and bound per-master request rates, as the other Shield proxies do.
8. **File transfer.** Inspect or explicitly block file/log transfer types;
   v0.1 blocks them in read-only and otherwise treats them as writes.
9. **DNP3.** Only after IEC-104 has a design partner; separate protocol
   engine, not a port of this one.
10. **Packaging.** systemd hardening, SBOM, signed releases, CRA technical
    documentation.
