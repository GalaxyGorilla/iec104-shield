# AGENTS.md — IEC 104 Shield

## Mission

A small, strict IEC 60870-5-104 security proxy for retrofit utility and
industrial installations. It owns the RTU's old address, moves the RTU behind
it, forwards monitoring data, and enforces a command policy. It is not a full
IEC-104 master/outstation stack.

## Invariants

1. **Terminating proxy, not byte relay.** Each leg has its own N(S)/N(R)
   space. S-frames are consumed locally, not forwarded.
2. **A denied command is never forwarded.** It is answered with a negative
   activation confirmation (COT 7 + P/N) built from the original ASDU.
3. **Fail closed.** If the listener, upstream dial or session fails, the
   master's connection closes. There is no bypass in v0.1.
4. **Unknown master-to-RTU types are refused** unless `allow_unknown_types` is
   explicitly set. A write type whose objects cannot be parsed is always
   refused.
5. **One upstream connection per master.** IEC-104 is stateful; for an RTU
   that accepts one connection set `max_clients: 1`. Do not multiplex
   sessions onto one upstream connection without redesigning the sequence
   and command state.
6. **Read-only still allows interrogation, counter interrogation, read and
   test.** It blocks process/system/parameter/file writes.
7. **Policy evaluation is deny-overrides.** An allow rule with an IOA range
   must cover every object in the ASDU. With no command policy at all, writes
   are denied; `command_policy.default: allow` is the explicit opt-in.

## Protocol details that are easy to get wrong

- APDU: `0x68`, length, 4 control octets, ASDU. Length counts the control
  field plus ASDU.
- I-frame: first control bit 0; N(S) and N(R) are 15-bit, little-endian with
  the low bit shifted out.
- S-frame: first control octet `0x01`; only N(R).
- U-frame: first control octet low bits `0b11`; function is the upper six
  bits. `STARTDT_ACT` is `0x07` on the wire, `TESTFR_CON` is `0x83`.
- COT: **bit 6 is P/N (`0x40`)**, **bit 7 is test (`0x80`)**. Do not swap
  them. This was a real interop bug.
- ASDU: type, VSQ (SQ + count), COT, originator, common address (2 bytes,
  little-endian), information objects.
- IOA is 3 bytes, little-endian.
- System commands (interrogation, clock sync, reset, test) normally have no
  IOA. Some stacks encode a zero IOA before the information element; the
  parser accepts both by total length.
- Process commands carry an IOA and a qualifier octet. The S/E bit is bit 7
  of the qualifier.
- `C_BO_NA_1` / `C_BO_TA_1` carry a bitstring, not a qualifier; they are
  reported as execute.
- A denied or rate-limited I-frame is answered with a negative activation
  confirmation and never dropped; dropping it would desynchronise N(S).
  Rate limiting and pacing apply only to master-to-RTU frames.
- TLS terminates on the master leg. Complete the handshake **before** dialing
  the outstation, so a plain or unauthenticated client cannot cause an
  upstream connection.

## Layout

```
cmd/iec104-shield/     CLI
internal/iec104/       framing + ASDU parser
internal/policy/       allow-list + command policy
internal/config/       YAML/flags + validation
internal/proxy/        gateway, session, sequence handling
internal/observ/       logger, metrics, audit
test/peers/iec104peer/  independent wendy512/iec104 peer, separate Go module
test/peers/iec104peer2/ independent otfabric/go-iec104 peer, separate Go module
scripts/                interop, SBOM
```

## Commands

```sh
make build
make test
make verify
make interop
make interop-lib60870
make smoke-reload
make acceptance
make cover
make release-all
```

`make acceptance` requires the independent peer to build. The peer module is
under `test/peers/iec104peer` and is deliberately not part of the main module.

## Style

- Go 1.26 minimum, toolchain 1.27.3.
- Standard library first. Protocol parsing is in-house for fuzzability and
  control.
- No third-party protocol stack in the proxy. The peer is test-only.
- Keep the parser strict on framing and tolerant only where a documented
  vendor encoding requires it.
- Every security decision gets an audit record and a metric.
- Comments explain *why*, especially around sequence handling and policy.

## Current state

v0.1 is a working software prototype with interop against two independent
Go stacks (`wendy512/iec104` and `otfabric/go-iec104`) plus MZ Automation
lib60870-C as an optional third outstation, SBO,
spontaneous-data and outstation-restart coverage, IEC 62351-3 TLS on the
master and/or upstream leg with optional mTLS, a loopback address-takeover
proof, SIGHUP reload
of the command policy, allow-list and limits, and token-bucket rate limiting
plus shared pacing for master-to-outstation I-frames. A listener or
outstation address change is reported as restart-only. Packaging includes a
hardened systemd unit with SIGHUP reload, SBOM/grype release gates,
signing/verification hooks, and a CRA technical-file outline. `docs/conformance-matrix.md` maps behaviour to tests
and names the remaining lab gaps. IEC 62351-3 TLS is implemented on both legs;
the next protocol slice is IEC 62351-5 (`docs/iec62351-posture.md`); the HA
shape is active/standby without state replication (`docs/ha-design.md`). It is not yet
validated against a physical RTU, IEC 62351 TLS/authentication, real ARP/NDP
takeover, or an IEC-104 conformance suite.
