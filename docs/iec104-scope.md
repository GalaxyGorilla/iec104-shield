# IEC 104 Shield — scope and design

**Status:** v0.1 implementation, 2026-11-03. Software prototype; not yet
validated against a physical RTU or a utility conformance suite.

## Why IEC-104 for a Germany/Europe focus

IEC 60870-5-104 is the prevailing telecontrol protocol between European grid
operators and their substations. It carries measurements and status, but also
**control commands**: single/double commands, setpoints, clock
synchronisation, reset and parameter changes. The base protocol has no
authentication or encryption; IEC 62351-3/5 add them, but deployment is
uneven. A valid I-frame to TCP 2404 can, in principle, operate a breaker if
nothing else stops it.

That makes IEC-104 the natural fourth Shield proxy after Modbus TCP,
BACnet/IP and SNMP:

- same buyer as the appliance thesis: utilities, industrial brownfield,
  critical facilities;
- same retrofit shape: long-lived RTUs and gateways that cannot be changed;
- same address-takeover deployment: the appliance owns the RTU's old address;
- a clear, high-consequence policy question: **which commands may cross, from
  which master, to which common address and information object?**

DNP3 is the North-American counterpart. It remains the second utility
protocol, not the first for a Europe-focused product.

## What the product should be

A **protocol-aware security gateway**, not a full IEC-104 master/outstation
stack and not a byte-level firewall.

The gateway:

1. owns the address the master already knows;
2. opens one upstream connection per master session to the RTU at its new
   address;
3. terminates the IEC-104 sequence spaces on both legs;
4. forwards monitoring data and allowed commands;
5. answers a denied command with a negative activation confirmation and never
   forwards it;
6. fails closed: if the gateway or the upstream path dies, the master's
   connection dies; the RTU is not silently exposed at the old address.

The important design consequence is **terminating proxy, not transparent
relay**. Dropping a disallowed I-frame in a byte relay would desynchronise the
master's and RTU's N(S)/N(R) counters. Forwarding it and hoping the RTU
rejects it would execute the command. The gateway therefore acknowledges each
leg independently, allocates fresh sequence numbers, and synthesises the
negative confirmation itself.

## v0.1 scope (implemented)

- IEC 60870-5-104 over TCP, default port 2404.
- APDU framing: start octet, length, I/S/U control fields, 15-bit sequence
  numbers.
- ASDU header: type, VSQ, COT (cause, P/N, test), originator, common address.
- Fixed-size information objects and IOA extraction for the standard types.
- Tolerant parsing of the two common interrogation encodings (with and without
  a zero IOA before QOI).
- Independent send/receive sequence spaces per leg, immediate S-frame
  acknowledgements, k-window backpressure, t1 timeout.
- STARTDT/STOPDT/TESTFR forwarding end to end.
- Client IP allow-list and connection cap.
- `read_only` mode: block all write-class ASDUs, keep interrogation, counter
  interrogation, read and test commands.
- Scoped command policy: type, common address, IOA range, select/execute,
  allow/deny, deny-overrides, default deny.
- Unknown/private master-to-outstation ASDU types refused by default; an
  explicit `allow_unknown_types` opt-out exists for non-write types. A write
  type whose objects cannot be parsed is always refused.
- Denied commands get a negative activation confirmation (COT 7 + P/N) and
  never reach the RTU.
- JSON-lines audit of accepts, rejects, allowed commands, denied commands and
  protocol errors.
- Prometheus metrics and `/healthz` `/readyz`.
- `gateway`, `validate`, `selftest`, `version` commands.
- Independent interop test with `wendy512/iec104` as both master and
  outstation.
- Address-takeover loopback proof: the original address disappears when the
  proxy stops, while the RTU still answers at its moved address.

## Explicit non-goals for v0.1

- IEC 60870-5-101 serial and serial-to-IP gateways.
- IEC 62351-3 TLS and IEC 62351-5 application-layer authentication.
- DNP3 Secure Authentication / IEEE 1815.
- Redundancy groups and multi-master arbitration.
- Full IEC-104 conformance (t2/t3/w tuning, file transfer, all private types).
- Transparent/bump-in-the-wire mode. Sequence rewriting makes a naive
  transparent relay unsafe for command policy; if transparent mode is added,
  it must be a terminating proxy behind a redirect, like the Modbus B3 design.
- HA / standby pair. A single box is a single point of failure; the v1
  appliance plan uses active/standby without state replication.
- Deep inspection of file transfer contents.
- IEC 61850. That is a different, much larger problem inside the substation;
  IEC-104 is the control-centre link.

## Policy model

A write-class ASDU is one of:

- process commands 45–51 and 58–64;
- clock synchronisation 103;
- reset process 105;
- delay acquisition 106;
- parameter commands 110–113;
- file transfer / log query 120–127.

Interrogation (100), counter interrogation (101), read (102) and test commands
(104, 107) are read-only operations and remain available in `read_only` mode.

A rule can scope by:

- `types` — one type or a list;
- `common_address` — `*` or 0..65535;
- `ioa` — `*`, one address, or `from-to`;
- `select` — `any`, `select`, or `execute`.

Evaluation is deny-overrides. An allow rule with an IOA range must cover
**every** information object in the ASDU; a deny rule matches when **any**
object intersects its range. A range-scoped rule cannot match a command with no
IOA (interrogation, clock sync, file transfer); use an unscoped rule for those.
The default for unmatched writes is `deny`. With no `command_policy` at all,
writes are denied; `command_policy.default: allow` is the explicit opt-in to
transparent command forwarding.

Select-before-operate is a two-step command: a select (S/E bit set) followed by
an execute. A rule with `select: execute` allows only the second step; the
select is denied. For SBO points, use two rules or `select: any` and accept
both steps.

## Deployment shape

```
SCADA master ──► original RTU address ──► iec104-shield ──► RTU at new address
```

- The master keeps its configuration.
- The RTU is re-patched to a protected port and gets a new address.
- The appliance owns the old address and forwards only IEC-104.
- If the appliance stops, the old address is gone. The RTU is not exposed.
- Each master gets its own upstream connection, because IEC-104 is stateful.
  If the RTU accepts only one connection, set `max_clients: 1`.

This is a port-level loopback proof today. Real IP takeover (ARP/NDP,
gratuitous ARP, duplicate-address detection, switch CAM) and privileged port
2404 still need a lab test.

## Known risks

1. **Availability.** Fail-closed is the right security default, but utilities
   may demand bypass or stronger HA for telecontrol. That is a commercial and
   architectural decision, not a protocol detail.
2. **Security layers.** If a site uses IEC 62351-3 TLS, the gateway cannot
   inspect commands without terminating TLS. If it uses IEC 62351-5
   authentication, the gateway must decide whether it is a transparent
   bump-in-the-wire, a terminating proxy, or an authentication endpoint. v0.1
   is plain TCP and does not answer this.
3. **Vendor profiles.** IEC-104 interoperability lists differ. Private types,
   redundant channels, file transfer and unusual interrogation encodings need
   a real-device lab.
4. **Conformance.** There is no IEC-104 conformance suite in this repository
   yet. The independent peer proves interoperability, not conformance.
5. **One upstream per master.** A fragile RTU with one TCP connection needs
   `max_clients: 1`; multi-master multiplexing is future work.
6. **Unknown types.** The default is fail-closed for master-to-RTU unknown
   types. A site with private command types must explicitly allow them, which
   weakens the guarantee.

## Next milestones

1. Lab test with a real RTU or IEC-104 simulator: select-before-operate,
   spontaneous data, interrogation, clock sync, redundant connections.
2. Real IP takeover on a lab interface or two NICs.
3. Decide the IEC 62351-3/5 posture before promising deployment in a utility
   that has enabled it.
4. Add a conformance-oriented test matrix (IEC TS 60870-5-604 is the reference
   for test cases; it is not a free implementation).
5. Add SIGHUP policy reload with the same whole-snapshot semantics as the other
   Shield projects.
6. Consider DNP3 only after IEC-104 has a design partner.
