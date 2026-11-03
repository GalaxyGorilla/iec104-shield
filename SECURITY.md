# Security model

## What the proxy protects

A legacy IEC-104 outstation that cannot authenticate or authorize its master.
The proxy sits between the master and the outstation, owns the master-visible
address, and decides whether a command may cross.

## Trust boundaries

- **Master leg:** untrusted. The client IP allow-list is the first gate; the
  command policy is the second.
- **Outstation leg:** trusted for monitoring data, but still parsed strictly
  enough to preserve framing and sequence state. A malformed frame closes the
  session.
- **Management:** the YAML file, audit file and metrics listener are local
  operator concerns. The metrics listener should be bound to localhost or a
  management network.

## Fail-closed

- With no command policy, write-class ASDUs are denied; monitoring,
  interrogation, read and test commands still pass.
- An upstream dial failure closes the master connection.
- A sequence gap, malformed APDU, unsupported U function or t1 expiry closes
  the session.
- There is no bypass and no automatic fail-open in v0.1.
- When the process stops, the old address is gone.

## What a denied command does

The proxy builds a negative activation confirmation from the original ASDU:
same type, common address and information objects, COT 7 with the P/N bit set.
It sends that to the master and never forwards the command to the outstation.
The audit record contains type, cause, common address, IOA, select/execute and
the reason. Allowed control commands are recorded too, so the audit shows what
was permitted and what was refused.

## Known limitations

- No IEC 62351-3 TLS and no IEC 62351-5 authentication.
- Unknown/private master-to-outstation types are refused by default; a site
  can opt out with `allow_unknown_types` for non-write types. A write type
  whose objects cannot be parsed is always refused.
- File transfer is treated as a write and is not content-inspected.
- One upstream connection per master; a single-connection RTU needs
  `max_clients: 1`.
- No HA; a single box is a single point of failure.
- Not yet validated against a physical RTU or a conformance suite.

## Reporting

Treat this as pre-production software. Do not deploy it on a live utility
control path without a lab validation, a rollback plan and an explicit
availability decision (fail-closed vs bypass).
