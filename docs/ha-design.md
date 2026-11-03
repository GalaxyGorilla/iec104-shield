# High availability design

**Status:** design note for a later appliance version. v0.1 is a single box
and a single point of failure. This note defines the active/standby shape and
the in-flight command semantics so a future implementation does not invent
them under pressure.

## Shape

```
             shared service address (VRRP / keepalived)
                         │
          ┌──────────────┴──────────────┐
          │                             │
   active iec104-shield          standby iec104-shield
          │                             │
          └──────────────┬──────────────┘
                         │
                    RTU at new address
```

- Two appliances, one active and one standby.
- The active node owns the master-visible service address and the upstream
  connection(s).
- The standby node runs the same binary and config but does not accept master
  traffic and does not dial the RTU.
- **No IEC-104 session state is replicated.** N(S)/N(R), the command policy
  snapshot and the audit stream are local to the active node.

## Failover semantics

1. The active node fails (process, host, link, or upstream path).
2. VRRP/keepalived moves the service address to the standby.
3. The standby promotes itself, starts accepting masters, and dials the RTU
   per new master session.
4. Existing master TCP sessions are gone. The master must reconnect and
   re-interrogate.
5. The new active applies its own config snapshot; there is no half-replicated
   policy.

This is **not** a transparent failover. It is a fast restart of the security
function with a new IEC-104 session.

## In-flight commands

A command that was forwarded before the failure may already have executed at
the RTU. The standby cannot know. The rule is:

- **Never replay an in-flight command.** Replaying a breaker command is worse
  than losing it.
- The active node's audit record is the evidence that the command was
  forwarded. If the audit file is on shared storage or shipped off-box, the
  record survives; otherwise it is lost with the node.
- The master is responsible for re-reading state after reconnect and deciding
  whether to re-issue a command.
- The product documentation must state this explicitly; do not describe
  failover as "no command loss".

## Split brain

- VRRP priority plus a witness (a third host or a network reachability check)
  should prevent both nodes from owning the service address.
- The standby must not dial the RTU while passive. Two active upstream
  connections can confuse a single-connection RTU and violate the
  one-upstream-per-master invariant.
- If the witness is unavailable, prefer staying passive over active/active.

## Health and promotion

- Process health: the gateway is running and every listener is bound.
- Upstream health: do **not** poll the RTU from the standby with a synthetic
  master; that creates an extra upstream connection. Prefer passive checks
  (the active node's session state, interface status) and a deliberate
  operator-controlled failover.
- Promotion is a policy decision, not an automatic race: a short delay and a
  witness check are safer than instant takeover.
- The standby should log why it promoted and which config snapshot it loaded.

## Address takeover

- The service address must move at layer 2/3 (VRRP, gratuitous ARP/NDP).
- The switch CAM table and any upstream firewall state must follow.
- The old RTU address must not be answered by both nodes.
- The same loopback proof used in v0.1 is not sufficient; HA needs a real
  two-node lab.

## What is deliberately out of scope

- Stateful session replication.
- Active/active command handling.
- Distributed audit or policy consensus.
- Automatic RTU polling from the standby.
- Transparent TCP connection survival across failover.

## Acceptance criteria for a future HA slice

1. Two nodes, one service address, one active upstream path.
2. A master reconnect after failover succeeds and can interrogate.
3. No command is replayed automatically.
4. The standby never dials the RTU while passive.
5. Split-brain is prevented by a witness or an operator decision.
6. The audit trail shows which node handled which command.
7. The failover behaviour is documented in the operations runbook.
