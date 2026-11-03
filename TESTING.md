# Testing IEC 104 Shield

The suite is organized around protocol invariants and failure modes, not only
successful forwarding.

| Layer | Evidence |
| --- | --- |
| Framing | I/S/U parse and build, sequence wrap, length bounds, malformed frames, fuzz target |
| ASDU | Header, COT P/N and test bits, common address, IOA, sequence objects, optional zero-IOA system commands |
| Policy | Read-only, default deny, allow/deny scoping, select/execute, deny-overrides, no-IOA rules |
| Unknown types | Master-to-RTU private types denied by default; explicit opt-in; partial write types always denied |
| File transfer | 120–127 are write-class; fixed-size can be explicitly allowed, variable-size 125/127 always fail closed |
| Sequence | Independent per-leg spaces, S-frame acks, k-window, t1 expiry, sequence-gap close |
| Data plane | Denied command gets a negative confirmation and never reaches the outstation; allowed command does; interrogation data crosses |
| Fail-closed | Upstream dial failure closes the front connection; stopping the proxy removes the old address |
| Restart | Outstation death closes the master session; a restarted outstation gets a fresh upstream connection |
| Control frames | STARTDT/STOPDT/TESTFR relayed end to end |
| Reload | SIGHUP applies policy/allow-list/limits to running sessions; a bad file keeps the running config |
| Shielding | Token-bucket rate limit and shared pacing for master-to-outstation I-frames; RTU data is unaffected |
| Independent peer | Two separate stacks (`wendy512/iec104` and `otfabric/go-iec104`), neither end using this proxy's parser |
| Real binary | `validate`, `selftest`, `gateway`, YAML and flags modes |

## Commands

```sh
make test          # gofmt + race suite
make verify        # build + race suite + vet
make interop       # independent peer; exit 77 if it cannot be built
make smoke-reload  # real binary: deny -> SIGHUP -> allow, then a bad file
make acceptance    # verify + interop + smoke-reload, no skips
make cover         # per-package coverage floors
```

Parser fuzzing is available directly:

```sh
go test ./internal/iec104 -run '^$' -fuzz FuzzParseFrame -fuzztime 10s
go test ./internal/iec104 -run '^$' -fuzz FuzzParseASDU -fuzztime 10s
```

## Independent interop

`scripts/interop-iec104.sh` runs the same scenario twice: once with
`wendy512/iec104` and once with `otfabric/go-iec104`. For each stack it starts:

1. an outstation on a free loopback port;
2. the proxy on another free loopback port, with the outstation moved behind
   it;
3. a master from the same stack pointed at the proxy's address.

It asserts:

- the interrogation returns a single point;
- device-initiated spontaneous data (cause 3) crosses the proxy, both on the
  plain master connection and while select-before-operate is in progress;
- an allowed command (IOA 1000) gets a positive confirmation and reaches the
  outstation;
- a select-before-operate select and execute each get a positive confirmation
  and reach the outstation with the S/E bit intact;
- a denied command (IOA 2000) gets a negative confirmation and does **not**
  reach the outstation;
- after the proxy stops, the old address refuses connections.

The peers live in `test/peers/iec104peer` and `test/peers/iec104peer2` as
separate Go modules. They are test-only; the proxy itself has no third-party
protocol dependency.

## SIGHUP reload

`scripts/smoke-reload.sh` starts the real binary from a YAML file, proves a
command is denied, rewrites the file to allow it, sends SIGHUP, and proves the
same command now passes. It then writes a broken file and proves SIGHUP keeps
the running configuration.

Unit tests pin the same contract without signals: policy and
`allow_unknown_types` apply to an already established session, allow-list and
`max_clients` apply to new connections, a failed compile keeps the previous
runtime, and listener/device-address changes are reported as restart-only.

## Shielding limits

`rate_per_sec` is a token bucket shared by every master on a device. A request
over the limit gets a negative activation confirmation and is never forwarded,
so the master's sequence space stays aligned. `min_interval_ms` holds a shared
gate between forwarded master I-frames. Tests use a fake clock for the bucket
and timestamp the fake outstation for the pacing gap; a reload test proves a
new limit is part of the swapped snapshot. RTU-to-master monitoring data is
neither rate-limited nor paced.

## Coverage gate

`make cover` enforces the floors in [`coverage.floors`](coverage.floors).
The overall figure excludes the `covercheck` tooling package. Raise a floor
when a package improves; add a test rather than lowering it.

Current measured production coverage is about 83% overall, with the proxy at
about 88%, policy at about 96%, parser at about 74%, config at about 79%,
observability at about 93%, and the command at about 74%.

## Focused mutation checks

Not full mutation testing. Each row was applied to a clean tree, the named test
was run, the test failed, and the file was restored.

| Invariant broken | Mutation | Test that caught it |
|---|---|---|
| Negative confirmation P/N bit | `0x40` → `0x00` in `NegativeConfirmation` | `TestNegativeConfirmation` |
| Sequence-gap rejection | `seq != recvSeq` → `false && seq != recvSeq` | `TestSequenceGapCloses` |
| Policy deny-overrides | `!r.Allow` → `false && !r.Allow` | `TestDenyOverrides` |
| Unknown-type fail-closed | `a.Partial && !allowUnknown` → `false && ...` | `TestUnknownMasterTypeDeniedByDefault` |
| Ack-beyond-send rejection | `delta > outstanding` → `false && ...` | `TestLinkAckValidation` |
| Concurrent send ordering | removed `sendMu` | `TestLinkSendSerialization` |

## Remaining hardware boundary

The single-machine suite cannot reproduce:

- a physical RTU's timing, retransmission and vendor profile;
- IEC 62351 TLS or authentication;
- redundant channels and multi-master behavior;
- real ARP/NDP takeover, gratuitous ARP, duplicate-address detection, switch
  CAM, or privileged port 2404;
- sustained load and power/network interruption;
- a utility conformance suite.

These are commissioning and certification work, not silently converted into a
passing test.
