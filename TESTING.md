# Testing IEC 104 Shield

The suite is organized around protocol invariants and failure modes, not only
successful forwarding.

| Layer | Evidence |
| --- | --- |
| Framing | I/S/U parse and build, sequence wrap, length bounds, malformed frames, fuzz target |
| ASDU | Header, COT P/N and test bits, common address, IOA, sequence objects, optional zero-IOA system commands |
| Policy | Read-only, default deny, allow/deny scoping, select/execute, deny-overrides, no-IOA rules |
| Unknown types | Master-to-RTU private types denied by default; explicit opt-in; partial write types always denied |
| Sequence | Independent per-leg spaces, S-frame acks, k-window, t1 expiry, sequence-gap close |
| Data plane | Denied command gets a negative confirmation and never reaches the outstation; allowed command does; interrogation data crosses |
| Fail-closed | Upstream dial failure closes the front connection; stopping the proxy removes the old address |
| Control frames | STARTDT/STOPDT/TESTFR relayed end to end |
| Independent peer | `wendy512/iec104` master and outstation, neither end using this proxy's parser |
| Real binary | `validate`, `selftest`, `gateway`, YAML and flags modes |

## Commands

```sh
make test          # gofmt + race suite
make verify        # build + race suite + vet
make interop       # independent peer; exit 77 if it cannot be built
make acceptance    # verify + interop with INTEROP_REQUIRED=1
make cover         # per-package coverage floors
```

Parser fuzzing is available directly:

```sh
go test ./internal/iec104 -run '^$' -fuzz FuzzParseFrame -fuzztime 10s
go test ./internal/iec104 -run '^$' -fuzz FuzzParseASDU -fuzztime 10s
```

## Independent interop

`scripts/interop-iec104.sh` starts:

1. a `wendy512/iec104` outstation on a free loopback port;
2. the proxy on another free loopback port, with the outstation moved behind
   it;
3. a `wendy512/iec104` master pointed at the proxy's address.

It asserts:

- the interrogation returns a single point;
- an allowed command (IOA 1000) gets a positive confirmation and reaches the
  outstation;
- a denied command (IOA 2000) gets a negative confirmation and does **not**
  reach the outstation;
- after the proxy stops, the old address refuses connections.

The peer lives in `test/peers/iec104peer` as a separate Go module. It is
test-only; the proxy itself has no third-party protocol dependency.

## Coverage gate

`make cover` enforces the floors in [`coverage.floors`](coverage.floors).
The overall figure excludes the `covercheck` tooling package. Raise a floor
when a package improves; add a test rather than lowering it.

Current measured production coverage is about 75% overall, with the proxy at
about 86%, policy at about 96%, parser at about 74%, config at about 79%,
observability at about 93%, and the command at about 42%.

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
