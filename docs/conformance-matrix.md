# IEC-104 conformance matrix

**Status:** working matrix, not a conformance certificate. IEC TS 60870-5-604
is the reference for the test cases a conformance lab would run. This table
maps the behaviours we exercise to the evidence in this repository and marks
what still needs a lab, a physical RTU or a second implementation.

Clause numbers are intentionally omitted: the mapping is by behaviour, so it
can be checked without pretending to reproduce the standard's numbering.

## APCI and framing

| Behaviour | Evidence | Status |
|---|---|---|
| Start octet, length field, I/S/U discrimination | `internal/iec104/apdu_test.go`, `FuzzParseFrame` | covered |
| Malformed/truncated/oversized frames rejected | `apdu_test.go`, fuzz corpus | covered |
| I-frame N(S)/N(R) 15-bit little-endian encoding | `apdu_test.go`, interop | covered |
| S-frame carries only N(R) | `apdu_test.go`, `TestLinkAckValidation` | covered |
| U-frame function encoding (`STARTDT_ACT` 0x07, `TESTFR_CON` 0x83) | `apdu_test.go`, interop | covered |

## Sequence and link state

| Behaviour | Evidence | Status |
|---|---|---|
| Independent N(S)/N(R) per leg | `internal/proxy` sequence tests, interop | covered |
| Duplicate acknowledgement accepted | `TestLinkAckValidation` | covered |
| Sequence gap closes the session | `TestSequenceGapCloses` | covered |
| Acknowledgement beyond send sequence rejected | `TestLinkAckValidation` | covered |
| N(S) wrap at 32767 | `TestLinkSequenceWrap` | covered |
| k-window backpressure | `TestLinkWindowBlocksUntilAck` | covered |
| t1 expiry closes the session | `TestLinkT1Expiry` | covered |
| Concurrent send ordering | `TestLinkSendSerialization` | covered |
| t2 acknowledgement timer | none | lab/implementation gap |
| w receive window | none | lab/implementation gap |

## U functions

| Behaviour | Evidence | Status |
|---|---|---|
| STARTDT relayed end to end | `TestStartStopDTAreForwarded`, interop | covered |
| STOPDT relayed end to end | `TestStartStopDTAreForwarded` | covered |
| TESTFR relayed end to end | `TestTestFRIsForwarded` | covered |
| Unsupported U function closes the session | `internal/proxy` pump error path | covered by code path, no dedicated test |

## ASDU

| Behaviour | Evidence | Status |
|---|---|---|
| Header, VSQ, COT, originator, common address | `internal/iec104/asdu_test.go`, fuzz | covered |
| P/N bit is bit 6, test bit is bit 7 | `asdu_test.go`, `TestNegativeConfirmation` | covered |
| IOA 3-byte little-endian | `asdu_test.go` | covered |
| Fixed-size information objects | `asdu_test.go` | covered |
| Sequence objects (SQ) | `asdu_test.go` | covered |
| Zero-IOA system-command encoding | `asdu_test.go` | covered |
| Unknown/private type marked partial | `asdu_test.go`, `TestUnknownMasterTypeDeniedByDefault` | covered |

## Monitoring and system functions

| Behaviour | Evidence | Status |
|---|---|---|
| Station interrogation | `TestReadOnlyDeniesCommand`, interop | covered |
| Counter interrogation | policy matrix (`readTypes`) | policy-covered, no end-to-end data test |
| Read | policy matrix | policy-covered |
| Test command | policy matrix | policy-covered |
| Spontaneous device data | `TestSpontaneousDeviceData`, interop | covered |
| Multi-object monitoring data | `TestManyFrames` | covered |
| Clock sync, reset, delay acquisition | policy matrix | policy-covered, no end-to-end data test |

## Commands and policy

| Behaviour | Evidence | Status |
|---|---|---|
| Single/double/step/setpoint command classification | `internal/iec104/asdu_test.go`, policy matrix | covered |
| Select-before-operate select/execute | `TestSBOSelectAllowedExecuteDenied`, interop | covered |
| Denied command gets negative confirmation and is not forwarded | `TestReadOnlyDeniesCommand`, interop | covered |
| Default deny with no policy | `TestDefaultDeniesWrites` | covered |
| Read-only allows interrogation/read/test | `TestReadOnlyDeniesCommand` | covered |
| Deny-overrides and allow-must-cover | `TestDenyOverrides`, `TestMultiObjectAllowMustCover` | covered |
| Unknown master type refused by default | `TestUnknownMasterTypeDeniedByDefault` | covered |
| Partial write type always refused | `TestFileTransferIsPolicyGated` | covered |
| File transfer fixed-size policy-gated, 125/127 fail closed | `TestFileTransferIsPolicyGated` | covered |
| Allowed and denied commands audited | `TestAuditAllowedAndDeniedCommands` | covered |

## Shielding and operations

| Behaviour | Evidence | Status |
|---|---|---|
| IP allow-list | `TestAllowList` | covered |
| Connection cap | `TestMaxClients` | covered |
| Rate limiting with negative confirmation | `TestRateLimitDeniesBurstAndRecovers` | covered |
| Shared pacing between forwarded frames | `TestPacingSpacesForwardedFrames` | covered |
| SIGHUP policy/allow-list/limit reload | `TestReload*`, `scripts/smoke-reload.sh` | covered |
| Bad reload keeps the running config | `TestReloadBadRuntimeKeepsPrevious`, `smoke-reload.sh` | covered |
| Upstream failure closes the master | `TestFailClosedWhenDeviceDown` | covered |
| Outstation restart and fresh upstream | `TestOutstationRestart` | covered |
| Address takeover on loopback | `scripts/interop-iec104.sh` | covered (loopback only) |
| Real ARP/NDP takeover and port 2404 | none | lab |

## TLS (IEC 62351-3 option B)

| Behaviour | Evidence | Status |
|---|---|---|
| Master-facing TLS termination | `TestTLSGateway`, `scripts/interop-iec104.sh` | covered |
| mTLS when `client_ca` is configured | `TestTLSGatewayRequiresClientCertificate` | covered |
| Plain client refused before the upstream dial | `TestTLSGateway`, interop | covered |
| Certificate/key validation | `TestTLSValidation`, flags test | covered |
| Upstream TLS leg (option C) | `TestUpstreamTLS`, `TestUpstreamTLSBadCA` | covered |
| Upstream mTLS | `TestUpstreamTLSClientCertificate` | covered |
| Both legs TLS at once | `otfabric-tls-both` interop | covered |
| IEC 62351-5 ASDU authentication | none | out of scope for v0.1 |

## Interop

| Behaviour | Evidence | Status |
|---|---|---|
| Interrogation, allowed/denied command, SBO, spontaneous data | `scripts/interop-iec104.sh` with `wendy512/iec104` | covered |
| Same scenario with a second independent stack | `scripts/interop-iec104.sh` with `otfabric/go-iec104` | covered |
| Third outstation implementation | `scripts/interop-iec104-lib60870.sh` with MZ Automation lib60870-C | covered (optional C toolchain) |
| Physical RTU timing, retransmission, vendor profiles | none | lab |
| Master-leg IEC 62351-3 TLS and plain-client rejection | `scripts/interop-iec104.sh` | covered |
| Both-leg TLS | `scripts/interop-iec104.sh` (`otfabric-tls-both`) | covered |
| IEC 62351-5 authentication | none | not implemented |
| Redundancy groups | none | out of scope for v0.1 |

## How to run

```sh
make test          # parser, policy, proxy, config, observability
make interop       # both independent peer stacks
make acceptance    # verify + interop + SIGHUP smoke
make cover         # statement coverage floors
```

## Gaps to close next

1. Dedicated t2/t3 and w-window behaviour, or an explicit decision that the
   proxy's terminating design does not need them.
2. End-to-end counter-interrogation, read, clock-sync and reset tests against
   a peer that answers them.
3. A physical RTU lab run with the vendor's timing profile.
4. Real ARP/NDP address takeover and privileged port 2404.
5. An external IEC-104 conformance suite or lab report.
