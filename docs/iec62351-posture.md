# IEC 62351 posture

**Status:** option B (terminate TLS on the master leg) is implemented in
v0.1. Option C (upstream TLS) and IEC 62351-5 are not. This note records the
decision and the remaining work.

## The constraint

IEC-104 has no authentication or encryption of its own. IEC 62351 adds:

- **IEC 62351-3**: TLS for the TCP connection (server and mutual
  authentication, cipher profiles).
- **IEC 62351-5**: application-layer authentication of ASDUs
  (challenge/response, security information in the ASDU).

A byte-level TLS passthrough cannot enforce a command policy: the proxy would
see ciphertext, so it could not classify or authorize a command. That rules
out "just tunnel TLS end to end" for this product.

## Options

| Option | Master leg | RTU leg | Policy | Notes |
|---|---|---|---|---|
| A. Passthrough | TLS | TLS | none | Rejected: the proxy cannot inspect commands |
| B. Terminate master TLS | TLS | plain | full | Recommended first step |
| C. TLS both legs | TLS | TLS | full | Needed when the RTU supports it |
| D. IEC 62351-5 endpoint | TLS or plain | plain | full | Only if a design partner requires ASDU authentication |

## Decision for the next slice

**Option B first, with C as a configuration variant.** Terminate TLS on the
master-facing listener, keep the RTU leg plaintext, and preserve the existing
terminating-proxy and command-policy model. The master is the untrusted side;
the RTU is the legacy device the appliance exists to protect. A plaintext RTU
leg is the retrofit reality.

Concretely:

- `tls:` block on a device: certificate, key, optional client CA.
- TLS 1.2 minimum, server authentication mandatory, mutual authentication when
  `client_ca` is set.
- The proxy remains a terminating IEC-104 proxy: TLS is a transport wrapper,
  not a second protocol engine.
- The same policy, audit and metrics paths apply; the audit record does not
  include payload secrets.
- `selftest` and `validate` must work with the TLS config.
- A plain client against a TLS listener is rejected; a TLS client without a
  required certificate is rejected.

Option C is the same code with a `device_tls:` block on the upstream leg,
mirroring the two-proxy pattern used by the other Shield projects. It is a
configuration variant, not a separate mode.

## Why not IEC 62351-5 yet

IEC 62351-5 authenticates ASDUs, not just the connection. It requires:

- a security association and key management;
- challenge/response state per session;
- interoperability with the master's and RTU's security information encoding;
- a design partner who actually deploys it.

That is a product decision, not a parser feature. v0.1 should not pretend to
be an IEC 62351-5 endpoint. The CRA technical file records this as a known
gap; the roadmap records it as a later phase.

## Acceptance criteria for option B

| # | Criterion | Status |
|---|---|---|
| 1 | A TLS master can interrogate and command through the proxy | met (`TestTLSGateway`, interop) |
| 2 | A plain master is refused when TLS is required | met (`TestTLSGateway`, interop) |
| 3 | mTLS is enforced when `client_ca` is configured | met (`TestTLSGatewayRequiresClientCertificate`) |
| 4 | A bad certificate or wrong CA fails closed and is audited | met (handshake failure audit `tls_handshake`) |
| 5 | Command policy and negative confirmation are unchanged | met (same proxy path) |
| 6 | `validate` rejects missing/unreadable certificate files | met (`TestTLSValidation`, flags test) |
| 7 | `selftest` uses the configured TLS path | not applicable to option B: selftest probes the plaintext RTU leg; it must use TLS for option C |
| 8 | Interop runs with at least one independent master over TLS | met (`otfabric-tls` scenario) |

## Open questions for the design partner

- Does the master support TLS 1.2/1.3 and which cipher profile?
- Is mutual authentication required, or only server authentication?
- Is the certificate lifecycle managed by the utility PKI or the appliance?
- Does the RTU support TLS, and would a two-leg TLS deployment be acceptable?
- Is IEC 62351-5 required by a procurement or certification requirement?
