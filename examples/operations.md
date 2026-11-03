# Operations runbook

This is the day-2 guide for a single IEC-104 gateway. It assumes the
deployment shape in [address-takeover.md](address-takeover.md).

## 1. Install

```sh
sudo install -m 0755 bin/iec104-shield /usr/local/bin/iec104-shield
sudo install -d -o iec104-shield -g iec104-shield /etc/iec104-shield
sudo install -d -o iec104-shield -g iec104-shield /var/log/iec104-shield
sudo install -m 0644 deploy/iec104-shield.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now iec104-shield
```

The unit runs as an unprivileged user with only `CAP_NET_BIND_SERVICE`, a
strict filesystem view and no new privileges. Port 2404 is the only reason
for the capability; an unprivileged port needs none.

## 2. Validate before every start or reload

```sh
iec104-shield validate --config /etc/iec104-shield/gateway.yaml
iec104-shield selftest --config /etc/iec104-shield/gateway.yaml
```

`validate` checks syntax, addresses, policy compilation and file readability.
`selftest` dials the RTU, starts data transfer and exchanges TESTFR; it does
not send commands.

## 3. Reload without dropping sessions

```sh
sudo systemctl reload iec104-shield
# or: sudo kill -HUP "$(pidof iec104-shield)"
```

Reloadable in place:

- command policy and `read_only`;
- IP allow-list;
- `max_clients`;
- dial/idle timeout, `t1`, `k`;
- `rate_per_sec` and `min_interval_ms`.

Policy changes apply to an already established session on its next frame, so
a revoked command cannot execute after the reload. `listen_addr`,
`device_addr`, and adding or removing a device require a restart and are
logged as warnings. A file that fails to load leaves the running
configuration untouched.

## 4. Tune shielding for a fragile RTU

```yaml
    rate_per_sec: 20       # master-to-RTU I-frames per second, all masters
    min_interval_ms: 50    # minimum gap between forwarded master frames
```

- Start with the RTU vendor's recommended poll interval.
- `rate_per_sec` is a burst-tolerant token bucket; an over-rate request is
  answered with a negative activation confirmation and never reaches the RTU.
- `min_interval_ms` spaces forwarded frames; it does not delay RTU-to-master
  spontaneous data.
- Both are shared by all masters on the device, because they protect the RTU,
  not an individual master.

Watch `iec104_shield_commands_denied_total{reason="rate_limit"}` after a
change. A persistent non-zero rate means the master is polling faster than
the configured budget.

## 5. Audit and metrics

```yaml
metrics:
  addr: "127.0.0.1:9204"
audit:
  file: "/var/log/iec104-shield/audit.jsonl"
  max_mb: 64
```

- Keep the metrics listener on localhost or a management network.
- The audit file rotates at `max_mb`; ship or retain the rotated files.
- Allowed and denied control commands are both recorded. Monitoring data is
  counted by metrics, not audited, to keep the trail readable.
- Useful checks:

```sh
curl -fsS http://127.0.0.1:9204/healthz
curl -fsS http://127.0.0.1:9204/readyz
curl -fsS http://127.0.0.1:9204/metrics | grep iec104_shield
```

## 6. Failure behaviour

- If the listener cannot bind, the process exits; systemd restarts it.
- If the upstream RTU cannot be dialled, the master connection closes.
- If a session sees a sequence gap, malformed frame, t1 expiry or unsupported
  U function, the session closes.
- If the outstation restarts, the old master session closes; the next master
  connection gets a fresh upstream connection.
- There is no bypass and no automatic fail-open.

Plan the operational consequence: fail-closed protects the RTU but also
removes remote control until the path is restored. Record that decision in
the site's availability plan.

## 7. Upgrade

1. Validate the new binary and config in a lab or on a standby appliance.
2. Copy the binary to a versioned path.
3. Switch the systemd `ExecStart` symlink or unit.
4. `systemctl restart iec104-shield`.
5. Run `selftest` and one controlled command from the real master.
6. Keep the previous binary and config for rollback.

The v0.1 release has no signed-update channel yet; verify the checksum and
SBOM from the release before installing.

## 8. Troubleshooting

| Symptom | Check |
|---|---|
| `validate` fails | YAML unknown key, address syntax, inverted IOA range, unreadable audit path |
| Master connects then drops | `journalctl -u iec104-shield`; upstream dial error or fail-closed session error |
| Command denied unexpectedly | audit `command_denied` reason; policy rule scope, select/execute, common address, IOA coverage |
| Command denied with `rate_limit` | `rate_per_sec` / `min_interval_ms` versus the master's poll rate |
| Reload did not apply | log says `restart required` for listener/device changes, or `keeping the running configuration` for a bad file |
| Old address still answers after stop | another process or a stale listener owns the port; the proxy does not fail open |
