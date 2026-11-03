# Single-RTU gateway walkthrough

This is the smallest useful deployment: one master, one RTU, one proxy.

## 1. Build

```sh
go build -o bin/iec104-shield ./cmd/iec104-shield
```

## 2. Write a config

```yaml
# /etc/iec104-shield/gateway.yaml
devices:
  - name: rtu-1
    listen_addr: "0.0.0.0:2404"     # the address the master already uses
    device_addr: "10.0.0.10:2404"   # the RTU's new address
    allow: ["10.0.0.0/24"]
    max_clients: 1
    command_policy:
      default: deny
      rules:
        - types: [45, 46]
          common_address: 1
          ioa: "1000-2000"
          select: execute
          action: allow
log:
  level: info
  format: console
metrics:
  addr: "127.0.0.1:9204"
audit:
  file: "/var/log/iec104-shield/audit.jsonl"
  max_mb: 64
```

`max_clients: 1` is deliberate if the RTU accepts only one TCP connection.

## 3. Validate

```sh
./bin/iec104-shield validate --config /etc/iec104-shield/gateway.yaml
```

## 4. Probe the RTU

```sh
./bin/iec104-shield selftest --config /etc/iec104-shield/gateway.yaml
```

The selftest sends STARTDT and TESTFR and waits for TESTFR confirmation. It
does not send commands; the outstation may send monitoring data, which the
probe ignores.

## 5. Move the RTU

- Re-patch the RTU to the protected port.
- Give it the new address in `device_addr`.
- Give the proxy the RTU's old address in `listen_addr`.
- Keep the master's configuration unchanged.

## 6. Start

```sh
sudo ./bin/iec104-shield gateway --config /etc/iec104-shield/gateway.yaml
```

## 7. Verify

- The master reconnects to the old address and receives interrogation data.
- An allowed command gets a positive confirmation.
- A command outside the policy gets a negative confirmation and appears in the
  audit log as `command_denied`.
- Stop the proxy: the old address refuses connections. The RTU is still
  reachable only at its new address.

## Rollback

Stop the proxy, move the RTU back to its old address, and restart the master's
connection. There is no bypass in v0.1; plan the maintenance window
accordingly.
