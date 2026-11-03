# Address takeover

Address takeover is the default deployment shape:

```
master ──► old RTU address ──► iec104-shield ──► RTU at new address
```

The master keeps its existing `IP:port`. The RTU moves behind the proxy. The
proxy owns the old endpoint and forwards only IEC-104.

## Why terminating matters

IEC-104 numbers every I-frame. A byte relay that drops a disallowed command
would leave the master's N(S) ahead of the RTU's, and the next frame would be
rejected or misinterpreted. Forwarding the command and relying on the RTU to
reject it would execute it.

The proxy therefore terminates both TCP legs, acknowledges each I-frame, and
allocates fresh sequence numbers. A denied command is consumed on the master
leg and answered with a negative activation confirmation; the RTU leg never
sees it.

## Loopback proof

`make interop` runs the independent-peer proof:

- an independent outstation listens on a free loopback port;
- the proxy owns a second loopback port;
- an independent master connects to the proxy;
- interrogation data crosses;
- an allowed command reaches the outstation and gets a positive confirmation;
- a denied command gets a negative confirmation and does not reach the
  outstation;
- after the proxy stops, the proxy's port refuses connections.

This is **port-level** takeover on loopback. It does not exercise ARP/NDP,
gratuitous ARP, duplicate-address detection, a switch CAM table, a second NIC
or privileged port 2404.

## What to test on a real lab

1. Bind the old RTU IP on the proxy's interface and the new IP on the RTU.
2. Verify ARP/NDP takeover and gratuitous ARP.
3. Verify duplicate-address detection does not fight the proxy.
4. Verify the switch CAM table moves to the proxy's port.
5. Test with the real master, not a simulator.
6. Stop the proxy and confirm the old IP is unreachable while the RTU still
   answers at its new address.
