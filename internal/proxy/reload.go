package proxy

import (
	"fmt"

	"github.com/GalaxyGorilla/iec104-shield/internal/config"
)

// Reload applies a freshly loaded configuration to the running gateways
// WITHOUT dropping listeners or the master/outstation connections. It returns
// human-readable warnings for everything it could not apply; the caller (main,
// on SIGHUP) logs them. An empty slice means the new configuration was applied
// completely.
//
// Reloadable: command policy, read_only, allow-list, allow_unknown_types,
// max_clients, dial/idle timeout, t1 and k. Policy and allow_unknown_types are
// read for every master frame, so a revocation applies to an already
// established session on its next command.
//
// Restart required (reported, not applied): listen_addr, device_addr, and
// adding or removing a device. A device whose new runtime fails to compile
// keeps serving its previous settings; Reload never leaves a gateway without a
// usable runtime.
func (r *Runner) Reload(cfg *config.Config) []string {
	var warnings []string
	running := make(map[string]bool, len(r.gws))
	for _, gw := range r.gws {
		running[gw.cfg.Name] = true
	}

	for _, gw := range r.gws {
		name := gw.cfg.Name
		dev := findDevice(cfg, name)
		if dev == nil {
			warnings = append(warnings, fmt.Sprintf(
				"device %s: no longer in the config; still serving (restart required to remove it)", name))
			continue
		}
		for _, msg := range restartRequired(gw, *dev) {
			warnings = append(warnings, fmt.Sprintf("device %s: %s (restart required)", name, msg))
		}
		rt, err := newGatewayRuntime(*dev)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf(
				"device %s: reload failed, keeping previous settings: %v", name, err))
			continue
		}
		gw.setRuntime(rt)
		if r.log != nil {
			r.log.Infof("device %s: configuration reloaded (read_only=%v max_clients=%d allow_unknown_types=%v)",
				name, rt.policy.ReadOnly(), rt.maxClients, rt.allowUnknownTypes)
		}
	}

	// New devices cannot be added without binding their listeners, so they are
	// reported instead of silently ignored (the operator would otherwise
	// believe the new device is protected).
	for i := range cfg.Devices {
		if !running[cfg.Devices[i].Name] {
			warnings = append(warnings, fmt.Sprintf(
				"device %s: new in the config, not running (restart required to add it)", cfg.Devices[i].Name))
		}
	}
	return warnings
}

// findDevice returns the config entry for a running gateway, matched by name.
func findDevice(cfg *config.Config, name string) *config.Device {
	for i := range cfg.Devices {
		if cfg.Devices[i].Name == name {
			return &cfg.Devices[i]
		}
	}
	return nil
}

// restartRequired lists the differences a SIGHUP cannot apply because they are
// bound to the listener or the upstream dial target.
func restartRequired(gw *Gateway, dev config.Device) []string {
	old := gw.cfg
	var msgs []string
	if old.ListenAddr != dev.ListenAddr {
		msgs = append(msgs, fmt.Sprintf("listen_addr %s -> %s", old.ListenAddr, dev.ListenAddr))
	}
	if old.DeviceAddr != dev.DeviceAddr {
		msgs = append(msgs, fmt.Sprintf("device_addr %s -> %s", old.DeviceAddr, dev.DeviceAddr))
	}
	return msgs
}
