package proxy

import (
	"net"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/GalaxyGorilla/iec104-shield/internal/config"
)

func reloadConfig(t *testing.T, dev config.Device) *config.Config {
	t.Helper()
	cfg := config.Defaults()
	cfg.Devices = []config.Device{dev}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func startReloadRunner(t *testing.T, dev config.Device) (*Runner, *config.Config) {
	t.Helper()
	cfg := reloadConfig(t, dev)
	r, err := NewRunner(cfg, zap.NewNop().Sugar(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- r.Run() }()
	select {
	case <-r.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("runner did not become ready")
	}
	t.Cleanup(func() {
		r.Stop()
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("runner stop: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("runner did not stop")
		}
	})
	return r, cfg
}

func TestReloadPolicyAppliesToEstablishedSession(t *testing.T) {
	fake := startFake(t, replyCommand)
	defer fake.close()
	dev := testDevice(fake.addr())
	dev.ListenAddr = freeTCPAddr(t)
	dev.CommandPolicy = &config.CommandPolicy{Default: "deny"}
	r, _ := startReloadRunner(t, dev)

	m := dialMaster(t, dev.ListenAddr)
	defer m.close()

	if err := m.sendI(singleCommand(1, 1000, false, true)); err != nil {
		t.Fatal(err)
	}
	neg, err := m.readI()
	if err != nil {
		t.Fatal(err)
	}
	if !neg.PN {
		t.Fatalf("command was not denied before the reload: %+v", neg)
	}

	dev.CommandPolicy = &config.CommandPolicy{Default: "allow"}
	if warnings := r.Reload(reloadConfig(t, dev)); len(warnings) != 0 {
		t.Fatalf("reload warnings: %v", warnings)
	}

	// Same connection: the policy snapshot is read per frame, so the
	// established session must see the new verdict.
	if err := m.sendI(singleCommand(1, 1000, false, true)); err != nil {
		t.Fatal(err)
	}
	con, err := m.readI()
	if err != nil {
		t.Fatal(err)
	}
	if con.PN {
		t.Fatalf("command was still denied after the reload: %+v", con)
	}
	if got := fake.received(); len(got) != 1 {
		t.Fatalf("outstation received %d commands, want 1", len(got))
	}
}

func TestReloadAllowListAppliesToNewConnections(t *testing.T) {
	fake := startFake(t, replyCommand)
	defer fake.close()
	dev := testDevice(fake.addr())
	dev.ListenAddr = freeTCPAddr(t)
	dev.Allow = []string{"127.0.0.1/32"}
	r, _ := startReloadRunner(t, dev)

	m := dialMaster(t, dev.ListenAddr)
	defer m.close()

	dev.Allow = []string{"10.0.0.0/8"}
	if warnings := r.Reload(reloadConfig(t, dev)); len(warnings) != 0 {
		t.Fatalf("reload warnings: %v", warnings)
	}

	// A new connection is admitted by the listener and then rejected by the
	// new allow-list; the existing session is not torn down.
	conn, err := net.DialTimeout("tcp", dev.ListenAddr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := conn.Read(b[:]); err == nil {
		t.Fatal("new connection was not rejected by the reloaded allow-list")
	}

	if err := m.sendI(interrogation(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.readI(); err != nil {
		t.Fatalf("established session broke on reload: %v", err)
	}
}

func TestReloadMaxClients(t *testing.T) {
	fake := startFake(t, replyCommand)
	defer fake.close()
	dev := testDevice(fake.addr())
	dev.ListenAddr = freeTCPAddr(t)
	dev.MaxClients = 2
	r, _ := startReloadRunner(t, dev)

	m := dialMaster(t, dev.ListenAddr)
	defer m.close()

	dev.MaxClients = 1
	if warnings := r.Reload(reloadConfig(t, dev)); len(warnings) != 0 {
		t.Fatalf("reload warnings: %v", warnings)
	}

	conn, err := net.DialTimeout("tcp", dev.ListenAddr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := conn.Read(b[:]); err == nil {
		t.Fatal("second connection was not rejected by the reloaded limit")
	}
}

func TestReloadAllowUnknownTypes(t *testing.T) {
	fake := startFake(t, nil)
	defer fake.close()
	dev := testDevice(fake.addr())
	dev.ListenAddr = freeTCPAddr(t)
	r, _ := startReloadRunner(t, dev)

	m := dialMaster(t, dev.ListenAddr)
	defer m.close()
	unknown := []byte{200, 0x01, 0x06, 0x00, 0x01, 0x00, 0xde, 0xad}
	if err := m.sendI(unknown); err != nil {
		t.Fatal(err)
	}
	neg, err := m.readI()
	if err != nil {
		t.Fatal(err)
	}
	if !neg.PN {
		t.Fatalf("unknown type was not refused before the reload: %+v", neg)
	}

	dev.AllowUnknownTypes = true
	if warnings := r.Reload(reloadConfig(t, dev)); len(warnings) != 0 {
		t.Fatalf("reload warnings: %v", warnings)
	}
	if err := m.sendI(unknown); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if len(fake.received()) == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("unknown type was not forwarded after the reload")
}

func TestReloadBadRuntimeKeepsPrevious(t *testing.T) {
	fake := startFake(t, replyCommand)
	defer fake.close()
	dev := testDevice(fake.addr())
	dev.ListenAddr = freeTCPAddr(t)
	dev.CommandPolicy = &config.CommandPolicy{Default: "deny"}
	r, _ := startReloadRunner(t, dev)

	bad := dev
	// An inverted IOA range is rejected by CompilePolicy. Reload must report
	// it and keep the running (deny) policy.
	bad.CommandPolicy = &config.CommandPolicy{
		Default: "allow",
		Rules: []config.CommandRule{{
			Types:  config.IntList{45},
			IOA:    &config.IOARange{From: 10, To: 5},
			Action: "allow",
		}},
	}
	cfg := config.Defaults()
	cfg.Devices = []config.Device{bad}
	cfg.ApplyDefaults()
	warnings := r.Reload(cfg)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "keeping previous settings") {
		t.Fatalf("warnings = %v", warnings)
	}

	m := dialMaster(t, dev.ListenAddr)
	defer m.close()
	if err := m.sendI(singleCommand(1, 1000, false, true)); err != nil {
		t.Fatal(err)
	}
	neg, err := m.readI()
	if err != nil {
		t.Fatal(err)
	}
	if !neg.PN {
		t.Fatalf("bad reload changed the policy: %+v", neg)
	}
}

func TestReloadWarnsAboutRestartOnlyChanges(t *testing.T) {
	fake := startFake(t, replyCommand)
	defer fake.close()
	dev := testDevice(fake.addr())
	dev.ListenAddr = freeTCPAddr(t)
	r, cfg := startReloadRunner(t, dev)

	moved := dev
	moved.DeviceAddr = "127.0.0.1:1"
	cfg.Devices = []config.Device{moved}
	warnings := r.Reload(cfg)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "device_addr") {
		t.Fatalf("warnings = %v", warnings)
	}

	cfg.Devices = nil
	warnings = r.Reload(cfg)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "no longer in the config") {
		t.Fatalf("warnings = %v", warnings)
	}

	extra := dev
	extra.Name = "extra"
	cfg.Devices = []config.Device{dev, extra}
	warnings = r.Reload(cfg)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "new in the config") {
		t.Fatalf("warnings = %v", warnings)
	}
}

func TestReloadEnablesRateLimit(t *testing.T) {
	fake := startFake(t, replyCommand)
	defer fake.close()
	dev := testDevice(fake.addr())
	dev.ListenAddr = freeTCPAddr(t)
	dev.CommandPolicy = &config.CommandPolicy{Default: "allow"}
	r, _ := startReloadRunner(t, dev)

	m := dialMaster(t, dev.ListenAddr)
	defer m.close()
	for i := 0; i < 2; i++ {
		if err := m.sendI(singleCommand(1, 1000, false, true)); err != nil {
			t.Fatal(err)
		}
		if con, err := m.readI(); err != nil || con.PN {
			t.Fatalf("command %d before reload: %+v, %v", i, con, err)
		}
	}

	dev.RatePerSec = 1
	if warnings := r.Reload(reloadConfig(t, dev)); len(warnings) != 0 {
		t.Fatalf("reload warnings: %v", warnings)
	}

	// The reload creates a fresh bucket: one request passes, the next is
	// denied. This proves the limiter is part of the swapped snapshot.
	if err := m.sendI(singleCommand(1, 1000, false, true)); err != nil {
		t.Fatal(err)
	}
	if con, err := m.readI(); err != nil || con.PN {
		t.Fatalf("first command after reload: %+v, %v", con, err)
	}
	if err := m.sendI(singleCommand(1, 1000, false, true)); err != nil {
		t.Fatal(err)
	}
	neg, err := m.readI()
	if err != nil {
		t.Fatal(err)
	}
	if !neg.PN {
		t.Fatalf("second command after reload was not rate-limited: %+v", neg)
	}
	if got := len(fake.received()); got != 3 {
		t.Fatalf("outstation received %d commands, want 3", got)
	}
}
