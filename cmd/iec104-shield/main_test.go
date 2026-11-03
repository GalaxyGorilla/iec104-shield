package main

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"

	"github.com/GalaxyGorilla/iec104-shield/internal/iec104"
)

func parseFlags(t *testing.T, args ...string) cliFlags {
	t.Helper()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	c := register(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestParseCommandRule(t *testing.T) {
	r, err := parseCommandRule("allow:45,46:1:1000-2000:execute")
	if err != nil {
		t.Fatal(err)
	}
	if r.Action != "allow" || len(r.Types) != 2 || r.Types[0] != 45 {
		t.Fatalf("rule = %+v", r)
	}
	if r.CommonAddress == nil || r.CommonAddress.Value != 1 {
		t.Fatalf("ca = %+v", r.CommonAddress)
	}
	if r.IOA == nil || r.IOA.From != 1000 || r.IOA.To != 2000 {
		t.Fatalf("ioa = %+v", r.IOA)
	}
	if r.Select != "execute" {
		t.Fatalf("select = %q", r.Select)
	}
}

func TestParseCommandRuleWildcards(t *testing.T) {
	r, err := parseCommandRule("deny:*:*:*:*")
	if err != nil {
		t.Fatal(err)
	}
	if r.Action != "deny" || len(r.Types) != 0 || r.CommonAddress != nil || r.IOA != nil || r.Select != "" {
		t.Fatalf("rule = %+v", r)
	}
}

func TestParseCommandRuleRejects(t *testing.T) {
	for _, spec := range []string{
		"allow:45:1:1000",
		"maybe:45:1:1000:any",
		"allow:notanumber:1:1000:any",
		"allow:45:99999:1000:any",
		"allow:45:1:2000-1000:any",
		"allow:45:1:1000:never",
	} {
		if _, err := parseCommandRule(spec); err == nil {
			t.Fatalf("%q accepted", spec)
		}
	}
}

func TestFlagsConfig(t *testing.T) {
	c := parseFlags(t,
		"--listen", "127.0.0.1:2404",
		"--device", "127.0.0.1:2405",
		"--read-only",
		"--max-clients", "3",
	)
	cfg, err := flagsConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Devices) != 1 || cfg.Devices[0].MaxClients != 3 || !cfg.Devices[0].ReadOnly {
		t.Fatalf("config = %+v", cfg)
	}
	if cfg.Devices[0].K != 12 || cfg.Devices[0].DialTimeoutMs != 5000 {
		t.Fatalf("defaults = %+v", cfg.Devices[0])
	}
}

func TestFlagsConfigRejectsReadOnlyAndPolicy(t *testing.T) {
	c := parseFlags(t,
		"--listen", "127.0.0.1:2404",
		"--device", "127.0.0.1:2405",
		"--read-only",
		"--command-rule", "allow:45:1:1000-2000:any",
	)
	if _, err := flagsConfig(c); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("err = %v", err)
	}
}

func TestFlagsConfigRequiresEndpoints(t *testing.T) {
	c := parseFlags(t)
	if _, err := flagsConfig(c); err == nil {
		t.Fatal("missing endpoints accepted")
	}
}

func TestProbe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			f, err := iec104.ReadFrame(conn)
			if err != nil {
				return
			}
			if f.Type == iec104.UFrame && f.U == iec104.UTestFRActive {
				_, _ = conn.Write(iec104.NewU(iec104.UTestFRConfirm))
				return
			}
		}
	}()
	if err := probe(ln.Addr().String(), time.Second); err != nil {
		t.Fatalf("probe: %v", err)
	}
	_ = ln.Close()
	<-done
}

func TestProbeTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			if _, err := iec104.ReadFrame(conn); err != nil {
				return
			}
		}
	}()
	if err := probe(ln.Addr().String(), 100*time.Millisecond); err == nil {
		t.Fatal("probe succeeded without a TESTFR confirmation")
	}
}

func TestProbeDialError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	if err := probe(addr, 100*time.Millisecond); err == nil {
		t.Fatal("probe succeeded against a closed port")
	}
}
