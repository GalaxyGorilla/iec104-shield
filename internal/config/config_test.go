package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/GalaxyGorilla/iec104-shield/internal/iec104"
)

func TestDecodeValid(t *testing.T) {
	c, err := Decode(strings.NewReader(`
devices:
  - name: substation
    listen_addr: "127.0.0.1:2404"
    device_addr: "127.0.0.1:2405"
    allow: ["10.0.0.0/8"]
    max_clients: 2
    read_only: true
log:
  level: debug
metrics:
  addr: "127.0.0.1:9204"
audit:
  file: "/tmp/iec104-audit.jsonl"
  max_mb: 8
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Devices) != 1 || c.Devices[0].MaxClients != 2 {
		t.Fatalf("config = %+v", c)
	}
	if c.Devices[0].DialTimeoutMs != defaultDialTimeoutMs || c.Devices[0].K != defaultK {
		t.Fatalf("defaults = %+v", c.Devices[0])
	}
	if c.Audit.MaxMB != 8 || c.Log.Level != "debug" {
		t.Fatalf("process = %+v", c)
	}
}

func TestDecodeCommandPolicy(t *testing.T) {
	c, err := Decode(strings.NewReader(`
devices:
  - listen_addr: "127.0.0.1:2404"
    device_addr: "127.0.0.1:2405"
    command_policy:
      default: deny
      rules:
        - types: [45, 46]
          common_address: 1
          ioa: "1000-2000"
          select: execute
          action: allow
        - types: 45
          common_address: "*"
          ioa: 1500
          action: deny
`))
	if err != nil {
		t.Fatal(err)
	}
	pol, err := c.Devices[0].CompilePolicy()
	if err != nil {
		t.Fatal(err)
	}
	allow := func(typ uint8, ca uint16, ioa uint32, sel bool) bool {
		info := byte(0x01)
		if sel {
			info |= 0x80
		}
		a, err := iec104.ParseASDU([]byte{typ, 0x01, 0x06, 0x00,
			byte(ca), byte(ca >> 8), byte(ioa), byte(ioa >> 8), byte(ioa >> 16), info})
		if err != nil {
			t.Fatal(err)
		}
		return pol.Allowed(a)
	}
	if !allow(45, 1, 1200, false) {
		t.Fatal("allow rule did not permit execute")
	}
	if allow(45, 1, 1200, true) {
		t.Fatal("select should not match an execute-only rule")
	}
	if allow(45, 1, 1500, false) {
		t.Fatal("deny rule did not override")
	}
	if allow(46, 1, 2500, false) {
		t.Fatal("address outside the allow range was permitted")
	}
	if allow(46, 2, 1200, false) {
		t.Fatal("wrong common address was permitted")
	}
}

func TestDecodeRejects(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{"unknown-key", `
devices:
  - listen_addr: "127.0.0.1:2404"
    device_addr: "127.0.0.1:2405"
    read_onyl: true
`, "field read_onyl not found"},
		{"duplicate-listen", `
devices:
  - listen_addr: "127.0.0.1:2404"
    device_addr: "127.0.0.1:2405"
  - listen_addr: "127.0.0.1:2404"
    device_addr: "127.0.0.1:2406"
`, "already used"},
		{"read-only-and-policy", `
devices:
  - listen_addr: "127.0.0.1:2404"
    device_addr: "127.0.0.1:2405"
    read_only: true
    command_policy:
      default: deny
`, "mutually exclusive"},
		{"bad-select", `
devices:
  - listen_addr: "127.0.0.1:2404"
    device_addr: "127.0.0.1:2405"
    command_policy:
      rules:
        - types: 45
          select: sometimes
`, "select"},
		{"bad-ioa", `
devices:
  - listen_addr: "127.0.0.1:2404"
    device_addr: "127.0.0.1:2405"
    command_policy:
      rules:
        - types: 45
          ioa: "2000-1000"
`, "from must be <= to"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode(strings.NewReader(tc.yaml))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestIntListScalarAndSequence(t *testing.T) {
	var l IntList
	if err := l.UnmarshalYAML(&yaml.Node{Kind: yaml.ScalarNode, Value: "45"}); err != nil {
		t.Fatal(err)
	}
	if len(l) != 1 || l[0] != 45 {
		t.Fatalf("list = %v", l)
	}
	if err := l.UnmarshalYAML(&yaml.Node{Kind: yaml.SequenceNode, Content: []*yaml.Node{
		{Kind: yaml.ScalarNode, Value: "45"},
		{Kind: yaml.ScalarNode, Value: "46"},
	}}); err != nil {
		t.Fatal(err)
	}
	if len(l) != 2 || l[1] != 46 {
		t.Fatalf("list = %v", l)
	}
}
