// Package config loads the IEC-104 gateway configuration. One YAML file
// describes one process with one or more listener<->outstation pairs. Each
// device has its own allow-list and command policy; the process shares one
// metrics endpoint and one audit stream.
package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/GalaxyGorilla/iec104-shield/internal/policy"
)

const (
	defaultMaxClients    = 8
	defaultDialTimeoutMs = 5000
	defaultT1Ms          = 15000
	defaultK             = 12
	defaultAuditMaxMB    = 64
)

// Config is the top-level process configuration.
type Config struct {
	Devices []Device `yaml:"devices"`
	Log     Log      `yaml:"log"`
	Metrics Metrics  `yaml:"metrics"`
	Audit   Audit    `yaml:"audit"`
}

// Device couples one front-leg listener with one outstation.
type Device struct {
	Name string `yaml:"name"`
	// ListenAddr is the client-visible address the appliance owns. This is
	// the outstation's original address in an address-takeover deployment.
	ListenAddr string `yaml:"listen_addr"`
	// DeviceAddr is the outstation's new address behind the appliance.
	DeviceAddr string `yaml:"device_addr"`

	Allow []string `yaml:"allow"`
	// MaxClients caps concurrent master connections. IEC-104 sessions are
	// stateful, so the proxy opens one upstream connection per client.
	MaxClients int `yaml:"max_clients"`

	// ReadOnly blocks every write-class ASDU (commands, clock sync,
	// reset, parameter and file transfer). Interrogation, counter
	// interrogation, read and test commands remain available.
	ReadOnly bool `yaml:"read_only"`
	// CommandPolicy is the fine-grained alternative to read_only.
	CommandPolicy *CommandPolicy `yaml:"command_policy"`
	// AllowUnknownTypes forwards master-to-outstation ASDUs whose type is
	// not in the standard fixed-size table. Default false: an unknown or
	// private type from the master is refused (fail closed) because the
	// proxy cannot classify it. Device-to-master monitoring is never
	// filtered by type.
	AllowUnknownTypes bool `yaml:"allow_unknown_types"`

	DialTimeoutMs int `yaml:"dial_timeout_ms"`
	IdleTimeoutMs int `yaml:"idle_timeout_ms"`
	// T1Ms bounds how long an unacknowledged I-frame may stay outstanding.
	T1Ms int `yaml:"t1_ms"`
	// K is the maximum number of unacknowledged I-frames the proxy sends
	// to one peer. Default 12 (the IEC-104 default).
	K int `yaml:"k"`
}

// CommandPolicy is the scoped command policy. Default is the verdict for a
// write no rule matches; rules are evaluated as a set with deny-overrides.
type CommandPolicy struct {
	Default string        `yaml:"default"`
	Rules   []CommandRule `yaml:"rules"`
}

// CommandRule is one scoped rule. An empty Types, CommonAddress, IOA or Select
// matches everything in that dimension. Action defaults to allow.
type CommandRule struct {
	Types         IntList        `yaml:"types"`
	CommonAddress *CommonAddress `yaml:"common_address"`
	IOA           *IOARange      `yaml:"ioa"`
	Select        string         `yaml:"select"`
	Action        string         `yaml:"action"`
}

// Log selects logging behavior.
type Log struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// Metrics is the Prometheus listener.
type Metrics struct {
	Addr string `yaml:"addr"`
}

// Audit is the optional structured security-decision stream.
type Audit struct {
	File  string `yaml:"file"`
	MaxMB int    `yaml:"max_mb"`
}

// IntList accepts either a scalar integer or a YAML sequence.
type IntList []int

// UnmarshalYAML implements yaml.Unmarshaler.
func (l *IntList) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		var v int
		if err := value.Decode(&v); err != nil {
			return err
		}
		*l = IntList{v}
	case yaml.SequenceNode:
		var v []int
		if err := value.Decode(&v); err != nil {
			return err
		}
		*l = IntList(v)
	default:
		return fmt.Errorf("expected an integer or a list of integers")
	}
	return nil
}

// CommonAddress accepts "*" or a 0..65535 integer.
type CommonAddress struct {
	Any   bool
	Value uint16
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (a *CommonAddress) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("expected \"*\" or a common address")
	}
	if value.Value == "*" {
		a.Any = true
		return nil
	}
	var v int
	if err := value.Decode(&v); err != nil {
		return err
	}
	if v < 0 || v > 65535 {
		return fmt.Errorf("common address %d outside 0..65535", v)
	}
	a.Value = uint16(v)
	return nil
}

// IOARange accepts "*", a single address, or "from-to".
type IOARange struct {
	Any  bool
	From uint32
	To   uint32
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (r *IOARange) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("expected \"*\", an address, or an address range")
	}
	s := strings.TrimSpace(value.Value)
	if s == "" || s == "*" {
		r.Any = true
		return nil
	}
	parts := strings.Split(s, "-")
	if len(parts) > 2 {
		return fmt.Errorf("invalid ioa range %q", s)
	}
	from, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 32)
	if err != nil || from > 0xffffff {
		return fmt.Errorf("invalid ioa %q", s)
	}
	to := from
	if len(parts) == 2 {
		to, err = strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 32)
		if err != nil || to > 0xffffff {
			return fmt.Errorf("invalid ioa range %q", s)
		}
	}
	if from > to {
		return fmt.Errorf("ioa range %q: from must be <= to", s)
	}
	r.From, r.To = uint32(from), uint32(to)
	return nil
}

// Defaults returns a config with process defaults filled in.
func Defaults() *Config {
	return &Config{
		Log:   Log{Level: "info", Format: "console"},
		Audit: Audit{MaxMB: defaultAuditMaxMB},
	}
}

// Load reads and validates a YAML config. Unknown keys are errors.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	defer f.Close()
	return Decode(f)
}

// Decode is Load for an arbitrary reader.
func Decode(r io.Reader) (*Config, error) {
	c := Defaults()
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("config: %w", err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// ApplyDefaults fills process and device defaults. It is exported for the
// flags-mode command path, which builds a Config in memory instead of decoding
// YAML.
func (c *Config) ApplyDefaults() { c.applyDefaults() }

func (c *Config) applyDefaults() {
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.Format == "" {
		c.Log.Format = "console"
	}
	if c.Audit.MaxMB == 0 {
		c.Audit.MaxMB = defaultAuditMaxMB
	}
	for i := range c.Devices {
		d := &c.Devices[i]
		if d.Name == "" {
			d.Name = d.DeviceAddr
		}
		if d.MaxClients == 0 {
			d.MaxClients = defaultMaxClients
		}
		if d.DialTimeoutMs == 0 {
			d.DialTimeoutMs = defaultDialTimeoutMs
		}
		if d.T1Ms == 0 {
			d.T1Ms = defaultT1Ms
		}
		if d.K == 0 {
			d.K = defaultK
		}
		if d.CommandPolicy != nil && d.CommandPolicy.Default == "" {
			d.CommandPolicy.Default = "deny"
		}
	}
}

// Validate checks every field that can be checked without touching the
// network and compiles the policies so validation and runtime agree.
func (c *Config) Validate() error {
	if len(c.Devices) == 0 {
		return errors.New("config: at least one device entry is required")
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("config: log.level %q (want debug|info|warn|error)", c.Log.Level)
	}
	switch c.Log.Format {
	case "console", "json":
	default:
		return fmt.Errorf("config: log.format %q (want console|json)", c.Log.Format)
	}
	if c.Metrics.Addr != "" {
		if err := validateHostPort("metrics.addr", c.Metrics.Addr); err != nil {
			return fmt.Errorf("config: %s", err)
		}
	}
	if c.Audit.MaxMB < 1 || c.Audit.MaxMB > 10240 {
		return fmt.Errorf("config: audit.max_mb %d outside 1..10240", c.Audit.MaxMB)
	}
	seen := make(map[string]string, len(c.Devices))
	for i := range c.Devices {
		if err := c.Devices[i].validate(i, seen); err != nil {
			return err
		}
	}
	return nil
}

func (d *Device) validate(i int, seen map[string]string) error {
	label := d.Name
	if label == "" {
		label = fmt.Sprintf("devices[%d]", i)
	}
	fail := func(format string, args ...any) error {
		return fmt.Errorf("config: device %q: %s", label, fmt.Sprintf(format, args...))
	}
	if d.ListenAddr == "" {
		return fail("listen_addr is required")
	}
	if err := validateHostPort("listen_addr", d.ListenAddr); err != nil {
		return fail("%s", err)
	}
	if prev, ok := seen[d.ListenAddr]; ok {
		return fail("listen_addr %q is already used by device %q", d.ListenAddr, prev)
	}
	seen[d.ListenAddr] = label
	if d.DeviceAddr == "" {
		return fail("device_addr is required")
	}
	if err := validateHostPort("device_addr", d.DeviceAddr); err != nil {
		return fail("%s", err)
	}
	if d.ListenAddr == d.DeviceAddr {
		return fail("listen_addr and device_addr must differ (the proxy would dial itself)")
	}
	if _, err := policy.NewList(d.Allow); err != nil {
		return fail("allow: %v", err)
	}
	if d.MaxClients < 1 || d.MaxClients > 1024 {
		return fail("max_clients %d outside 1..1024", d.MaxClients)
	}
	if d.DialTimeoutMs < 0 || d.IdleTimeoutMs < 0 || d.T1Ms < 0 {
		return fail("timeouts must not be negative")
	}
	if d.K < 1 || d.K > 32767 {
		return fail("k %d outside 1..32767", d.K)
	}
	if d.ReadOnly && d.CommandPolicy != nil {
		return fail("read_only and command_policy are mutually exclusive")
	}
	if d.CommandPolicy != nil {
		if err := d.CommandPolicy.validate(); err != nil {
			return fail("command_policy: %v", err)
		}
	}
	if _, err := d.CompilePolicy(); err != nil {
		return fail("command_policy: %v", err)
	}
	return nil
}

func (p *CommandPolicy) validate() error {
	switch p.Default {
	case "", "allow", "deny":
	default:
		return fmt.Errorf("default %q (want allow|deny)", p.Default)
	}
	for i, r := range p.Rules {
		for _, t := range r.Types {
			if t < 1 || t > 255 {
				return fmt.Errorf("rule %d: type %d outside 1..255", i, t)
			}
		}
		switch r.Select {
		case "", "any", "select", "execute":
		default:
			return fmt.Errorf("rule %d: select %q (want any|select|execute)", i, r.Select)
		}
		switch r.Action {
		case "", "allow", "deny":
		default:
			return fmt.Errorf("rule %d: action %q (want allow|deny)", i, r.Action)
		}
	}
	return nil
}

// CompilePolicy converts the YAML policy into the runtime policy.
func (d Device) CompilePolicy() (*policy.Policy, error) {
	if d.ReadOnly {
		return policy.New(true, false, nil)
	}
	if d.CommandPolicy == nil {
		// Secure default: without an explicit policy, write-class ASDUs
		// are denied. Monitoring, interrogation and test commands still
		// pass. A site that wants transparent command forwarding must say
		// so with `command_policy.default: allow`.
		return policy.New(false, false, nil)
	}
	defaultAllow := d.CommandPolicy.Default == "allow"
	rules := make([]policy.Rule, 0, len(d.CommandPolicy.Rules))
	for _, r := range d.CommandPolicy.Rules {
		cr := policy.Rule{Allow: r.Action != "deny"}
		for _, t := range r.Types {
			cr.Types = append(cr.Types, uint8(t))
		}
		if r.CommonAddress != nil && !r.CommonAddress.Any {
			ca := r.CommonAddress.Value
			cr.CommonAddress = &ca
		}
		if r.IOA != nil && !r.IOA.Any {
			from, to := r.IOA.From, r.IOA.To
			cr.IOAFrom, cr.IOATo = &from, &to
		}
		switch r.Select {
		case "select":
			v := true
			cr.Select = &v
		case "execute":
			v := false
			cr.Select = &v
		}
		rules = append(rules, cr)
	}
	return policy.New(false, defaultAllow, rules)
}

// CompileAllow builds the client allow-list.
func (d Device) CompileAllow() (*policy.List, error) { return policy.NewList(d.Allow) }

func validateHostPort(field, s string) error {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return fmt.Errorf("%s %q: %w", field, s, err)
	}
	if host == "" && !strings.HasPrefix(s, ":") {
		return fmt.Errorf("%s %q: empty host", field, s)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("%s %q: port outside 1..65535", field, s)
	}
	return nil
}
