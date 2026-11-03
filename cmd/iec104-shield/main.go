// Command iec104-shield runs an IEC 60870-5-104 security proxy.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/pflag"
	"go.uber.org/zap"

	"github.com/GalaxyGorilla/iec104-shield/internal/config"
	"github.com/GalaxyGorilla/iec104-shield/internal/iec104"
	"github.com/GalaxyGorilla/iec104-shield/internal/observ"
	"github.com/GalaxyGorilla/iec104-shield/internal/proxy"
)

// version is overridden for releases via ldflags.
var version = "0.1.0"

func main() { os.Exit(run()) }

func run() int {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		return 2
	}
	switch os.Args[1] {
	case "version", "--version", "-v":
		fmt.Printf("iec104-shield %s\n", version)
		return 0
	case "gateway":
		return runGateway(os.Args[2:])
	case "validate":
		return runValidate(os.Args[2:])
	case "selftest":
		return runSelftest(os.Args[2:])
	case "help", "--help", "-h":
		usage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage(os.Stderr)
		return 2
	}
}

type cliFlags struct {
	fs *pflag.FlagSet

	configPath   *string
	listen       *string
	device       *string
	allow        *[]string
	maxClients   *int
	readOnly     *bool
	allowUnknown *bool
	commandDef   *string
	commandRules *[]string
	dialTimeout  *int
	idleTimeout  *int
	t1           *int
	k            *int
	metricsAddr  *string
	logLevel     *string
	logFormat    *string
	jsonOut      *bool
	probe        *bool
}

func register(fs *pflag.FlagSet) cliFlags {
	var c cliFlags
	c.fs = fs
	c.configPath = fs.String("config", "", "path to YAML config file (either --config or direct flags)")
	c.listen = fs.String("listen", "", "front-leg listener address the master connects to, ip:port")
	c.device = fs.String("device", "", "outstation address behind the appliance, ip:port")
	c.allow = fs.StringArray("allow", nil, "client allow-list entry, IP or CIDR (repeatable; empty = any client)")
	c.maxClients = fs.Int("max-clients", 0, "max concurrent master connections (0 = default 8)")
	c.readOnly = fs.Bool("read-only", false, "block every write-class ASDU; interrogation/read/test stay allowed")
	c.allowUnknown = fs.Bool("allow-unknown-types", false, "forward master ASDUs whose type the proxy cannot classify (default: refuse them)")
	c.commandDef = fs.String("command-default", "", "command policy verdict for writes no rule covers: deny (default) or allow")
	c.commandRules = fs.StringArray("command-rule", nil, "command rule ACTION:TYPES:CA:IOA:SELECT (repeatable; TYPES/CA/IOA/SELECT may be *; e.g. allow:45,46:1:1000-2000:execute)")
	c.dialTimeout = fs.Int("dial-timeout-ms", 0, "upstream dial timeout in ms (0 = default 5000)")
	c.idleTimeout = fs.Int("idle-timeout-ms", 0, "close an idle master connection after this many ms (0 = disabled)")
	c.t1 = fs.Int("t1-ms", 0, "unacknowledged I-frame timeout in ms (0 = default 15000)")
	c.k = fs.Int("k", 0, "max unacknowledged I-frames toward one peer (0 = default 12)")
	c.metricsAddr = fs.String("metrics-addr", "", "Prometheus metrics listen address (e.g. 127.0.0.1:9204)")
	c.logLevel = fs.String("log-level", "info", "log level: debug, info, warn, error")
	c.logFormat = fs.String("log-format", "console", "log format: console or json")
	c.jsonOut = fs.Bool("json", false, "validate/selftest: machine-readable JSON output")
	c.probe = fs.Bool("probe", true, "selftest: dial each outstation and exchange TESTFR")
	return c
}

func flagsConfig(c cliFlags) (*config.Config, error) {
	if *c.listen == "" {
		return nil, fmt.Errorf("--listen is required")
	}
	if *c.device == "" {
		return nil, fmt.Errorf("--device is required")
	}
	dev := config.Device{
		Name:              "",
		ListenAddr:        *c.listen,
		DeviceAddr:        *c.device,
		Allow:             *c.allow,
		MaxClients:        *c.maxClients,
		ReadOnly:          *c.readOnly,
		AllowUnknownTypes: *c.allowUnknown,
		DialTimeoutMs:     *c.dialTimeout,
		IdleTimeoutMs:     *c.idleTimeout,
		T1Ms:              *c.t1,
		K:                 *c.k,
	}
	if *c.commandDef != "" || len(*c.commandRules) > 0 {
		def := *c.commandDef
		if def == "" {
			def = "deny"
		}
		pol := &config.CommandPolicy{Default: def}
		for _, spec := range *c.commandRules {
			rule, err := parseCommandRule(spec)
			if err != nil {
				return nil, err
			}
			pol.Rules = append(pol.Rules, rule)
		}
		dev.CommandPolicy = pol
	}
	cfg := config.Defaults()
	cfg.Devices = []config.Device{dev}
	cfg.Log.Level = *c.logLevel
	cfg.Log.Format = *c.logFormat
	cfg.Metrics.Addr = *c.metricsAddr
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func parseCommandRule(spec string) (config.CommandRule, error) {
	parts := strings.Split(spec, ":")
	if len(parts) != 5 {
		return config.CommandRule{}, fmt.Errorf("command rule %q: want ACTION:TYPES:CA:IOA:SELECT", spec)
	}
	action := strings.ToLower(strings.TrimSpace(parts[0]))
	if action != "allow" && action != "deny" {
		return config.CommandRule{}, fmt.Errorf("command rule %q: action must be allow or deny", spec)
	}
	rule := config.CommandRule{Action: action}
	if t := strings.TrimSpace(parts[1]); t != "" && t != "*" {
		for _, s := range strings.Split(t, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(s))
			if err != nil {
				return config.CommandRule{}, fmt.Errorf("command rule %q: type %q", spec, s)
			}
			rule.Types = append(rule.Types, n)
		}
	}
	if ca := strings.TrimSpace(parts[2]); ca != "" && ca != "*" {
		n, err := strconv.Atoi(ca)
		if err != nil || n < 0 || n > 65535 {
			return config.CommandRule{}, fmt.Errorf("command rule %q: common address %q", spec, ca)
		}
		rule.CommonAddress = &config.CommonAddress{Value: uint16(n)}
	}
	if ioa := strings.TrimSpace(parts[3]); ioa != "" && ioa != "*" {
		parts := strings.Split(ioa, "-")
		if len(parts) > 2 {
			return config.CommandRule{}, fmt.Errorf("command rule %q: ioa %q", spec, ioa)
		}
		from, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 32)
		if err != nil || from > 0xffffff {
			return config.CommandRule{}, fmt.Errorf("command rule %q: ioa %q", spec, ioa)
		}
		to := from
		if len(parts) == 2 {
			to, err = strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 32)
			if err != nil || to > 0xffffff {
				return config.CommandRule{}, fmt.Errorf("command rule %q: ioa %q", spec, ioa)
			}
		}
		if from > to {
			return config.CommandRule{}, fmt.Errorf("command rule %q: ioa from must be <= to", spec)
		}
		rule.IOA = &config.IOARange{From: uint32(from), To: uint32(to)}
	}
	switch sel := strings.ToLower(strings.TrimSpace(parts[4])); sel {
	case "", "any", "*":
	case "select", "execute":
		rule.Select = sel
	default:
		return config.CommandRule{}, fmt.Errorf("command rule %q: select must be any, select or execute", spec)
	}
	return rule, nil
}

func loadChecked(c cliFlags) (*config.Config, error) {
	if *c.configPath != "" {
		return config.Load(*c.configPath)
	}
	return flagsConfig(c)
}

func runGateway(args []string) int {
	fs := pflag.NewFlagSet("gateway", pflag.ContinueOnError)
	c := register(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadChecked(c)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	log, err := observ.Log(cfg.Log.Level, cfg.Log.Format)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = log.Sync() }()

	met := observ.NewMetrics()
	var audit *observ.Audit
	if cfg.Audit.File != "" {
		audit, err = observ.NewAuditFile(cfg.Audit.File, int64(cfg.Audit.MaxMB)*1024*1024, met.AuditDropped)
		if err != nil {
			log.Error("audit", zap.Error(err))
			return 1
		}
		defer func() { _ = audit.Close() }()
	}

	runner, err := proxy.NewRunner(cfg, log.Sugar(), met, audit)
	if err != nil {
		log.Error("build gateways", zap.Error(err))
		return 1
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if cfg.Metrics.Addr != "" {
		ln, err := observ.Listen(cfg.Metrics.Addr)
		if err != nil {
			log.Error("metrics", zap.Error(err))
			return 1
		}
		go func() {
			if err := observ.Serve(ctx, ln, met.Handler(), log); err != nil {
				log.Error("metrics server", zap.Error(err))
			}
		}()
	}

	errCh := make(chan error, 1)
	go func() { errCh <- runner.Run() }()
	select {
	case <-runner.Ready():
		log.Info("iec104-shield ready")
	case err := <-errCh:
		log.Error("startup", zap.Error(err))
		return 1
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sig)
	for {
		select {
		case s := <-sig:
			if s == syscall.SIGHUP {
				log.Warn("SIGHUP: reload is not implemented in v0.1; keeping the running config")
				continue
			}
			log.Info("shutting down", zap.String("signal", s.String()))
			runner.Stop()
			<-errCh
			return 0
		case err := <-errCh:
			runner.Stop()
			if err != nil {
				log.Error("gateway stopped", zap.Error(err))
				return 1
			}
			return 0
		}
	}
}

type checkResult struct {
	Device string `json:"device"`
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
}

func runValidate(args []string) int {
	fs := pflag.NewFlagSet("validate", pflag.ContinueOnError)
	c := register(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadChecked(c)
	if err != nil {
		if *c.jsonOut {
			_ = json.NewEncoder(os.Stdout).Encode(checkResult{OK: false, Error: err.Error()})
		} else {
			fmt.Fprintln(os.Stderr, err)
		}
		return 1
	}
	if *c.jsonOut {
		_ = json.NewEncoder(os.Stdout).Encode(checkResult{OK: true})
	} else {
		fmt.Printf("ok: %d device(s)\n", len(cfg.Devices))
	}
	return 0
}

func runSelftest(args []string) int {
	fs := pflag.NewFlagSet("selftest", pflag.ContinueOnError)
	c := register(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadChecked(c)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	results := make([]checkResult, 0, len(cfg.Devices))
	failed := false
	for _, dev := range cfg.Devices {
		res := checkResult{Device: dev.Name, OK: true}
		if *c.probe {
			if err := probe(dev.DeviceAddr, time.Duration(dev.DialTimeoutMs)*time.Millisecond); err != nil {
				res.OK = false
				res.Error = err.Error()
				failed = true
			}
		}
		results = append(results, res)
	}
	if *c.jsonOut {
		_ = json.NewEncoder(os.Stdout).Encode(results)
	} else {
		for _, r := range results {
			if r.OK {
				fmt.Printf("%s: ok\n", r.Device)
			} else {
				fmt.Printf("%s: FAIL: %s\n", r.Device, r.Error)
			}
		}
	}
	if failed {
		return 1
	}
	return 0
}

// probe dials the outstation and exchanges TESTFR, proving that the TCP path
// and the IEC-104 APCI are alive without starting data transfer.
func probe(addr string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(iec104.NewU(iec104.UStartDTActive)); err != nil {
		return err
	}
	if _, err := conn.Write(iec104.NewU(iec104.UTestFRActive)); err != nil {
		return err
	}
	for {
		f, err := iec104.ReadFrame(conn)
		if err != nil {
			return err
		}
		if f.Type == iec104.UFrame && f.U == iec104.UTestFRConfirm {
			return nil
		}
	}
}

func usage(w *os.File) {
	fmt.Fprintln(w, `iec104-shield — IEC 60870-5-104 security proxy

Usage:
  iec104-shield gateway  --config FILE | --listen ADDR --device ADDR [flags]
  iec104-shield validate --config FILE | --listen ADDR --device ADDR
  iec104-shield selftest --config FILE | --listen ADDR --device ADDR
  iec104-shield version

The gateway owns the master-visible address, moves the outstation behind it,
and enforces a command policy on the IEC-104 application layer. Denied
commands are answered with a negative activation confirmation and never reach
the outstation. If the gateway or upstream path fails, the master connection
is closed (fail-closed); there is no bypass.`)
}
