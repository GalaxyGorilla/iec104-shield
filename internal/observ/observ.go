// Package observ provides the process logger, Prometheus metrics and the
// bounded JSON audit stream used by the IEC-104 gateway.
package observ

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Log builds the process logger.
func Log(level, format string) (*zap.Logger, error) {
	var lvl zapcore.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("observ: log level %q: %w", level, err)
	}
	cfg := zap.NewProductionConfig()
	if format == "console" {
		cfg = zap.NewDevelopmentConfig()
	}
	cfg.Level = zap.NewAtomicLevelAt(lvl)
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	cfg.DisableCaller = true
	return cfg.Build()
}

// Metrics is the process-wide Prometheus instrument set.
type Metrics struct {
	reg *prometheus.Registry

	ConnAccepted prometheus.Counter
	ConnRejected prometheus.Counter
	Active       prometheus.Gauge
	Frames       *prometheus.CounterVec
	Forwarded    *prometheus.CounterVec
	Denied       *prometheus.CounterVec
	ParseErrors  prometheus.Counter
	UpstreamErrs prometheus.Counter
	SequenceErrs prometheus.Counter
	AuditDropped prometheus.Counter
}

// NewMetrics builds an isolated registry and instrument set.
func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{reg: reg}
	m.ConnAccepted = counter(reg, "iec104_shield_connections_accepted_total",
		"Front-leg master connections accepted.")
	m.ConnRejected = counter(reg, "iec104_shield_connections_rejected_total",
		"Front-leg connections rejected by the allow-list or connection cap.")
	m.Active = gauge(reg, "iec104_shield_active_connections",
		"Front-leg master connections currently served.")
	m.Frames = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "iec104_shield_frames_total",
		Help: "APDUs received by device, direction (master|device) and frame type (I|S|U).",
	}, []string{"device", "direction", "type"})
	reg.MustRegister(m.Frames)
	m.Forwarded = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "iec104_shield_asdu_forwarded_total",
		Help: "I-frame ASDUs forwarded by device and direction.",
	}, []string{"device", "direction"})
	reg.MustRegister(m.Forwarded)
	m.Denied = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "iec104_shield_commands_denied_total",
		Help: "Write-class ASDUs refused by the command policy.",
	}, []string{"device", "reason"})
	reg.MustRegister(m.Denied)
	m.ParseErrors = counter(reg, "iec104_shield_parse_errors_total",
		"Malformed APDUs or ASDUs that caused a connection to close.")
	m.UpstreamErrs = counter(reg, "iec104_shield_upstream_errors_total",
		"Outstation dial, read or write errors.")
	m.SequenceErrs = counter(reg, "iec104_shield_sequence_errors_total",
		"Sequence-number violations that caused a connection to close.")
	m.AuditDropped = counter(reg, "iec104_shield_audit_dropped_total",
		"Audit records dropped because the audit queue was full.")
	return m
}

// Handler serves /metrics, /healthz and /readyz.
func (m *Metrics) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ready\n")
	})
	return mux
}

// Listen binds the metrics listener synchronously.
func Listen(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("observ: metrics listener %q: %w", addr, err)
	}
	return ln, nil
}

// Serve runs the metrics listener until ctx is cancelled.
func Serve(ctx context.Context, ln net.Listener, h http.Handler, log *zap.Logger) error {
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (m *Metrics) IncConnAccepted() {
	if m != nil {
		m.ConnAccepted.Inc()
		m.Active.Inc()
	}
}

func (m *Metrics) IncConnRejected() {
	if m != nil {
		m.ConnRejected.Inc()
	}
}

func (m *Metrics) DecActive() {
	if m != nil {
		m.Active.Dec()
	}
}

func (m *Metrics) IncFrame(device, direction, kind string) {
	if m != nil {
		m.Frames.WithLabelValues(device, direction, kind).Inc()
	}
}

func (m *Metrics) IncForwarded(device, direction string) {
	if m != nil {
		m.Forwarded.WithLabelValues(device, direction).Inc()
	}
}

func (m *Metrics) IncDenied(device, reason string) {
	if m != nil {
		m.Denied.WithLabelValues(device, reason).Inc()
	}
}

func (m *Metrics) IncParseError() {
	if m != nil {
		m.ParseErrors.Inc()
	}
}

func (m *Metrics) IncUpstreamError() {
	if m != nil {
		m.UpstreamErrs.Inc()
	}
}

func (m *Metrics) IncSequenceError() {
	if m != nil {
		m.SequenceErrs.Inc()
	}
}

func counter(reg *prometheus.Registry, name, help string) prometheus.Counter {
	c := prometheus.NewCounter(prometheus.CounterOpts{Name: name, Help: help})
	reg.MustRegister(c)
	return c
}

func gauge(reg *prometheus.Registry, name, help string) prometheus.Gauge {
	g := prometheus.NewGauge(prometheus.GaugeOpts{Name: name, Help: help})
	reg.MustRegister(g)
	return g
}
