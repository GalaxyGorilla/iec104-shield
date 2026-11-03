package proxy

import (
	"fmt"
	"net"
	"sync"

	"go.uber.org/zap"

	"github.com/GalaxyGorilla/iec104-shield/internal/config"
	"github.com/GalaxyGorilla/iec104-shield/internal/observ"
)

// Runner owns all gateways and their listeners.
type Runner struct {
	gws   []*Gateway
	lns   []net.Listener
	log   *zap.SugaredLogger
	wg    sync.WaitGroup
	bound chan struct{}
}

// NewRunner builds one gateway per config device.
func NewRunner(cfg *config.Config, log *zap.SugaredLogger, met Metrics, audit *observ.Audit) (*Runner, error) {
	if log == nil {
		log = zap.NewNop().Sugar()
	}
	r := &Runner{bound: make(chan struct{}), log: log}
	for i := range cfg.Devices {
		gw, err := New(cfg.Devices[i], log, met, audit)
		if err != nil {
			return nil, fmt.Errorf("device %s: %w", cfg.Devices[i].Name, err)
		}
		r.gws = append(r.gws, gw)
	}
	return r, nil
}

// Ready closes after every listener has bound.
func (r *Runner) Ready() <-chan struct{} { return r.bound }

// Run binds every listener and serves until Stop or a fatal accept error.
func (r *Runner) Run() error {
	for _, gw := range r.gws {
		ln, err := net.Listen("tcp", gw.cfg.ListenAddr)
		if err != nil {
			r.closeListeners()
			return fmt.Errorf("bind %s (device %s): %w", gw.cfg.ListenAddr, gw.cfg.Name, err)
		}
		r.lns = append(r.lns, ln)
	}
	close(r.bound)
	errCh := make(chan error, len(r.lns))
	for i, ln := range r.lns {
		ln, gw := ln, r.gws[i]
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			errCh <- gw.Serve(ln)
		}()
	}
	return <-errCh
}

// Stop closes listeners and every live client connection, then waits for the
// handlers. Upstream connections follow their sessions.
func (r *Runner) Stop() {
	r.closeListeners()
	for _, gw := range r.gws {
		gw.Close()
	}
	r.wg.Wait()
	for _, gw := range r.gws {
		gw.Wait()
	}
}

func (r *Runner) closeListeners() {
	for _, ln := range r.lns {
		_ = ln.Close()
	}
}
