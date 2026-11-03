// Package proxy implements the IEC 60870-5-104 security gateway.
//
// One Gateway owns one client-visible listener and one outstation address.
// Each accepted master connection gets its own upstream connection and its own
// two IEC-104 sequence spaces. The proxy is therefore a terminating proxy, not
// a byte relay: it acknowledges I-frames on each leg independently, forwards
// allowed ASDUs with fresh sequence numbers, and answers a denied command with
// a negative activation confirmation instead of forwarding it.
//
// This is the only correct shape for command policy. Silently dropping an
// I-frame would desynchronise the master's and outstation's sequence numbers;
// forwarding it and relying on the outstation to reject it would execute the
// command.
package proxy

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/GalaxyGorilla/iec104-shield/internal/config"
	"github.com/GalaxyGorilla/iec104-shield/internal/iec104"
	"github.com/GalaxyGorilla/iec104-shield/internal/observ"
	"github.com/GalaxyGorilla/iec104-shield/internal/policy"
)

// Config is the listener identity of one gateway. Everything that a SIGHUP
// can change lives in gatewayRuntime instead.
type Config struct {
	Name       string
	ListenAddr string
	DeviceAddr string
}

// gatewayRuntime is the set of config-derived knobs a reload can swap without
// rebinding the listener or dropping a session. The whole struct is replaced
// under rtMu, so a frame sees ONE consistent configuration rather than a
// half-applied mix (for example a new policy with the old allow-list).
//
// ListenAddr and DeviceAddr are deliberately absent: they are bound to the
// listener and the upstream dial, so a change requires a restart and is
// reported by Runner.Reload instead of being silently ignored.
type gatewayRuntime struct {
	policy            *policy.Policy
	allow             *policy.List
	allowUnknownTypes bool
	maxClients        int
	dialTimeout       time.Duration
	idleTimeout       time.Duration
	t1                time.Duration
	k                 int
	lim               *rateLimiter
	pace              time.Duration
}

func newGatewayRuntime(dev config.Device) (gatewayRuntime, error) {
	pol, err := dev.CompilePolicy()
	if err != nil {
		return gatewayRuntime{}, err
	}
	allow, err := dev.CompileAllow()
	if err != nil {
		return gatewayRuntime{}, err
	}
	return gatewayRuntime{
		policy:            pol,
		allow:             allow,
		allowUnknownTypes: dev.AllowUnknownTypes,
		maxClients:        dev.MaxClients,
		dialTimeout:       time.Duration(dev.DialTimeoutMs) * time.Millisecond,
		idleTimeout:       time.Duration(dev.IdleTimeoutMs) * time.Millisecond,
		t1:                time.Duration(dev.T1Ms) * time.Millisecond,
		k:                 dev.K,
		lim:               newRateLimiter(dev.RatePerSec),
		pace:              time.Duration(dev.MinIntervalMs) * time.Millisecond,
	}, nil
}

// Metrics is the observability hook. A nil implementation is normalized to a
// no-op; every method is nil-safe.
type Metrics interface {
	IncConnAccepted()
	IncConnRejected()
	DecActive()
	IncFrame(device, direction, kind string)
	IncForwarded(device, direction string)
	IncDenied(device, reason string)
	IncParseError()
	IncUpstreamError()
	IncSequenceError()
}

type nopMetrics struct{}

func (nopMetrics) IncConnAccepted()                {}
func (nopMetrics) IncConnRejected()                {}
func (nopMetrics) DecActive()                      {}
func (nopMetrics) IncFrame(string, string, string) {}
func (nopMetrics) IncForwarded(string, string)     {}
func (nopMetrics) IncDenied(string, string)        {}
func (nopMetrics) IncParseError()                  {}
func (nopMetrics) IncUpstreamError()               {}
func (nopMetrics) IncSequenceError()               {}

func metricsOrNop(m Metrics) Metrics {
	if m == nil {
		return nopMetrics{}
	}
	return m
}

// Gateway is one listener<->outstation pair.
type Gateway struct {
	cfg Config
	log *zap.SugaredLogger
	met Metrics

	audit *observ.Audit

	// rt is swapped whole by a reload. Readers take a copy under RLock and
	// never hold the lock across I/O.
	rtMu sync.RWMutex
	rt   gatewayRuntime

	clients atomic.Int64

	// paceMu and lastForward enforce the shared minimum gap between
	// forwarded master I-frames. The gap is per gateway (per RTU), not per
	// master: the RTU sees every session on its own upstream connection.
	paceMu      sync.Mutex
	lastForward time.Time

	connsMu sync.Mutex
	conns   map[net.Conn]struct{}
	wg      sync.WaitGroup
}

// New builds a gateway from a validated device config.
func New(dev config.Device, log *zap.SugaredLogger, met Metrics, audit *observ.Audit) (*Gateway, error) {
	rt, err := newGatewayRuntime(dev)
	if err != nil {
		return nil, err
	}
	if log == nil {
		log = zap.NewNop().Sugar()
	}
	return &Gateway{
		cfg: Config{
			Name:       dev.Name,
			ListenAddr: dev.ListenAddr,
			DeviceAddr: dev.DeviceAddr,
		},
		log:   log,
		met:   metricsOrNop(met),
		audit: audit,
		rt:    rt,
		conns: make(map[net.Conn]struct{}),
	}, nil
}

// runtime returns one consistent snapshot. The value is copied, so callers
// never hold rtMu across a blocking read or write.
func (g *Gateway) runtime() gatewayRuntime {
	g.rtMu.RLock()
	defer g.rtMu.RUnlock()
	return g.rt
}

// setRuntime swaps the reloadable configuration atomically.
func (g *Gateway) setRuntime(rt gatewayRuntime) {
	g.rtMu.Lock()
	defer g.rtMu.Unlock()
	g.rt = rt
}

// pace blocks until the shared minimum gap since the last forwarded master
// I-frame has elapsed. Holding paceMu across the wait is deliberate: it is
// the serialization point the RTU sees, and it keeps two masters from both
// deciding the gap is free and forwarding together. The wait is bounded by
// the session's done channel, so a closing session cannot stall shutdown.
func (g *Gateway) pace(rt gatewayRuntime, done <-chan struct{}) error {
	g.paceMu.Lock()
	defer g.paceMu.Unlock()
	now := time.Now()
	if rt.pace <= 0 {
		g.lastForward = now
		return nil
	}
	if !g.lastForward.IsZero() {
		if wait := rt.pace - now.Sub(g.lastForward); wait > 0 {
			timer := time.NewTimer(wait)
			defer timer.Stop()
			select {
			case <-timer.C:
				now = time.Now()
			case <-done:
				return errSessionClosed
			}
		}
	}
	g.lastForward = now
	return nil
}

// Name returns the configured device name.
func (g *Gateway) Name() string { return g.cfg.Name }

// Serve accepts master connections until ln is closed.
func (g *Gateway) Serve(ln net.Listener) error {
	rt := g.runtime()
	g.log.Infof("iec104 gateway %s: listening on %s -> %s (max_clients=%d read_only=%v)",
		g.cfg.Name, ln.Addr(), g.cfg.DeviceAddr, rt.maxClients, rt.policy.ReadOnly())
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if !g.admit(conn) {
			g.met.IncConnRejected()
			_ = conn.Close()
			continue
		}
		enableKeepAlive(conn)
		g.met.IncConnAccepted()
		g.track(conn, true)
		g.wg.Add(1)
		go func() {
			defer g.wg.Done()
			defer g.met.DecActive()
			defer g.clients.Add(-1)
			defer g.track(conn, false)
			defer conn.Close()
			g.handle(conn)
		}()
	}
}

func (g *Gateway) admit(conn net.Conn) bool {
	rt := g.runtime()
	if n := g.clients.Add(1); n > int64(rt.maxClients) {
		g.clients.Add(-1)
		g.log.Warnf("iec104 gateway %s: rejecting %s: connection limit (%d) reached",
			g.cfg.Name, conn.RemoteAddr(), rt.maxClients)
		g.record(observ.AuditEvent{Event: "connection_rejected", Device: g.cfg.Name,
			Client: conn.RemoteAddr().String(), Reason: "connection_limit"})
		return false
	}
	if rt.allow != nil {
		ip := remoteIP(conn)
		if ip == nil || !rt.allow.Allowed(ip) {
			g.clients.Add(-1)
			g.log.Warnf("iec104 gateway %s: rejecting %s: not in allow-list",
				g.cfg.Name, conn.RemoteAddr())
			g.record(observ.AuditEvent{Event: "connection_rejected", Device: g.cfg.Name,
				Client: conn.RemoteAddr().String(), Reason: "allow_list"})
			return false
		}
	}
	return true
}

func (g *Gateway) handle(client net.Conn) {
	clientName := client.RemoteAddr().String()
	g.record(observ.AuditEvent{Event: "connection", Device: g.cfg.Name, Client: clientName, Reason: "accepted"})

	rt := g.runtime()
	device, err := net.DialTimeout("tcp", g.cfg.DeviceAddr, rt.dialTimeout)
	if err != nil {
		g.met.IncUpstreamError()
		g.log.Warnf("iec104 gateway %s: upstream %s: %v", g.cfg.Name, g.cfg.DeviceAddr, err)
		g.record(observ.AuditEvent{Event: "upstream_error", Device: g.cfg.Name,
			Client: clientName, Reason: err.Error()})
		return // fail closed: the master sees a closed connection
	}
	defer device.Close()
	enableKeepAlive(device)

	s := newSession(g, client, device)
	s.run()
	g.record(observ.AuditEvent{Event: "connection_closed", Device: g.cfg.Name, Client: clientName})
}

func (g *Gateway) track(conn net.Conn, add bool) {
	g.connsMu.Lock()
	defer g.connsMu.Unlock()
	if add {
		g.conns[conn] = struct{}{}
	} else {
		delete(g.conns, conn)
	}
}

// Close stops accepting and closes every live client connection. The upstream
// side follows because each session closes both legs.
func (g *Gateway) Close() {
	g.connsMu.Lock()
	conns := make([]net.Conn, 0, len(g.conns))
	for c := range g.conns {
		conns = append(conns, c)
	}
	g.connsMu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

// Wait waits for all client handlers to finish.
func (g *Gateway) Wait() { g.wg.Wait() }

func (g *Gateway) record(ev observ.AuditEvent) {
	if g.audit != nil {
		g.audit.Record(ev)
	}
}

func enableKeepAlive(conn net.Conn) {
	if t, ok := conn.(*net.TCPConn); ok {
		_ = t.SetKeepAlive(true)
		_ = t.SetKeepAlivePeriod(30 * time.Second)
	}
}

func remoteIP(conn net.Conn) net.IP {
	if a, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return a.IP
	}
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

// session is one master<->outstation pair with independent sequence spaces.
type session struct {
	gw     *Gateway
	client string
	master *link
	device *link
	done   chan struct{}
	once   sync.Once
	wg     sync.WaitGroup
}

func newSession(g *Gateway, client, device net.Conn) *session {
	rt := g.runtime()
	s := &session{gw: g, client: client.RemoteAddr().String(), done: make(chan struct{})}
	s.master = newLink("master", client, rt.k, rt.t1, rt.idleTimeout, s.done)
	s.device = newLink("device", device, rt.k, rt.t1, 0, s.done)
	return s
}

func (s *session) run() {
	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		s.logPumpError("master->device", s.pump(s.master, s.device, true))
		s.close()
	}()
	go func() {
		defer s.wg.Done()
		s.logPumpError("device->master", s.pump(s.device, s.master, false))
		s.close()
	}()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.watchT1()
	}()
	s.wg.Wait()
}

func (s *session) close() {
	s.once.Do(func() {
		close(s.done)
		_ = s.master.conn.Close()
		_ = s.device.conn.Close()
	})
}

func (s *session) logPumpError(direction string, err error) {
	if err == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, errSessionClosed) {
		return
	}
	s.gw.log.Debugf("iec104 gateway %s: %s: %v", s.gw.cfg.Name, direction, err)
}

func (s *session) watchT1() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case now := <-ticker.C:
			if s.master.expired(now) || s.device.expired(now) {
				s.gw.met.IncSequenceError()
				s.gw.log.Warnf("iec104 gateway %s: t1 expired waiting for an acknowledgement", s.gw.cfg.Name)
				s.close()
				return
			}
		}
	}
}

func (s *session) pump(src, dst *link, fromMaster bool) error {
	dir := "device"
	if fromMaster {
		dir = "master"
	}
	for {
		f, err := src.readFrame()
		if err != nil {
			return err
		}
		s.gw.met.IncFrame(s.gw.cfg.Name, dir, f.Type.String())
		switch f.Type {
		case iec104.IFrame:
			ack, err := src.recvI(f.SendSeq)
			if err != nil {
				s.gw.met.IncSequenceError()
				s.gw.record(observ.AuditEvent{Event: "protocol_error", Device: s.gw.cfg.Name,
					Direction: dir, Reason: err.Error()})
				return err
			}
			if err := src.observeAck(f.RecvSeq); err != nil {
				s.gw.met.IncSequenceError()
				return err
			}
			if fromMaster {
				a, err := iec104.ParseASDU(f.ASDU)
				if err != nil {
					s.gw.met.IncParseError()
					s.gw.record(observ.AuditEvent{Event: "protocol_error", Device: s.gw.cfg.Name,
						Direction: dir, Reason: err.Error()})
					return err
				}
				// Read the snapshot AFTER the blocking frame read. Reading
				// it before would delay a reload by one frame for a busy
				// master and indefinitely for an idle one, so a revoked
				// command could still execute after SIGHUP.
				rt := s.gw.runtime()
				denied := !rt.policy.Allowed(a)
				reason := "command_policy"
				if rt.policy.ReadOnly() {
					reason = "read_only"
				}
				if a.Partial && iec104.IsWrite(a.TypeID) {
					// A write type whose information objects could not be
					// parsed cannot be authorized by IOA. File transfer
					// types 125/127 are the standard example.
					denied = true
					reason = "unsupported_write_type"
				} else if a.Partial && !rt.allowUnknownTypes {
					denied = true
					reason = "unknown_type"
				}
				if a.Count == 0 {
					denied = true
					reason = "malformed_asdu"
				}
				if denied {
					neg := iec104.NegativeConfirmation(a)
					if neg == nil {
						return fmt.Errorf("iec104: cannot build negative confirmation")
					}
					if err := src.sendI(neg); err != nil {
						return err
					}
					s.gw.met.IncDenied(s.gw.cfg.Name, reason)
					s.gw.recordDenied(s.client, a, reason)
					if err := src.sendS(ack); err != nil {
						return err
					}
					continue
				}
				// Rate limiting runs after policy: a denied command never
				// consumes a token, and a rate-limited request is answered
				// with a negative confirmation instead of being dropped
				// (dropping an I-frame would desynchronise the master).
				if !rt.lim.allow() {
					neg := iec104.NegativeConfirmation(a)
					if neg == nil {
						return fmt.Errorf("iec104: cannot build negative confirmation")
					}
					if err := src.sendI(neg); err != nil {
						return err
					}
					s.gw.met.IncDenied(s.gw.cfg.Name, "rate_limit")
					s.gw.recordDenied(s.client, a, "rate_limit")
					if err := src.sendS(ack); err != nil {
						return err
					}
					continue
				}
				if err := s.gw.pace(rt, s.done); err != nil {
					return err
				}
				s.gw.log.Debugf("iec104 gateway %s: forward master->device %s", s.gw.cfg.Name, a.Describe())
				if err := dst.sendI(f.ASDU); err != nil {
					return err
				}
				if iec104.IsWrite(a.TypeID) {
					s.gw.recordCommand(s.client, "command_allowed", a, "policy")
				}
				s.gw.met.IncForwarded(s.gw.cfg.Name, "master_to_device")
			} else {
				if a, err := iec104.ParseASDU(f.ASDU); err == nil {
					s.gw.log.Debugf("iec104 gateway %s: forward device->master %s", s.gw.cfg.Name, a.Describe())
				} else {
					s.gw.log.Debugf("iec104 gateway %s: forward device->master raw=%x", s.gw.cfg.Name, f.ASDU)
				}
				if err := dst.sendI(f.ASDU); err != nil {
					return err
				}
				s.gw.met.IncForwarded(s.gw.cfg.Name, "device_to_master")
			}
			if err := src.sendS(ack); err != nil {
				return err
			}
		case iec104.SFrame:
			if err := src.observeAck(f.RecvSeq); err != nil {
				s.gw.met.IncSequenceError()
				return err
			}
		case iec104.UFrame:
			switch f.U {
			case iec104.UTestFRActive, iec104.UTestFRConfirm,
				iec104.UStartDTActive, iec104.UStartDTConfirm,
				iec104.UStopDTActive, iec104.UStopDTConfirm:
				// Keepalive and data-transfer control frames are relayed
				// end to end. Answering TESTFR locally would let the master
				// believe the outstation is alive while the upstream leg is
				// dead, which is exactly the failure this proxy must expose.
				if err := dst.sendU(f.U); err != nil {
					return err
				}
			default:
				return fmt.Errorf("iec104: unsupported U function %s", f.U)
			}
		}
	}
}

func (g *Gateway) recordDenied(client string, a iec104.ASDU, reason string) {
	event := "asdu_denied"
	if iec104.IsWrite(a.TypeID) {
		event = "command_denied"
	}
	g.recordCommand(client, event, a, reason)
}

// recordCommand records one command decision. Allowed and denied control
// commands are both recorded: a utility audit trail needs to show what was
// permitted, not only what was refused. Monitoring data is not audited (it
// would be too high volume); it is counted by metrics.
func (g *Gateway) recordCommand(client, event string, a iec104.ASDU, reason string) {
	var sel *bool
	if iec104.IsProcessCommand(a.TypeID) {
		v := iec104.Select(a)
		sel = &v
	}
	g.record(observ.AuditEvent{
		Event:         event,
		Device:        g.cfg.Name,
		Client:        client,
		Direction:     "master",
		TypeID:        a.TypeID,
		TypeName:      iec104.TypeName(a.TypeID),
		Cause:         a.Cause,
		CommonAddress: a.CommonAddr,
		IOA:           ioaString(a),
		Select:        sel,
		Reason:        reason,
	})
}

func ioaString(a iec104.ASDU) string {
	if len(a.Objects) == 0 {
		return ""
	}
	if len(a.Objects) == 1 {
		return fmt.Sprintf("%d", a.Objects[0].IOA)
	}
	return fmt.Sprintf("%d..%d", a.Objects[0].IOA, a.Objects[len(a.Objects)-1].IOA)
}

var errSessionClosed = errors.New("iec104: session closed")

// link is one TCP leg with its own send/receive sequence numbers.
type link struct {
	name string
	conn net.Conn
	br   *bufio.Reader
	bw   *bufio.Writer

	mu       sync.Mutex
	sendSeq  uint16
	recvSeq  uint16
	peerAck  uint16
	lastSend time.Time

	// sendMu serialises I-frame sequence allocation AND the write, so two
	// goroutines cannot reserve N(S)=0 and N(S)=1 and then write them in
	// reverse order. S/U frames may interleave; they carry no send
	// sequence number.
	sendMu  sync.Mutex
	writeMu sync.Mutex

	// sendHook is a test seam. It is nil in production. Tests use it to
	// force the interleaving that sendMu prevents: two goroutines reserve
	// N(S) and then race to write.
	sendHook func()
	ackCh    chan struct{}
	done     <-chan struct{}
	k        int
	t1       time.Duration
	idle     time.Duration
}

func newLink(name string, conn net.Conn, k int, t1, idle time.Duration, done <-chan struct{}) *link {
	return &link{
		name: name, conn: conn,
		br:    bufio.NewReaderSize(conn, 4096),
		bw:    bufio.NewWriterSize(conn, 4096),
		ackCh: make(chan struct{}, 1),
		done:  done, k: k, t1: t1, idle: idle,
	}
}

func (l *link) readFrame() (iec104.Frame, error) {
	if l.idle > 0 {
		_ = l.conn.SetReadDeadline(time.Now().Add(l.idle))
	}
	return iec104.ReadFrame(l.br)
}

func (l *link) recvI(seq uint16) (uint16, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if seq != l.recvSeq {
		return 0, fmt.Errorf("iec104: %s sequence gap: got %d want %d", l.name, seq, l.recvSeq)
	}
	l.recvSeq = (l.recvSeq + 1) & iec104.MaxSequence
	return l.recvSeq, nil
}

func (l *link) observeAck(nr uint16) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	delta := (nr - l.peerAck) & iec104.MaxSequence
	if delta == 0 {
		return nil // duplicate acknowledgement
	}
	outstanding := (l.sendSeq - l.peerAck) & iec104.MaxSequence
	if delta > outstanding {
		return fmt.Errorf("iec104: %s acknowledgement %d beyond send sequence %d", l.name, nr, l.sendSeq)
	}
	l.peerAck = nr
	if l.peerAck == l.sendSeq {
		l.lastSend = time.Time{}
	}
	select {
	case l.ackCh <- struct{}{}:
	default:
	}
	return nil
}

func (l *link) expired(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.t1 <= 0 || l.lastSend.IsZero() {
		return false
	}
	return now.Sub(l.lastSend) > l.t1
}

func (l *link) waitSendSlot() error {
	for {
		l.mu.Lock()
		unacked := (l.sendSeq - l.peerAck) & iec104.MaxSequence
		if unacked < uint16(l.k) {
			l.mu.Unlock()
			return nil
		}
		l.mu.Unlock()
		select {
		case <-l.ackCh:
		case <-l.done:
			return errSessionClosed
		}
	}
}

func (l *link) reserveSend() (seq, ack uint16, err error) {
	if err := l.waitSendSlot(); err != nil {
		return 0, 0, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if (l.sendSeq-l.peerAck)&iec104.MaxSequence == 0 {
		l.lastSend = time.Now()
	}
	seq = l.sendSeq
	l.sendSeq = (l.sendSeq + 1) & iec104.MaxSequence
	ack = l.recvSeq
	return seq, ack, nil
}

func (l *link) sendI(asdu []byte) error {
	l.sendMu.Lock()
	defer l.sendMu.Unlock()
	seq, ack, err := l.reserveSend()
	if err != nil {
		return err
	}
	if l.sendHook != nil {
		l.sendHook()
	}
	raw, err := iec104.NewI(seq, ack, asdu)
	if err != nil {
		return err
	}
	return l.write(raw)
}

func (l *link) sendS(ack uint16) error { return l.write(iec104.NewS(ack)) }

func (l *link) sendU(fn iec104.UFunction) error { return l.write(iec104.NewU(fn)) }

func (l *link) write(raw []byte) error {
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	_ = l.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := l.bw.Write(raw); err != nil {
		return err
	}
	return l.bw.Flush()
}
