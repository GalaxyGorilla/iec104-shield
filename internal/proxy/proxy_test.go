package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/GalaxyGorilla/iec104-shield/internal/config"
	"github.com/GalaxyGorilla/iec104-shield/internal/iec104"
	"github.com/GalaxyGorilla/iec104-shield/internal/observ"
)

func testDevice(deviceAddr string) config.Device {
	return config.Device{
		Name:          "test",
		ListenAddr:    "127.0.0.1:0",
		DeviceAddr:    deviceAddr,
		MaxClients:    4,
		DialTimeoutMs: 1000,
		T1Ms:          5000,
		K:             12,
	}
}

func startGateway(t *testing.T, dev config.Device) (string, func()) {
	t.Helper()
	return startGatewayWith(t, dev, nil, nil)
}

func startGatewayWith(t *testing.T, dev config.Device, met Metrics, audit *observ.Audit) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gw, err := New(dev, zap.NewNop().Sugar(), met, audit)
	if err != nil {
		ln.Close()
		t.Fatal(err)
	}
	go func() { _ = gw.Serve(ln) }()
	stop := func() {
		_ = ln.Close()
		gw.Close()
		gw.Wait()
	}
	return ln.Addr().String(), stop
}

type testPeer struct {
	conn    net.Conn
	br      *bufio.Reader
	bw      *bufio.Writer
	sendSeq uint16
	recvSeq uint16
	mu      sync.Mutex
	sendMu  sync.Mutex
}

func newTestPeer(conn net.Conn) *testPeer {
	return &testPeer{
		conn: conn,
		br:   bufio.NewReader(conn),
		bw:   bufio.NewWriter(conn),
	}
}

func (p *testPeer) close() { _ = p.conn.Close() }

func (p *testPeer) write(raw []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	_ = p.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := p.bw.Write(raw); err != nil {
		return err
	}
	return p.bw.Flush()
}

func (p *testPeer) sendI(asdu []byte) error {
	// Serialise sequence allocation and the write, exactly as the proxy
	// does, so a spontaneous sender and a response cannot write N(S) out
	// of order.
	p.sendMu.Lock()
	defer p.sendMu.Unlock()
	p.mu.Lock()
	seq, ack := p.sendSeq, p.recvSeq
	p.sendSeq = (p.sendSeq + 1) & iec104.MaxSequence
	p.mu.Unlock()
	raw, err := iec104.NewI(seq, ack, asdu)
	if err != nil {
		return err
	}
	return p.write(raw)
}

func (p *testPeer) sendS(ack uint16) error { return p.write(iec104.NewS(ack)) }
func (p *testPeer) sendU(fn iec104.UFunction) error {
	return p.write(iec104.NewU(fn))
}

func (p *testPeer) read() (iec104.Frame, error) {
	_ = p.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	f, err := iec104.ReadFrame(p.br)
	if err != nil {
		return iec104.Frame{}, err
	}
	if f.Type == iec104.IFrame {
		p.mu.Lock()
		if f.SendSeq != p.recvSeq {
			want := p.recvSeq
			p.mu.Unlock()
			return iec104.Frame{}, fmt.Errorf("peer sequence gap: got %d want %d", f.SendSeq, want)
		}
		p.recvSeq = (p.recvSeq + 1) & iec104.MaxSequence
		ack := p.recvSeq
		p.mu.Unlock()
		_ = p.sendS(ack)
	}
	return f, nil
}

func (p *testPeer) readI() (iec104.ASDU, error) {
	for {
		f, err := p.read()
		if err != nil {
			return iec104.ASDU{}, err
		}
		if f.Type == iec104.IFrame {
			return iec104.ParseASDU(f.ASDU)
		}
	}
}

func (p *testPeer) readU(want iec104.UFunction) error {
	for {
		f, err := p.read()
		if err != nil {
			return err
		}
		if f.Type == iec104.UFrame && f.U == want {
			return nil
		}
	}
}

type fakeOutstation struct {
	ln    net.Listener
	mu    sync.Mutex
	conns map[net.Conn]struct{}
	got   []iec104.ASDU
	gotAt []time.Time
	uGot  []iec104.UFunction
}

func startFake(t *testing.T, handler func(*testPeer, iec104.ASDU)) *fakeOutstation {
	t.Helper()
	return startFakeWithConnect(t, handler, nil)
}

func startFakeWithConnect(t *testing.T, handler func(*testPeer, iec104.ASDU), onConnect func(*testPeer)) *fakeOutstation {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeOutstation{ln: ln, conns: make(map[net.Conn]struct{})}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.conns[conn] = struct{}{}
			f.mu.Unlock()
			go func() {
				p := newTestPeer(conn)
				if onConnect != nil {
					go onConnect(p)
				}
				defer p.close()
				defer func() {
					f.mu.Lock()
					delete(f.conns, conn)
					f.mu.Unlock()
				}()
				for {
					fr, err := p.read()
					if err != nil {
						return
					}
					switch fr.Type {
					case iec104.UFrame:
						f.mu.Lock()
						f.uGot = append(f.uGot, fr.U)
						f.mu.Unlock()
						switch fr.U {
						case iec104.UStartDTActive:
							_ = p.sendU(iec104.UStartDTConfirm)
						case iec104.UTestFRActive:
							_ = p.sendU(iec104.UTestFRConfirm)
						}
					case iec104.IFrame:
						a, err := iec104.ParseASDU(fr.ASDU)
						if err != nil {
							return
						}
						f.mu.Lock()
						f.got = append(f.got, a)
						f.gotAt = append(f.gotAt, time.Now())
						f.mu.Unlock()
						if handler != nil {
							handler(p, a)
						}
					}
				}
			}()
		}
	}()
	return f
}

func (f *fakeOutstation) addr() string { return f.ln.Addr().String() }
func (f *fakeOutstation) close() {
	_ = f.ln.Close()
	f.mu.Lock()
	conns := make([]net.Conn, 0, len(f.conns))
	for c := range f.conns {
		conns = append(conns, c)
	}
	f.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func (f *fakeOutstation) received() []iec104.ASDU {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]iec104.ASDU(nil), f.got...)
}

func (f *fakeOutstation) receivedAt() []time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Time(nil), f.gotAt...)
}

func (f *fakeOutstation) uFrames() []iec104.UFunction {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]iec104.UFunction(nil), f.uGot...)
}

func dialMaster(t *testing.T, addr string) *testPeer {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	p := newTestPeer(conn)
	if err := p.sendU(iec104.UStartDTActive); err != nil {
		t.Fatal(err)
	}
	if err := p.readU(iec104.UStartDTConfirm); err != nil {
		t.Fatal(err)
	}
	return p
}

func interrogation(ca uint16) []byte {
	return []byte{100, 0x01, 0x06, 0x00, byte(ca), byte(ca >> 8), 0x14}
}

func singlePoint(ca uint16, ioa uint32, on bool) []byte {
	value := byte(0x00)
	if on {
		value = 0x01
	}
	return []byte{1, 0x01, 0x03, 0x00, byte(ca), byte(ca >> 8),
		byte(ioa), byte(ioa >> 8), byte(ioa >> 16), value}
}

func singleCommand(ca uint16, ioa uint32, selectBit, on bool) []byte {
	info := byte(0x00)
	if on {
		info |= 0x01
	}
	if selectBit {
		info |= 0x80
	}
	return []byte{45, 0x01, 0x06, 0x00, byte(ca), byte(ca >> 8),
		byte(ioa), byte(ioa >> 8), byte(ioa >> 16), info}
}

func withCOT(asdu []byte, cot uint8) []byte {
	out := append([]byte(nil), asdu...)
	out[2] = cot
	return out
}

func replyCommand(p *testPeer, a iec104.ASDU) {
	_ = p.sendI(withCOT(a.Raw, 7))
}

func TestReadOnlyDeniesCommand(t *testing.T) {
	fake := startFake(t, replyCommand)
	defer fake.close()
	dev := testDevice(fake.addr())
	dev.ReadOnly = true
	addr, stop := startGateway(t, dev)
	defer stop()

	m := dialMaster(t, addr)
	defer m.close()

	if err := m.sendI(singleCommand(1, 1000, false, true)); err != nil {
		t.Fatal(err)
	}
	neg, err := m.readI()
	if err != nil {
		t.Fatal(err)
	}
	if neg.TypeID != 45 || neg.Cause != 7 || !neg.PN {
		t.Fatalf("denial = %+v", neg)
	}
	if len(fake.received()) != 0 {
		t.Fatalf("denied command reached the outstation: %+v", fake.received())
	}

	if err := m.sendI(interrogation(1)); err != nil {
		t.Fatal(err)
	}
	got, err := m.readI()
	if err != nil {
		t.Fatal(err)
	}
	if got.TypeID != 100 {
		t.Fatalf("interrogation response = %+v", got)
	}
	if len(fake.received()) != 1 {
		t.Fatalf("interrogation did not reach the outstation: %+v", fake.received())
	}
}

func TestAllowedCommandForwarded(t *testing.T) {
	fake := startFake(t, replyCommand)
	defer fake.close()
	dev := testDevice(fake.addr())
	ca := uint16(1)
	from, to := uint32(1000), uint32(2000)
	dev.CommandPolicy = &config.CommandPolicy{
		Default: "deny",
		Rules: []config.CommandRule{{
			Types:         config.IntList{45},
			CommonAddress: &config.CommonAddress{Value: ca},
			IOA:           &config.IOARange{From: from, To: to},
			Select:        "execute",
			Action:        "allow",
		}},
	}
	addr, stop := startGateway(t, dev)
	defer stop()

	m := dialMaster(t, addr)
	defer m.close()

	if err := m.sendI(singleCommand(1, 1500, false, true)); err != nil {
		t.Fatal(err)
	}
	con, err := m.readI()
	if err != nil {
		t.Fatal(err)
	}
	if con.TypeID != 45 || con.Cause != 7 || con.PN {
		t.Fatalf("confirmation = %+v", con)
	}
	if len(fake.received()) != 1 || fake.received()[0].Objects[0].IOA != 1500 {
		t.Fatalf("allowed command not forwarded: %+v", fake.received())
	}

	if err := m.sendI(singleCommand(1, 2500, false, true)); err != nil {
		t.Fatal(err)
	}
	neg, err := m.readI()
	if err != nil {
		t.Fatal(err)
	}
	if !neg.PN || neg.Cause != 7 {
		t.Fatalf("out-of-range command = %+v", neg)
	}
	if len(fake.received()) != 1 {
		t.Fatalf("out-of-range command reached the outstation: %+v", fake.received())
	}
}

func TestUnknownMasterTypeDeniedByDefault(t *testing.T) {
	fake := startFake(t, nil)
	defer fake.close()
	addr, stop := startGateway(t, testDevice(fake.addr()))
	defer stop()

	m := dialMaster(t, addr)
	defer m.close()
	// Private type 200 with an unclassifiable payload.
	unknown := []byte{200, 0x01, 0x06, 0x00, 0x01, 0x00, 0xde, 0xad}
	if err := m.sendI(unknown); err != nil {
		t.Fatal(err)
	}
	neg, err := m.readI()
	if err != nil {
		t.Fatal(err)
	}
	if neg.TypeID != 200 || !neg.PN {
		t.Fatalf("unknown type was not refused: %+v", neg)
	}
	if len(fake.received()) != 0 {
		t.Fatalf("unknown type reached the outstation: %+v", fake.received())
	}
}

func TestUnknownMasterTypeCanBeAllowed(t *testing.T) {
	fake := startFake(t, nil)
	defer fake.close()
	dev := testDevice(fake.addr())
	dev.AllowUnknownTypes = true
	addr, stop := startGateway(t, dev)
	defer stop()

	m := dialMaster(t, addr)
	defer m.close()
	unknown := []byte{200, 0x01, 0x06, 0x00, 0x01, 0x00, 0xde, 0xad}
	if err := m.sendI(unknown); err != nil {
		t.Fatal(err)
	}
	// The fake outstation records it; no response is needed for this test.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if len(fake.received()) == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("unknown type was not forwarded: %+v", fake.received())
}

func TestLinkConcurrentSendOrder(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan struct{})
	defer close(done)
	l := newLink("test", client, 12, 5*time.Second, 0, done)

	type got struct {
		seq uint16
		err error
	}
	frames := make(chan got, 2)
	go func() {
		for i := 0; i < 2; i++ {
			f, err := iec104.ReadFrame(server)
			frames <- got{seq: f.SendSeq, err: err}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func(i int) {
			defer wg.Done()
			_ = l.sendI([]byte{100, 0x01, 0x06, 0x00, 0x01, 0x00, byte(i)})
		}(i)
	}
	wg.Wait()
	a, b := <-frames, <-frames
	if a.err != nil || b.err != nil {
		t.Fatalf("read errors: %v %v", a.err, b.err)
	}
	if a.seq != 0 || b.seq != 1 {
		t.Fatalf("send sequence order = %d, %d; want 0, 1", a.seq, b.seq)
	}
}

func TestLinkT1Expiry(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan struct{})
	defer close(done)
	l := newLink("test", client, 12, 100*time.Millisecond, 0, done)
	l.mu.Lock()
	l.sendSeq = 1
	l.peerAck = 0
	l.lastSend = time.Now().Add(-time.Second)
	l.mu.Unlock()
	if !l.expired(time.Now()) {
		t.Fatal("t1 did not expire with one unacknowledged frame")
	}
	l.mu.Lock()
	l.peerAck = 1
	l.lastSend = time.Time{}
	l.mu.Unlock()
	if l.expired(time.Now()) {
		t.Fatal("t1 expired with nothing outstanding")
	}
}

func TestDefaultDeniesWrites(t *testing.T) {
	fake := startFake(t, nil)
	defer fake.close()
	addr, stop := startGateway(t, testDevice(fake.addr()))
	defer stop()

	m := dialMaster(t, addr)
	defer m.close()
	if err := m.sendI(singleCommand(1, 1000, false, true)); err != nil {
		t.Fatal(err)
	}
	neg, err := m.readI()
	if err != nil {
		t.Fatal(err)
	}
	if !neg.PN || neg.TypeID != 45 {
		t.Fatalf("default policy did not deny the command: %+v", neg)
	}
	if len(fake.received()) != 0 {
		t.Fatalf("default policy forwarded the command: %+v", fake.received())
	}
}

func TestManyFrames(t *testing.T) {
	fake := startFake(t, replyCommand)
	defer fake.close()
	dev := testDevice(fake.addr())
	dev.CommandPolicy = &config.CommandPolicy{Default: "allow"}
	addr, stop := startGateway(t, dev)
	defer stop()

	m := dialMaster(t, addr)
	defer m.close()
	for i := 0; i < 40; i++ {
		if err := m.sendI(singleCommand(1, uint32(1000+i), false, true)); err != nil {
			t.Fatal(err)
		}
		con, err := m.readI()
		if err != nil {
			t.Fatal(err)
		}
		if con.TypeID != 45 || con.PN {
			t.Fatalf("round %d: %+v", i, con)
		}
	}
	if got := len(fake.received()); got != 40 {
		t.Fatalf("outstation received %d commands, want 40", got)
	}
}

func TestFailClosedWhenDeviceDown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	_ = ln.Close()
	addr, stop := startGateway(t, testDevice(dead))
	defer stop()

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var b [1]byte
	if _, err := conn.Read(b[:]); err == nil {
		t.Fatal("front connection stayed open after upstream dial failed")
	}
}

func TestAllowList(t *testing.T) {
	fake := startFake(t, nil)
	defer fake.close()
	dev := testDevice(fake.addr())
	dev.Allow = []string{"192.0.2.0/24"}
	addr, stop := startGateway(t, dev)
	defer stop()

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var b [1]byte
	if _, err := conn.Read(b[:]); err == nil {
		t.Fatal("off-list client was not closed")
	}
}

func TestTestFRIsForwarded(t *testing.T) {
	fake := startFake(t, nil)
	defer fake.close()
	addr, stop := startGateway(t, testDevice(fake.addr()))
	defer stop()

	m := dialMaster(t, addr)
	defer m.close()
	if err := m.sendU(iec104.UTestFRActive); err != nil {
		t.Fatal(err)
	}
	if err := m.readU(iec104.UTestFRConfirm); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, u := range fake.uFrames() {
		if u == iec104.UTestFRActive {
			found = true
		}
	}
	if !found {
		t.Fatal("TESTFR was not forwarded end to end")
	}
}

func TestSequenceGapCloses(t *testing.T) {
	fake := startFake(t, nil)
	defer fake.close()
	addr, stop := startGateway(t, testDevice(fake.addr()))
	defer stop()

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	p := newTestPeer(conn)
	// Skip the STARTDT handshake and send I-frame with N(S)=1 while the
	// proxy expects 0.
	raw, _ := iec104.NewI(1, 0, interrogation(1))
	if err := p.write(raw); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var b [1]byte
	if _, err := conn.Read(b[:]); err == nil {
		t.Fatal("sequence gap did not close the connection")
	}
}

func TestSessionCloseUnblocks(t *testing.T) {
	fake := startFake(t, nil)
	defer fake.close()
	addr, stop := startGateway(t, testDevice(fake.addr()))
	defer stop()
	m := dialMaster(t, addr)
	m.close()
	time.Sleep(20 * time.Millisecond)
}

func TestLinkSequenceWrap(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan struct{})
	defer close(done)
	l := newLink("test", client, 12, time.Second, 0, done)

	l.mu.Lock()
	l.recvSeq = iec104.MaxSequence
	l.sendSeq = iec104.MaxSequence
	l.peerAck = iec104.MaxSequence
	l.mu.Unlock()

	ack, err := l.recvI(iec104.MaxSequence)
	if err != nil {
		t.Fatal(err)
	}
	if ack != 0 {
		t.Fatalf("receive sequence wrap = %d, want 0", ack)
	}
	seq, _, err := l.reserveSend()
	if err != nil {
		t.Fatal(err)
	}
	if seq != iec104.MaxSequence {
		t.Fatalf("send sequence before wrap = %d, want %d", seq, iec104.MaxSequence)
	}
	if err := l.observeAck(0); err != nil {
		t.Fatalf("ack after wrap: %v", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.peerAck != 0 || l.sendSeq != 0 {
		t.Fatalf("state after wrap = peerAck=%d sendSeq=%d", l.peerAck, l.sendSeq)
	}
}

func TestLinkWindowBlocksUntilAck(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan struct{})
	defer close(done)
	l := newLink("test", client, 1, time.Second, 0, done)
	l.mu.Lock()
	l.sendSeq = 1
	l.peerAck = 0
	l.mu.Unlock()

	result := make(chan error, 1)
	go func() { result <- l.waitSendSlot() }()
	select {
	case err := <-result:
		t.Fatalf("waitSendSlot returned before ack: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := l.observeAck(1); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("waitSendSlot did not resume after ack")
	}
}

func TestLinkAckValidation(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan struct{})
	defer close(done)
	l := newLink("test", client, 12, time.Second, 0, done)

	l.mu.Lock()
	l.sendSeq = 1
	l.peerAck = 0
	l.mu.Unlock()
	if err := l.observeAck(2); err == nil {
		t.Fatal("ack beyond send sequence accepted")
	}
	if err := l.observeAck(0); err != nil {
		t.Fatalf("duplicate ack rejected: %v", err)
	}
	l.mu.Lock()
	l.sendSeq = 2
	l.peerAck = 1
	l.mu.Unlock()
	if err := l.observeAck(0); err == nil {
		t.Fatal("stale ack accepted")
	}
}

type recordingMetrics struct {
	mu             sync.Mutex
	accepted       int
	rejected       int
	forwarded      int
	denied         int
	frames         int
	parseErrors    int
	upstreamErrors int
	sequenceErrors int
}

func (m *recordingMetrics) IncConnAccepted() { m.mu.Lock(); m.accepted++; m.mu.Unlock() }
func (m *recordingMetrics) IncConnRejected() { m.mu.Lock(); m.rejected++; m.mu.Unlock() }
func (m *recordingMetrics) DecActive()       {}
func (m *recordingMetrics) IncFrame(string, string, string) {
	m.mu.Lock()
	m.frames++
	m.mu.Unlock()
}
func (m *recordingMetrics) IncForwarded(string, string) {
	m.mu.Lock()
	m.forwarded++
	m.mu.Unlock()
}
func (m *recordingMetrics) IncDenied(string, string) {
	m.mu.Lock()
	m.denied++
	m.mu.Unlock()
}
func (m *recordingMetrics) IncParseError()    { m.mu.Lock(); m.parseErrors++; m.mu.Unlock() }
func (m *recordingMetrics) IncUpstreamError() { m.mu.Lock(); m.upstreamErrors++; m.mu.Unlock() }
func (m *recordingMetrics) IncSequenceError() { m.mu.Lock(); m.sequenceErrors++; m.mu.Unlock() }

func TestSBOSelectAllowedExecuteDenied(t *testing.T) {
	fake := startFake(t, replyCommand)
	defer fake.close()
	dev := testDevice(fake.addr())
	ca := uint16(1)
	dev.CommandPolicy = &config.CommandPolicy{
		Default: "deny",
		Rules: []config.CommandRule{{
			Types:         config.IntList{45},
			CommonAddress: &config.CommonAddress{Value: ca},
			Select:        "select",
			Action:        "allow",
		}},
	}
	addr, stop := startGateway(t, dev)
	defer stop()

	m := dialMaster(t, addr)
	defer m.close()
	if err := m.sendI(singleCommand(1, 1000, true, true)); err != nil {
		t.Fatal(err)
	}
	con, err := m.readI()
	if err != nil {
		t.Fatal(err)
	}
	if con.TypeID != 45 || con.PN {
		t.Fatalf("select confirmation = %+v", con)
	}

	if err := m.sendI(singleCommand(1, 1000, false, true)); err != nil {
		t.Fatal(err)
	}
	neg, err := m.readI()
	if err != nil {
		t.Fatal(err)
	}
	if !neg.PN {
		t.Fatalf("execute was not denied: %+v", neg)
	}
	got := fake.received()
	if len(got) != 1 || !iec104.Select(got[0]) {
		t.Fatalf("outstation received = %+v", got)
	}
}

func TestSBOSelectAndExecuteAllowed(t *testing.T) {
	fake := startFake(t, replyCommand)
	defer fake.close()
	dev := testDevice(fake.addr())
	dev.CommandPolicy = &config.CommandPolicy{Default: "allow"}
	addr, stop := startGateway(t, dev)
	defer stop()

	m := dialMaster(t, addr)
	defer m.close()
	for _, sel := range []bool{true, false} {
		if err := m.sendI(singleCommand(1, 1000, sel, true)); err != nil {
			t.Fatal(err)
		}
		con, err := m.readI()
		if err != nil {
			t.Fatal(err)
		}
		if con.PN {
			t.Fatalf("select=%t was denied: %+v", sel, con)
		}
	}
	if got := len(fake.received()); got != 2 {
		t.Fatalf("outstation received %d commands, want 2", got)
	}
}

func TestMultipleMastersSeparateUpstreams(t *testing.T) {
	fake := startFake(t, replyCommand)
	defer fake.close()
	dev := testDevice(fake.addr())
	dev.MaxClients = 2
	addr, stop := startGateway(t, dev)
	defer stop()

	m1 := dialMaster(t, addr)
	defer m1.close()
	m2 := dialMaster(t, addr)
	defer m2.close()

	for _, m := range []*testPeer{m1, m2} {
		if err := m.sendI(interrogation(1)); err != nil {
			t.Fatal(err)
		}
		if _, err := m.readI(); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(fake.received()); got != 2 {
		t.Fatalf("outstation received %d interrogations, want 2", got)
	}
}

func TestMaxClients(t *testing.T) {
	fake := startFake(t, nil)
	defer fake.close()
	dev := testDevice(fake.addr())
	dev.MaxClients = 1
	addr, stop := startGateway(t, dev)
	defer stop()

	m1 := dialMaster(t, addr)
	defer m1.close()

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := conn.Read(b[:]); err == nil {
		t.Fatal("second master was not rejected by the connection cap")
	}
}

func TestSpontaneousDeviceData(t *testing.T) {
	sendNow := make(chan struct{})
	fake := startFakeWithConnect(t, nil, func(p *testPeer) {
		<-sendNow
		_ = p.sendI(singlePoint(1, 100, true))
	})
	defer fake.close()
	addr, stop := startGateway(t, testDevice(fake.addr()))
	defer stop()

	m := dialMaster(t, addr)
	defer m.close()
	close(sendNow)
	got, err := m.readI()
	if err != nil {
		t.Fatal(err)
	}
	if got.TypeID != 1 || len(got.Objects) != 1 || got.Objects[0].IOA != 100 {
		t.Fatalf("spontaneous data = %+v", got)
	}
}

func TestOutstationClosesAfterConfirmation(t *testing.T) {
	fake := startFake(t, func(p *testPeer, a iec104.ASDU) {
		_ = p.sendI(withCOT(a.Raw, 7))
		p.close()
	})
	defer fake.close()
	addr, stop := startGateway(t, testDevice(fake.addr()))
	defer stop()

	m := dialMaster(t, addr)
	defer m.close()
	if err := m.sendI(singleCommand(1, 1000, false, true)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.readI(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.readI(); err == nil {
		t.Fatal("master connection stayed open after the outstation closed")
	}
}

func startRawOutstation(t *testing.T, payload []byte) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = conn.Write(payload)
		_ = conn.Close()
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func TestPartialUpstreamFrameClosesClient(t *testing.T) {
	devAddr, stopRaw := startRawOutstation(t, []byte{0x68, 0x0e, 0x30})
	defer stopRaw()
	addr, stop := startGateway(t, testDevice(devAddr))
	defer stop()

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var b [1]byte
	if _, err := conn.Read(b[:]); err == nil {
		t.Fatal("client stayed open after a truncated upstream frame")
	}
}

func TestAuditAllowedAndDeniedCommands(t *testing.T) {
	var buf bytes.Buffer
	audit := observ.NewAuditWriter(&buf, nil)
	fake := startFake(t, replyCommand)
	defer fake.close()
	dev := testDevice(fake.addr())
	dev.CommandPolicy = &config.CommandPolicy{
		Default: "deny",
		Rules: []config.CommandRule{{
			Types:         config.IntList{45},
			CommonAddress: &config.CommonAddress{Value: 1},
			IOA:           &config.IOARange{From: 1000, To: 1000},
			Select:        "execute",
			Action:        "allow",
		}},
	}
	addr, stop := startGatewayWith(t, dev, nil, audit)
	m := dialMaster(t, addr)
	if err := m.sendI(singleCommand(1, 1000, false, true)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.readI(); err != nil {
		t.Fatal(err)
	}
	if err := m.sendI(singleCommand(1, 2000, false, true)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.readI(); err != nil {
		t.Fatal(err)
	}
	m.close()
	stop()
	if err := audit.Close(); err != nil {
		t.Fatal(err)
	}

	var allowed, denied bool
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var ev observ.AuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("audit line %q: %v", line, err)
		}
		if ev.Event == "command_allowed" && ev.IOA == "1000" {
			allowed = true
		}
		if ev.Event == "command_denied" && ev.IOA == "2000" {
			denied = true
		}
	}
	if !allowed || !denied {
		t.Fatalf("audit allowed=%t denied=%t\n%s", allowed, denied, buf.String())
	}
}

func TestMetricsAllowedAndDenied(t *testing.T) {
	met := &recordingMetrics{}
	fake := startFake(t, replyCommand)
	defer fake.close()
	dev := testDevice(fake.addr())
	dev.CommandPolicy = &config.CommandPolicy{Default: "deny"}
	addr, stop := startGatewayWith(t, dev, met, nil)
	defer stop()

	m := dialMaster(t, addr)
	defer m.close()
	if err := m.sendI(singleCommand(1, 1000, false, true)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.readI(); err != nil {
		t.Fatal(err)
	}
	if err := m.sendI(interrogation(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.readI(); err != nil {
		t.Fatal(err)
	}
	met.mu.Lock()
	defer met.mu.Unlock()
	if met.denied == 0 {
		t.Fatal("denied command was not counted")
	}
	if met.forwarded == 0 {
		t.Fatal("forwarded interrogation was not counted")
	}
	if met.frames == 0 {
		t.Fatal("frames were not counted")
	}
}

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func TestRunnerStartStop(t *testing.T) {
	fake := startFake(t, replyCommand)
	defer fake.close()
	dev := testDevice(fake.addr())
	dev.ListenAddr = freeTCPAddr(t)
	dev.MaxClients = 1

	cfg := config.Defaults()
	cfg.Devices = []config.Device{dev}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
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

	m := dialMaster(t, dev.ListenAddr)
	if err := m.sendI(interrogation(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.readI(); err != nil {
		t.Fatal(err)
	}
	m.close()
	r.Stop()
	if err := <-errCh; err != nil {
		t.Fatalf("runner stop: %v", err)
	}
}

func TestRunnerBindFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	dev := testDevice("127.0.0.1:1")
	dev.ListenAddr = ln.Addr().String()

	cfg := config.Defaults()
	cfg.Devices = []config.Device{dev}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	r, err := NewRunner(cfg, zap.NewNop().Sugar(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Run(); err == nil {
		t.Fatal("runner accepted an already-bound listener")
	}
	select {
	case <-r.Ready():
		t.Fatal("runner advertised ready after a bind failure")
	default:
	}
}

func TestLinkSendSerialization(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan struct{})
	defer close(done)
	l := newLink("test", client, 12, time.Second, 0, done)

	var calls atomic.Int32
	first := make(chan struct{})
	second := make(chan struct{})
	release := make(chan struct{})
	l.sendHook = func() {
		if calls.Add(1) == 1 {
			close(first)
			<-release
			return
		}
		close(second)
	}

	frames := make(chan iec104.Frame, 2)
	go func() {
		for i := 0; i < 2; i++ {
			f, err := iec104.ReadFrame(server)
			if err != nil {
				return
			}
			frames <- f
		}
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = l.sendI([]byte{100, 0x01, 0x06, 0x00, 0x01, 0x00, 0x14})
	}()
	<-first

	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = l.sendI([]byte{100, 0x01, 0x06, 0x00, 0x01, 0x00, 0x14})
	}()
	select {
	case <-second:
		t.Fatal("second I-frame reserved N(S) before the first was written")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	wg.Wait()

	for i := 0; i < 2; i++ {
		select {
		case f := <-frames:
			if f.SendSeq != uint16(i) {
				t.Fatalf("frame %d send sequence = %d", i, f.SendSeq)
			}
		case <-time.After(time.Second):
			t.Fatalf("frame %d was not written", i)
		}
	}
}
