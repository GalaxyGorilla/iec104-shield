package proxy

import (
	"bufio"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/GalaxyGorilla/iec104-shield/internal/config"
	"github.com/GalaxyGorilla/iec104-shield/internal/iec104"
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
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gw, err := New(dev, zap.NewNop().Sugar(), nil, nil)
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

func (p *testPeer) sendS() error { return p.write(iec104.NewS(p.recvSeq)) }
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
		if f.SendSeq != p.recvSeq {
			return iec104.Frame{}, fmt.Errorf("peer sequence gap: got %d want %d", f.SendSeq, p.recvSeq)
		}
		p.recvSeq = (p.recvSeq + 1) & iec104.MaxSequence
		_ = p.sendS()
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
	ln   net.Listener
	conn net.Conn
	mu   sync.Mutex
	got  []iec104.ASDU
	uGot []iec104.UFunction
}

func startFake(t *testing.T, handler func(*testPeer, iec104.ASDU)) *fakeOutstation {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeOutstation{ln: ln}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		f.mu.Lock()
		f.conn = conn
		f.mu.Unlock()
		p := newTestPeer(conn)
		defer p.close()
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
				f.mu.Unlock()
				if handler != nil {
					handler(p, a)
				}
			}
		}
	}()
	return f
}

func (f *fakeOutstation) addr() string { return f.ln.Addr().String() }
func (f *fakeOutstation) close() {
	_ = f.ln.Close()
	f.mu.Lock()
	if f.conn != nil {
		_ = f.conn.Close()
	}
	f.mu.Unlock()
}

func (f *fakeOutstation) received() []iec104.ASDU {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]iec104.ASDU(nil), f.got...)
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
