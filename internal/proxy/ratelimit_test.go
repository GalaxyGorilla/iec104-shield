package proxy

import (
	"net"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/GalaxyGorilla/iec104-shield/internal/config"
	"github.com/GalaxyGorilla/iec104-shield/internal/iec104"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func TestRateLimiterTokenBucket(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1000, 0)}
	l := newRateLimiter(2)
	l.now = clock.Now

	first := l.allow()
	second := l.allow()
	if !first || !second {
		t.Fatal("initial burst was not allowed")
	}
	if l.allow() {
		t.Fatal("third request was allowed with an empty bucket")
	}
	clock.Advance(500 * time.Millisecond)
	if !l.allow() {
		t.Fatal("one token did not refill after 500ms at 2/s")
	}
	if l.allow() {
		t.Fatal("bucket refilled more than one token")
	}

	if newRateLimiter(0) != nil {
		t.Fatal("rate 0 did not produce an unlimited limiter")
	}
	var unlimited *rateLimiter
	if !unlimited.allow() {
		t.Fatal("nil limiter is not unlimited")
	}
}

func startGatewayHandle(t *testing.T, dev config.Device) (*Gateway, string, func()) {
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
	return gw, ln.Addr().String(), stop
}

func sendCommand(t *testing.T, m *testPeer, ioa uint32) iec104.ASDU {
	t.Helper()
	if err := m.sendI(singleCommand(1, ioa, false, true)); err != nil {
		t.Fatal(err)
	}
	a, err := m.readI()
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestRateLimitDeniesBurstAndRecovers(t *testing.T) {
	fake := startFake(t, replyCommand)
	defer fake.close()
	dev := testDevice(fake.addr())
	dev.CommandPolicy = &config.CommandPolicy{Default: "allow"}
	dev.RatePerSec = 1
	gw, addr, stop := startGatewayHandle(t, dev)
	defer stop()

	clock := &fakeClock{t: time.Unix(1000, 0)}
	gw.rtMu.Lock()
	gw.rt.lim.now = clock.Now
	gw.rtMu.Unlock()

	m := dialMaster(t, addr)
	defer m.close()

	if con := sendCommand(t, m, 1000); con.PN {
		t.Fatalf("first command was denied: %+v", con)
	}
	neg := sendCommand(t, m, 1000)
	if !neg.PN {
		t.Fatalf("burst command was not rate-limited: %+v", neg)
	}
	if got := len(fake.received()); got != 1 {
		t.Fatalf("outstation received %d commands, want 1", got)
	}

	clock.Advance(1100 * time.Millisecond)
	if con := sendCommand(t, m, 1000); con.PN {
		t.Fatalf("command was still rate-limited after refill: %+v", con)
	}
	if got := len(fake.received()); got != 2 {
		t.Fatalf("outstation received %d commands, want 2", got)
	}
}

func TestPacingSpacesForwardedFrames(t *testing.T) {
	fake := startFake(t, nil)
	defer fake.close()
	dev := testDevice(fake.addr())
	dev.CommandPolicy = &config.CommandPolicy{Default: "allow"}
	dev.MinIntervalMs = 60
	_, addr, stop := startGatewayHandle(t, dev)
	defer stop()

	m := dialMaster(t, addr)
	defer m.close()
	for i := 0; i < 2; i++ {
		if err := m.sendI(singleCommand(1, 1000, false, true)); err != nil {
			t.Fatal(err)
		}
	}

	deadline := time.Now().Add(2 * time.Second)
	for len(fake.received()) < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	at := fake.receivedAt()
	if len(at) != 2 {
		t.Fatalf("outstation received %d frames, want 2", len(at))
	}
	if gap := at[1].Sub(at[0]); gap < 40*time.Millisecond {
		t.Fatalf("forward gap = %v, want at least 40ms (configured 60ms)", gap)
	}
}
