package observ

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestAuditWriter(t *testing.T) {
	var buf bytes.Buffer
	a := NewAuditWriter(&buf, nil)
	a.Record(AuditEvent{Event: "command_denied", Device: "d1", TypeID: 45, Reason: "policy"})
	a.Record(AuditEvent{Event: "connection", Device: "d1"})
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %q", buf.String())
	}
	var ev AuditEvent
	if err := json.Unmarshal([]byte(lines[0]), &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Event != "command_denied" || ev.Time == "" || ev.TypeID != 45 {
		t.Fatalf("event = %+v", ev)
	}
}

func TestAuditNil(t *testing.T) {
	var a *Audit
	a.Record(AuditEvent{Event: "x"})
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestMetricsHandler(t *testing.T) {
	m := NewMetrics()
	m.IncConnAccepted()
	m.IncConnRejected()
	m.IncFrame("d1", "master", "I")
	m.IncForwarded("d1", "master_to_device")
	m.IncDenied("d1", "read_only")
	m.IncParseError()
	m.IncUpstreamError()
	m.IncSequenceError()
	m.DecActive()

	for _, path := range []string{"/metrics", "/healthz", "/readyz"} {
		rr := httptest.NewRecorder()
		m.Handler().ServeHTTP(rr, httptest.NewRequest("GET", path, nil))
		if rr.Code != 200 {
			t.Fatalf("%s = %d", path, rr.Code)
		}
	}
}

func TestLog(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error"} {
		l, err := Log(level, "console")
		if err != nil {
			t.Fatalf("%s: %v", level, err)
		}
		_ = l.Sync()
	}
	if _, err := Log("nope", "console"); err == nil {
		t.Fatal("bad level accepted")
	}
}

func TestAuditFileRotation(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/audit.jsonl"
	a, err := NewAuditFile(path, 100, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		a.Record(AuditEvent{Event: "command_denied", Device: "d1", Reason: "test"})
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("current audit file: %v", err)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("rotated audit file: %v", err)
	}
}

func TestNewAuditFileError(t *testing.T) {
	if _, err := NewAuditFile("/nonexistent-directory-for-iec104/audit.jsonl", 100, nil); err == nil {
		t.Fatal("missing directory accepted")
	}
}

func TestListenAndServe(t *testing.T) {
	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, ln, NewMetrics().Handler(), zap.NewNop()) }()

	url := "http://" + ln.Addr().String() + "/healthz"
	deadline := time.Now().Add(2 * time.Second)
	for {
		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Fatalf("healthz = %d", resp.StatusCode)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("metrics server did not start: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("serve: %v", err)
	}
}
