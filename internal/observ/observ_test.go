package observ

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
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
