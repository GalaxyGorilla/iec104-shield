package observ

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// AuditEvent is one security-relevant decision. The field names are a stable
// contract for a SIEM or log pipeline; add fields, never silently rename one.
type AuditEvent struct {
	Time          string `json:"time"`
	Event         string `json:"event"`
	Device        string `json:"device"`
	Client        string `json:"client,omitempty"`
	Direction     string `json:"direction,omitempty"`
	TypeID        uint8  `json:"type_id,omitempty"`
	TypeName      string `json:"type_name,omitempty"`
	Cause         uint8  `json:"cause,omitempty"`
	CommonAddress uint16 `json:"common_address,omitempty"`
	IOA           string `json:"ioa,omitempty"`
	Select        *bool  `json:"select,omitempty"`
	Reason        string `json:"reason,omitempty"`
}

const auditQueue = 1024

// Audit is a bounded, non-blocking JSON-lines audit stream. A full queue drops
// records and counts them rather than blocking the data plane.
type Audit struct {
	ch      chan AuditEvent
	closer  io.Closer
	dropped prometheus.Counter

	mu     sync.RWMutex
	closed bool
	once   sync.Once
	wg     sync.WaitGroup
}

// NewAuditWriter streams records to w.
func NewAuditWriter(w io.Writer, dropped prometheus.Counter) *Audit {
	a := &Audit{ch: make(chan AuditEvent, auditQueue), dropped: dropped}
	a.wg.Add(1)
	go a.run(w)
	return a
}

// NewAuditFile opens an append-only audit file with one rotated backup.
func NewAuditFile(path string, maxBytes int64, dropped prometheus.Counter) (*Audit, error) {
	rf, err := openRotatingFile(path, maxBytes)
	if err != nil {
		return nil, err
	}
	a := NewAuditWriter(rf, dropped)
	a.closer = rf
	return a, nil
}

// Record enqueues one event. Safe on a nil *Audit.
func (a *Audit) Record(ev AuditEvent) {
	if a == nil {
		return
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closed {
		return
	}
	select {
	case a.ch <- ev:
	default:
		if a.dropped != nil {
			a.dropped.Inc()
		}
	}
}

// Close drains and closes the stream. Idempotent and nil-safe.
func (a *Audit) Close() error {
	if a == nil {
		return nil
	}
	a.once.Do(func() {
		a.mu.Lock()
		a.closed = true
		close(a.ch)
		a.mu.Unlock()
		a.wg.Wait()
	})
	if a.closer != nil {
		return a.closer.Close()
	}
	return nil
}

func (a *Audit) run(w io.Writer) {
	defer a.wg.Done()
	enc := json.NewEncoder(w)
	for ev := range a.ch {
		ev.Time = time.Now().UTC().Format(time.RFC3339Nano)
		_ = enc.Encode(ev)
	}
}

type rotatingFile struct {
	mu   sync.Mutex
	path string
	max  int64
	f    *os.File
	size int64
}

func openRotatingFile(path string, max int64) (*rotatingFile, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &rotatingFile{path: path, max: max, f: f, size: fi.Size()}, nil
}

func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.max > 0 && r.size > 0 && r.size+int64(len(p)) > r.max {
		if err := r.rotateLocked(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *rotatingFile) rotateLocked() error {
	if err := r.f.Close(); err != nil {
		return err
	}
	_ = os.Rename(r.path, r.path+".1")
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	r.f = f
	r.size = 0
	return nil
}

func (r *rotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}
