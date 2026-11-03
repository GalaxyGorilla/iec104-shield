package policy

import (
	"net"
	"testing"

	"github.com/GalaxyGorilla/iec104-shield/internal/iec104"
)

func command(t *testing.T, typ uint8, ca uint16, ioa uint32, selectBit bool) iec104.ASDU {
	t.Helper()
	info := byte(0x01)
	if selectBit {
		info |= 0x80
	}
	b := []byte{typ, 0x01, 0x06, 0x00, byte(ca), byte(ca >> 8),
		byte(ioa), byte(ioa >> 8), byte(ioa >> 16), info}
	a, err := iec104.ParseASDU(b)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func interrogation(t *testing.T, ca uint16) iec104.ASDU {
	t.Helper()
	a, err := iec104.ParseASDU([]byte{100, 0x01, 0x06, 0x00, byte(ca), byte(ca >> 8), 0x14})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestReadOnly(t *testing.T) {
	p, err := New(true, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Allowed(command(t, 45, 1, 1000, false)) {
		t.Fatal("read-only allowed a command")
	}
	if !p.Allowed(interrogation(t, 1)) {
		t.Fatal("read-only refused an interrogation")
	}
	if !(*Policy)(nil).Allowed(command(t, 45, 1, 1000, false)) {
		t.Fatal("nil policy refused a command")
	}
}

func TestDefaultDeny(t *testing.T) {
	p, err := New(false, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Allowed(command(t, 45, 1, 1000, false)) {
		t.Fatal("default deny allowed a command")
	}
	if !p.Allowed(interrogation(t, 1)) {
		t.Fatal("default deny refused an interrogation")
	}
}

func TestAllowRule(t *testing.T) {
	from, to := uint32(1000), uint32(2000)
	ca := uint16(1)
	p, err := New(false, false, []Rule{{
		Types: []uint8{45, 46}, CommonAddress: &ca,
		IOAFrom: &from, IOATo: &to, Allow: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Allowed(command(t, 45, 1, 1500, false)) {
		t.Fatal("allow rule did not cover the command")
	}
	if p.Allowed(command(t, 45, 1, 2500, false)) {
		t.Fatal("allow rule covered an address outside its range")
	}
	if p.Allowed(command(t, 45, 2, 1500, false)) {
		t.Fatal("allow rule covered another common address")
	}
	if p.Allowed(command(t, 47, 1, 1500, false)) {
		t.Fatal("allow rule covered another type")
	}
}

func TestDenyOverrides(t *testing.T) {
	from, to := uint32(1000), uint32(2000)
	bad := uint32(1500)
	p, err := New(false, false, []Rule{
		{Types: []uint8{45}, IOAFrom: &from, IOATo: &to, Allow: true},
		{Types: []uint8{45}, IOAFrom: &bad, IOATo: &bad, Allow: false},
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.Allowed(command(t, 45, 1, 1500, false)) {
		t.Fatal("deny rule did not override the allow rule")
	}
	if !p.Allowed(command(t, 45, 1, 1600, false)) {
		t.Fatal("deny rule covered an address outside its range")
	}
}

func TestSelectRule(t *testing.T) {
	sel := true
	p, err := New(false, false, []Rule{{
		Types: []uint8{45}, Select: &sel, Allow: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Allowed(command(t, 45, 1, 1000, true)) {
		t.Fatal("select rule did not allow a select")
	}
	if p.Allowed(command(t, 45, 1, 1000, false)) {
		t.Fatal("select rule allowed an execute")
	}
}

func TestNoIOARule(t *testing.T) {
	from, to := uint32(1), uint32(10)
	p, err := New(false, true, []Rule{{
		Types: []uint8{103}, IOAFrom: &from, IOATo: &to, Allow: false,
	}})
	if err != nil {
		t.Fatal(err)
	}
	// Clock sync has no IOA, so an IOA-scoped deny cannot match; the
	// default allow applies. This is why a no-IOA command needs an
	// unscoped rule.
	clock, err := iec104.ParseASDU([]byte{103, 0x01, 0x06, 0x00, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Allowed(clock) {
		t.Fatal("IOA-scoped rule unexpectedly matched a no-IOA command")
	}
}

func TestList(t *testing.T) {
	l, err := NewList([]string{"10.0.0.0/8", "192.0.2.7", "2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"10.1.2.3", "192.0.2.7", "2001:db8::1"} {
		if !l.Allowed(net.ParseIP(ip)) {
			t.Fatalf("%s not allowed", ip)
		}
	}
	for _, ip := range []string{"11.0.0.1", "192.0.2.8", "2001:db9::1"} {
		if l.Allowed(net.ParseIP(ip)) {
			t.Fatalf("%s allowed", ip)
		}
	}
	if !(*List)(nil).Allowed(net.ParseIP("203.0.113.1")) {
		t.Fatal("nil list must allow everyone")
	}
	if _, err := NewList([]string{"not-an-ip"}); err == nil {
		t.Fatal("invalid entry accepted")
	}
}
