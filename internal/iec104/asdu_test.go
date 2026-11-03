package iec104

import (
	"bytes"
	"errors"
	"testing"
)

func le16(v uint16) []byte { return []byte{byte(v), byte(v >> 8)} }

func asduHeader(typ uint8, count uint8, sq bool, cause uint8, ca uint16) []byte {
	vsq := count & 0x7f
	if sq {
		vsq |= 0x80
	}
	return append([]byte{typ, vsq, cause, 0x00}, le16(ca)...)
}

func TestParseSinglePoint(t *testing.T) {
	b := asduHeader(1, 1, false, 3, 1)
	b = append(b, 0x64, 0x00, 0x00, 0x01)
	a, err := ParseASDU(b)
	if err != nil {
		t.Fatal(err)
	}
	if a.TypeID != 1 || a.Cause != 3 || a.CommonAddr != 1 || len(a.Objects) != 1 {
		t.Fatalf("asdu = %+v", a)
	}
	if a.Objects[0].IOA != 100 || !bytes.Equal(a.Objects[0].Info, []byte{0x01}) {
		t.Fatalf("object = %+v", a.Objects[0])
	}
	if IsWrite(a.TypeID) {
		t.Fatal("monitoring type classified as write")
	}
}

func TestParseSequenceObjects(t *testing.T) {
	b := asduHeader(1, 3, true, 3, 1)
	b = append(b, 0x64, 0x00, 0x00, 0x01, 0x00, 0x01)
	a, err := ParseASDU(b)
	if err != nil {
		t.Fatal(err)
	}
	if !a.SQ || a.Count != 3 || len(a.Objects) != 3 {
		t.Fatalf("asdu = %+v", a)
	}
	for i, o := range a.Objects {
		if o.IOA != uint32(100+i) {
			t.Fatalf("object %d ioa = %d", i, o.IOA)
		}
	}
}

func TestParseSingleCommandSelect(t *testing.T) {
	b := asduHeader(45, 1, false, 6, 1)
	b = append(b, 0xE8, 0x03, 0x00, 0x81) // IOA 1000, select + on
	a, err := ParseASDU(b)
	if err != nil {
		t.Fatal(err)
	}
	if !IsWrite(a.TypeID) || !IsProcessCommand(a.TypeID) {
		t.Fatalf("command classification: %+v", a)
	}
	if !Select(a) {
		t.Fatal("select bit not detected")
	}
	if a.Objects[0].IOA != 1000 {
		t.Fatalf("ioa = %d", a.Objects[0].IOA)
	}
}

func TestParseInterrogation(t *testing.T) {
	b := asduHeader(100, 1, false, 6, 1)
	b = append(b, 0x14) // QOI station
	a, err := ParseASDU(b)
	if err != nil {
		t.Fatal(err)
	}
	if IsWrite(a.TypeID) {
		t.Fatal("interrogation classified as write")
	}
	if !IsInterrogation(a.TypeID) {
		t.Fatal("interrogation not recognized")
	}
	if len(a.Objects) != 1 || !bytes.Equal(a.Objects[0].Info, []byte{0x14}) {
		t.Fatalf("object = %+v", a.Objects)
	}
}

func TestParseInterrogationWithZeroIOA(t *testing.T) {
	// Some independent stacks encode an IOA 0 before the QOI.
	b := asduHeader(100, 1, false, 6, 1)
	b = append(b, 0x00, 0x00, 0x00, 0x14)
	a, err := ParseASDU(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Objects) != 1 || !bytes.Equal(a.Objects[0].Info, []byte{0x14}) {
		t.Fatalf("object = %+v", a.Objects)
	}
}

func TestParseUnknownIsPartial(t *testing.T) {
	b := asduHeader(200, 1, false, 3, 1)
	b = append(b, 0xde, 0xad)
	a, err := ParseASDU(b)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Partial || len(a.Objects) != 0 {
		t.Fatalf("asdu = %+v", a)
	}
}

func TestParseTruncated(t *testing.T) {
	b := asduHeader(45, 1, false, 6, 1)
	b = append(b, 0xE8, 0x03) // missing the command octet
	if _, err := ParseASDU(b); !errors.Is(err, ErrTruncatedASDU) {
		t.Fatalf("err = %v", err)
	}
}

func TestParseTrailing(t *testing.T) {
	b := asduHeader(100, 1, false, 6, 1)
	b = append(b, 0x14, 0x00)
	if _, err := ParseASDU(b); !errors.Is(err, ErrTrailingASDU) {
		t.Fatalf("err = %v", err)
	}
}

func TestCOTBits(t *testing.T) {
	// P/N is bit 6 (0x40); test is bit 7 (0x80). This was a real interop bug.
	b := asduHeader(45, 1, false, 0x40|0x80|7, 1)
	b = append(b, 0xE8, 0x03, 0x00, 0x01)
	a, err := ParseASDU(b)
	if err != nil {
		t.Fatal(err)
	}
	if !a.PN || !a.Test || a.Cause != 7 {
		t.Fatalf("cot bits = pn=%t test=%t cause=%d", a.PN, a.Test, a.Cause)
	}
}

func TestNegativeConfirmation(t *testing.T) {
	b := asduHeader(45, 1, false, 6, 7)
	b = append(b, 0xE8, 0x03, 0x00, 0x01)
	a, err := ParseASDU(b)
	if err != nil {
		t.Fatal(err)
	}
	neg := NegativeConfirmation(a)
	if neg[2] != 0x47 {
		t.Fatalf("negative cot = 0x%02x", neg[2])
	}
	if b[2] != 6 {
		t.Fatal("original ASDU was modified")
	}
	if !bytes.Equal(neg[3:], b[3:]) {
		t.Fatal("negative confirmation did not mirror the command")
	}
}

func TestTypeNames(t *testing.T) {
	if TypeName(45) != "C_SC_NA_1" || TypeName(200) != "TYPE_200" {
		t.Fatalf("names = %q %q", TypeName(45), TypeName(200))
	}
}

func FuzzParseASDU(f *testing.F) {
	b := asduHeader(45, 1, false, 6, 1)
	b = append(b, 0xE8, 0x03, 0x00, 0x81)
	f.Add(b)
	f.Add(asduHeader(100, 1, false, 6, 1))
	f.Fuzz(func(t *testing.T, b []byte) {
		a, err := ParseASDU(b)
		if err != nil {
			return
		}
		if len(a.Raw) != len(b) {
			t.Fatalf("raw length changed")
		}
		if !a.Partial && a.Count > 0 && len(a.Objects) != int(a.Count) {
			t.Fatalf("object count = %d, want %d", len(a.Objects), a.Count)
		}
	})
}
