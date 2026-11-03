package iec104

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestParseIFrame(t *testing.T) {
	asdu := []byte{0x01, 0x01, 0x06, 0x00, 0x01, 0x00, 0x64, 0x00, 0x00, 0x01}
	raw, err := NewI(1, 2, asdu)
	if err != nil {
		t.Fatal(err)
	}
	f, err := ParseFrame(raw)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != IFrame || f.SendSeq != 1 || f.RecvSeq != 2 {
		t.Fatalf("frame = %+v", f)
	}
	if !bytes.Equal(f.ASDU, asdu) {
		t.Fatalf("asdu = %x", f.ASDU)
	}
}

func TestParseSFrame(t *testing.T) {
	f, err := ParseFrame(NewS(5))
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != SFrame || f.RecvSeq != 5 {
		t.Fatalf("frame = %+v", f)
	}
}

func TestParseUFrame(t *testing.T) {
	f, err := ParseFrame(NewU(UTestFRActive))
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != UFrame || f.U != UTestFRActive {
		t.Fatalf("frame = %+v", f)
	}
	if got := NewU(UTestFRActive); !bytes.Equal(got, []byte{0x68, 0x04, 0x43, 0, 0, 0}) {
		t.Fatalf("wire = %x", got)
	}
}

func TestParseFrameRejects(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"short", []byte{0x68}, ErrShortFrame},
		{"start", []byte{0x67, 0x04, 0x01, 0, 0, 0}, ErrBadStart},
		{"length-small", []byte{0x68, 0x03, 0x01, 0, 0}, ErrBadLength},
		{"length-large", []byte{0x68, 0xfe}, ErrBadLength},
		{"trailing", []byte{0x68, 0x04, 0x01, 0, 0, 0, 0}, ErrTrailingBytes},
		{"s-reserved", []byte{0x68, 0x04, 0x01, 0x01, 0, 0}, ErrBadControl},
		{"s-with-asdu", []byte{0x68, 0x05, 0x01, 0, 0, 0, 0}, ErrBadControl},
		{"s-reserved-bit", []byte{0x68, 0x04, 0x05, 0, 0, 0}, ErrBadControl},
		{"u-reserved", []byte{0x68, 0x04, 0x43, 0x01, 0, 0}, ErrBadControl},
		{"u-with-asdu", []byte{0x68, 0x05, 0x43, 0, 0, 0, 0}, ErrBadControl},
		{"i-empty", []byte{0x68, 0x04, 0x00, 0, 0, 0}, ErrBadControl},
		{"i-nr-low-bit", []byte{0x68, 0x05, 0x00, 0, 0x01, 0, 0}, ErrBadControl},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseFrame(tc.in); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestReadFrame(t *testing.T) {
	raw, _ := NewI(0, 0, []byte{0x01, 0x01, 0x06, 0x00, 0x01, 0x00, 0x64, 0x00, 0x00, 0x01})
	f, err := ReadFrame(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != IFrame || len(f.ASDU) != 10 {
		t.Fatalf("frame = %+v", f)
	}
	if _, err := ReadFrame(bytes.NewReader(raw[:3])); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated err = %v", err)
	}
	if _, err := ReadFrame(bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Fatalf("empty err = %v", err)
	}
}

func TestSequenceRoundTrip(t *testing.T) {
	for _, seq := range []uint16{0, 1, 0x7f, 0x80, 0x3fff, MaxSequence} {
		raw, err := NewI(seq, MaxSequence-seq, []byte{100, 0x01, 0x06, 0x00, 0x01, 0x00, 0x14})
		if err != nil {
			t.Fatal(err)
		}
		f, err := ParseFrame(raw)
		if err != nil {
			t.Fatal(err)
		}
		if f.SendSeq != seq || f.RecvSeq != MaxSequence-seq {
			t.Fatalf("seq %d -> %+v", seq, f)
		}
	}
}

func FuzzParseFrame(f *testing.F) {
	seed, _ := NewI(1, 2, []byte{0x01, 0x01, 0x06, 0x00, 0x01, 0x00, 0x64, 0x00, 0x00, 0x01})
	f.Add(seed)
	f.Add(NewS(3))
	f.Add(NewU(UTestFRActive))
	f.Fuzz(func(t *testing.T, b []byte) {
		fr, err := ParseFrame(b)
		if err != nil {
			return
		}
		if len(fr.Raw) != len(b) {
			t.Fatalf("raw length changed")
		}
		switch fr.Type {
		case IFrame:
			want, err := NewI(fr.SendSeq, fr.RecvSeq, fr.ASDU)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(want, b) {
				t.Fatalf("I-frame did not round-trip: %x != %x", want, b)
			}
		case SFrame:
			if want := NewS(fr.RecvSeq); !bytes.Equal(want, b) {
				t.Fatalf("S-frame did not round-trip: %x != %x", want, b)
			}
		case UFrame:
			if want := NewU(fr.U); !bytes.Equal(want, b) {
				t.Fatalf("U-frame did not round-trip: %x != %x", want, b)
			}
		}
	})
}
