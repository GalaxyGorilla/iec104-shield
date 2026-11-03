// Package iec104 implements the IEC 60870-5-104 frame and ASDU subset a
// security proxy needs: framing, control-field sequence numbers, ASDU
// identification, information-object addresses, command classification and
// negative confirmations.
//
// It is deliberately not a full IEC-104 stack. It does not own a master or
// outstation state machine; it parses enough of each APDU to decide whether a
// command may cross the proxy, and forwards the ASDU bytes untouched.
package iec104

import (
	"errors"
	"fmt"
	"io"
)

const (
	// StartByte is the fixed IEC 60870-5-104 start octet.
	StartByte = 0x68
	// ControlLen is the APCI control-field length.
	ControlLen = 4
	// MaxAPDU is the maximum APDU length including start and length octets.
	MaxAPDU = 255
	// MaxASDU is the maximum ASDU length (APDU minus start, length, control).
	MaxASDU = MaxAPDU - 2 - ControlLen
	// MaxSequence is the largest 15-bit sequence number.
	MaxSequence = 0x7fff
)

// FrameType is the APCI frame format.
type FrameType uint8

const (
	// IFrame carries an ASDU and both send and receive sequence numbers.
	IFrame FrameType = iota
	// SFrame acknowledges received I-frames.
	SFrame
	// UFrame carries an unnumbered control function.
	UFrame
)

func (t FrameType) String() string {
	switch t {
	case IFrame:
		return "I"
	case SFrame:
		return "S"
	case UFrame:
		return "U"
	default:
		return "unknown"
	}
}

// UFunction is the unnumbered control function. The constants are the
// function bits (the low two bits of the first control octet are always 0b11
// on the wire).
type UFunction uint8

const (
	UStartDTActive  UFunction = 0x04
	UStartDTConfirm UFunction = 0x08
	UStopDTActive   UFunction = 0x10
	UStopDTConfirm  UFunction = 0x20
	UTestFRActive   UFunction = 0x40
	UTestFRConfirm  UFunction = 0x80
)

func (u UFunction) String() string {
	switch u {
	case UStartDTActive:
		return "STARTDT_ACT"
	case UStartDTConfirm:
		return "STARTDT_CON"
	case UStopDTActive:
		return "STOPDT_ACT"
	case UStopDTConfirm:
		return "STOPDT_CON"
	case UTestFRActive:
		return "TESTFR_ACT"
	case UTestFRConfirm:
		return "TESTFR_CON"
	default:
		return fmt.Sprintf("U(0x%02x)", uint8(u))
	}
}

// Frame is one decoded APDU. Raw is the complete wire frame. ASDU is the
// application payload for I-frames only and aliases Raw; callers must not
// modify it in place.
type Frame struct {
	Type    FrameType
	SendSeq uint16
	RecvSeq uint16
	U       UFunction
	ASDU    []byte
	Raw     []byte
}

// ParseFrame decodes exactly one APDU. It rejects a frame with trailing bytes,
// a wrong start octet, an out-of-range length, a malformed control field or a
// U-frame with non-zero reserved octets.
func ParseFrame(b []byte) (Frame, error) {
	if len(b) < 2 {
		return Frame{}, ErrShortFrame
	}
	if b[0] != StartByte {
		return Frame{}, ErrBadStart
	}
	length := int(b[1])
	if length < ControlLen || length > MaxAPDU-2 {
		return Frame{}, fmt.Errorf("%w: %d", ErrBadLength, length)
	}
	if len(b) != 2+length {
		return Frame{}, fmt.Errorf("%w: length=%d got=%d", ErrTrailingBytes, length, len(b))
	}
	ctl := b[2:6]
	f := Frame{Raw: b}
	switch {
	case ctl[0]&0x01 == 0:
		if length == ControlLen {
			return Frame{}, ErrBadControl // I-frame without an ASDU
		}
		if ctl[2]&0x01 != 0 {
			return Frame{}, ErrBadControl // N(R) low bit is reserved
		}
		f.Type = IFrame
		f.SendSeq = uint16(ctl[0]>>1) | uint16(ctl[1])<<7
		f.RecvSeq = uint16(ctl[2]>>1) | uint16(ctl[3])<<7
		f.ASDU = b[6:]
	case ctl[0]&0x03 == 0x01:
		if ctl[0] != 0x01 || length != ControlLen || ctl[1] != 0 || ctl[2]&0x01 != 0 {
			return Frame{}, ErrBadControl
		}
		f.Type = SFrame
		f.RecvSeq = uint16(ctl[2]>>1) | uint16(ctl[3])<<7
	case ctl[0]&0x03 == 0x03:
		if length != ControlLen || ctl[1] != 0 || ctl[2] != 0 || ctl[3] != 0 {
			return Frame{}, ErrBadControl
		}
		f.Type = UFrame
		f.U = UFunction(ctl[0] & 0xfc)
	default:
		return Frame{}, ErrBadControl
	}
	return f, nil
}

// ReadFrame reads and decodes one APDU from r. A clean close at a frame
// boundary returns io.EOF; a truncated frame returns io.ErrUnexpectedEOF.
func ReadFrame(r io.Reader) (Frame, error) {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return Frame{}, err
	}
	if head[0] != StartByte {
		return Frame{}, ErrBadStart
	}
	length := int(head[1])
	if length < ControlLen || length > MaxAPDU-2 {
		return Frame{}, fmt.Errorf("%w: %d", ErrBadLength, length)
	}
	buf := make([]byte, 2+length)
	copy(buf, head[:])
	if _, err := io.ReadFull(r, buf[2:]); err != nil {
		return Frame{}, err
	}
	return ParseFrame(buf)
}

// NewI builds an I-frame. send and recv are masked to 15 bits.
func NewI(send, recv uint16, asdu []byte) ([]byte, error) {
	if len(asdu) > MaxASDU {
		return nil, fmt.Errorf("%w: asdu=%d", ErrASDUTooLarge, len(asdu))
	}
	send &= MaxSequence
	recv &= MaxSequence
	b := make([]byte, 6+len(asdu))
	b[0] = StartByte
	b[1] = byte(ControlLen + len(asdu))
	b[2] = byte(send << 1)
	b[3] = byte(send >> 7)
	b[4] = byte(recv << 1)
	b[5] = byte(recv >> 7)
	copy(b[6:], asdu)
	return b, nil
}

// NewS builds an S-frame acknowledging recv.
func NewS(recv uint16) []byte {
	recv &= MaxSequence
	return []byte{StartByte, ControlLen, 0x01, 0x00, byte(recv << 1), byte(recv >> 7)}
}

// NewU builds a U-frame for fn.
func NewU(fn UFunction) []byte {
	return []byte{StartByte, ControlLen, byte(fn) | 0x03, 0x00, 0x00, 0x00}
}

var (
	// ErrShortFrame means fewer than two octets were available.
	ErrShortFrame = errors.New("iec104: short frame")
	// ErrBadStart means the start octet is not 0x68.
	ErrBadStart = errors.New("iec104: bad start octet")
	// ErrBadLength means the APDU length is outside 4..253.
	ErrBadLength = errors.New("iec104: bad apdu length")
	// ErrTrailingBytes means the slice does not contain exactly one APDU.
	ErrTrailingBytes = errors.New("iec104: trailing or missing bytes")
	// ErrBadControl means the control field is malformed.
	ErrBadControl = errors.New("iec104: bad control field")
	// ErrASDUTooLarge means an ASDU exceeds the 249-octet limit.
	ErrASDUTooLarge = errors.New("iec104: asdu too large")
)
