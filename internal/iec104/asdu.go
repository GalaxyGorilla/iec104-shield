package iec104

import (
	"errors"
	"fmt"
)

// ASDU is a decoded application service data unit. Objects are decoded only
// for types with a known fixed information-element size. For an unknown or
// variable-size type Partial is true and Objects is empty; Raw still carries
// the complete ASDU for forwarding.
type ASDU struct {
	TypeID     uint8
	SQ         bool
	Count      uint8
	COT        uint8 // complete cause-of-transmission octet
	Cause      uint8 // low six bits of COT
	PN         bool  // negative-confirm bit
	Test       bool  // test bit
	Originator uint8
	CommonAddr uint16
	Objects    []Object
	Raw        []byte
	Partial    bool
}

// Object is one information object. Info is the information element without
// the three-octet information-object address.
type Object struct {
	IOA  uint32
	Info []byte
}

// ParseASDU decodes the ASDU header and, when the type has a known fixed
// information-element size, every information object. IEC 60870-5-104 uses a
// two-octet cause (cause + originator), a two-octet common address and a
// three-octet information-object address.
func ParseASDU(b []byte) (ASDU, error) {
	if len(b) < 6 {
		return ASDU{}, ErrShortASDU
	}
	a := ASDU{
		TypeID:     b[0],
		SQ:         b[1]&0x80 != 0,
		Count:      b[1] & 0x7f,
		COT:        b[2],
		Cause:      b[2] & 0x3f,
		PN:         b[2]&0x40 != 0,
		Test:       b[2]&0x80 != 0,
		Originator: b[3],
		CommonAddr: uint16(b[4]) | uint16(b[5])<<8,
		Raw:        b,
	}
	if a.Count == 0 {
		if len(b) != 6 {
			return ASDU{}, ErrTrailingASDU
		}
		return a, nil
	}
	size, known := elementSize(a.TypeID)
	if !known {
		a.Partial = true
		return a, nil
	}

	off := 6
	withIOA := hasIOA(a.TypeID)
	if !withIOA {
		if a.SQ {
			// Sequence addressing is only defined for information objects
			// that carry an address.
			return ASDU{}, ErrTrailingASDU
		}
		// Some stacks encode an information-object address before the
		// information element of a system command (usually IOA 0, for
		// example an interrogation with IOA 0 + QOI). The standard form has
		// no IOA. The total length disambiguates the two encodings.
		prefixIOA := a.Count == 1 && len(b) == 6+3+size &&
			b[6] == 0 && b[7] == 0 && b[8] == 0
		if prefixIOA {
			off = 9
		}
		a.Objects = make([]Object, 0, a.Count)
		for i := 0; i < int(a.Count); i++ {
			if len(b)-off < size {
				return ASDU{}, ErrTruncatedASDU
			}
			a.Objects = append(a.Objects, Object{Info: b[off : off+size]})
			off += size
		}
	} else if !a.SQ {
		a.Objects = make([]Object, 0, a.Count)
		for i := 0; i < int(a.Count); i++ {
			if len(b)-off < 3 {
				return ASDU{}, ErrTruncatedASDU
			}
			ioa := uint32(b[off]) | uint32(b[off+1])<<8 | uint32(b[off+2])<<16
			off += 3
			if len(b)-off < size {
				return ASDU{}, ErrTruncatedASDU
			}
			a.Objects = append(a.Objects, Object{IOA: ioa, Info: b[off : off+size]})
			off += size
		}
	} else {
		if len(b)-off < 3 {
			return ASDU{}, ErrTruncatedASDU
		}
		base := uint32(b[off]) | uint32(b[off+1])<<8 | uint32(b[off+2])<<16
		off += 3
		a.Objects = make([]Object, 0, a.Count)
		for i := 0; i < int(a.Count); i++ {
			if len(b)-off < size {
				return ASDU{}, ErrTruncatedASDU
			}
			ioa := base + uint32(i)
			if ioa > 0xffffff {
				return ASDU{}, ErrTruncatedASDU
			}
			a.Objects = append(a.Objects, Object{IOA: ioa, Info: b[off : off+size]})
			off += size
		}
	}
	if off != len(b) {
		return ASDU{}, ErrTrailingASDU
	}
	return a, nil
}

// NegativeConfirmation returns a copy of a command ASDU with the
// positive/negative bit set and the cause changed to the matching negative
// confirmation. It mirrors the type, common address and information objects so
// the master can correlate the refusal with the command it sent. The original
// ASDU is not modified.
func NegativeConfirmation(a ASDU) []byte {
	if len(a.Raw) < 3 {
		return nil
	}
	out := append([]byte(nil), a.Raw...)
	cause := uint8(7) // activation confirmation
	switch a.Cause {
	case 6: // activation
		cause = 7
	case 8: // deactivation
		cause = 9
	}
	out[2] = 0x40 | (a.COT & 0x80) | cause
	return out
}

// IsWrite reports whether a type changes the controlled process or the
// outstation's configuration and therefore needs command policy. Interrogation
// (100), counter interrogation (101), read (102) and test commands (104, 107)
// are read-only operations and stay allowed in read-only mode.
func IsWrite(t uint8) bool {
	switch {
	case t >= 45 && t <= 51, // process commands without time tag
		t >= 58 && t <= 64,   // process commands with CP56Time2a
		t == 103,             // clock synchronization
		t == 105,             // reset process
		t == 106,             // delay acquisition
		t >= 110 && t <= 113, // parameter commands
		t >= 120 && t <= 127: // file transfer / log query
		return true
	default:
		return false
	}
}

// IsProcessCommand reports whether t is a process command (single, double,
// step, setpoint or bitstring), as opposed to a system or file command.
func IsProcessCommand(t uint8) bool {
	return (t >= 45 && t <= 51) || (t >= 58 && t <= 64)
}

// IsInterrogation reports whether t is a read-style system command.
func IsInterrogation(t uint8) bool {
	return t == 100 || t == 101 || t == 102
}

// IsTest reports whether t is a test command.
func IsTest(t uint8) bool {
	return t == 104 || t == 107
}

// Select reports the select/execute bit for command types that carry one.
// C_BO_NA_1 and C_BO_TA_1 carry a bitstring, not a qualifier octet, and are
// reported as execute (false).
func Select(a ASDU) bool {
	if len(a.Objects) == 0 || len(a.Objects[0].Info) == 0 {
		return false
	}
	switch a.TypeID {
	case 45, 46, 47, 48, 49, 50,
		58, 59, 60, 61, 62, 63:
		return a.Objects[0].Info[0]&0x80 != 0
	default:
		return false
	}
}

// TypeName returns the standard IEC 60870-5-104 type name, or a numeric
// fallback for private/unknown types.
func TypeName(t uint8) string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("TYPE_%d", t)
}

// Describe returns a compact log/audit form of the ASDU.
func (a ASDU) Describe() string {
	sel := ""
	if IsProcessCommand(a.TypeID) {
		if Select(a) {
			sel = " select=true"
		} else {
			sel = " select=false"
		}
	}
	return fmt.Sprintf("type=%d(%s) cause=%d pn=%t ca=%d ioa=%s%s",
		a.TypeID, TypeName(a.TypeID), a.Cause, a.PN, a.CommonAddr, a.ioaString(), sel)
}

func (a ASDU) ioaString() string {
	if len(a.Objects) == 0 {
		return "-"
	}
	if len(a.Objects) == 1 {
		return fmt.Sprintf("%d", a.Objects[0].IOA)
	}
	return fmt.Sprintf("%d..%d", a.Objects[0].IOA, a.Objects[len(a.Objects)-1].IOA)
}

// elementSize is the information-element size in octets for a fixed-size
// standard type. The three-octet information-object address is not included.
// Variable-size file types are deliberately absent: they are forwarded but
// cannot be authorized by IOA until a later release.
func elementSize(t uint8) (int, bool) {
	n, ok := elementSizes[t]
	return n, ok
}

// hasIOA reports whether the type's information objects start with a
// three-octet information-object address. System commands such as
// interrogation, clock synchronization and reset carry only an information
// element; process commands, monitoring data and parameter commands carry an
// address.
func hasIOA(t uint8) bool {
	switch {
	case t >= 1 && t <= 40,
		t >= 45 && t <= 51,
		t >= 58 && t <= 64,
		t == 102,
		t >= 110 && t <= 113:
		return true
	default:
		return false
	}
}

var elementSizes = map[uint8]int{
	1: 1, 2: 4, 3: 1, 4: 4, 5: 2, 6: 5, 7: 5, 8: 8,
	9: 3, 10: 6, 11: 3, 12: 6, 13: 5, 14: 8,
	15: 5, 16: 8, 17: 6, 18: 7, 19: 7, 20: 5, 21: 2,
	30: 8, 31: 8, 32: 9, 33: 12, 34: 10, 35: 10, 36: 12,
	37: 12, 38: 11, 39: 11, 40: 11,
	45: 1, 46: 1, 47: 1, 48: 3, 49: 3, 50: 5, 51: 4,
	58: 8, 59: 8, 60: 8, 61: 10, 62: 10, 63: 12, 64: 11,
	70:  1,
	100: 1, 101: 1, 102: 0, 103: 7, 104: 2, 105: 1, 106: 2, 107: 7,
	110: 3, 111: 3, 112: 5, 113: 1,
	120: 6, 121: 7, 122: 4, 123: 5, 124: 4, 126: 13,
}

var typeNames = map[uint8]string{
	1: "M_SP_NA_1", 2: "M_SP_TA_1", 3: "M_DP_NA_1", 4: "M_DP_TA_1",
	5: "M_ST_NA_1", 6: "M_ST_TA_1", 7: "M_BO_NA_1", 8: "M_BO_TA_1",
	9: "M_ME_NA_1", 10: "M_ME_TA_1", 11: "M_ME_NB_1", 12: "M_ME_TB_1",
	13: "M_ME_NC_1", 14: "M_ME_TC_1", 15: "M_IT_NA_1", 16: "M_IT_TA_1",
	17: "M_EP_TA_1", 18: "M_EP_TB_1", 19: "M_EP_TC_1", 20: "M_PS_NA_1",
	21: "M_ME_ND_1",
	30: "M_SP_TB_1", 31: "M_DP_TB_1", 32: "M_ST_TB_1", 33: "M_BO_TB_1",
	34: "M_ME_TD_1", 35: "M_ME_TE_1", 36: "M_ME_TF_1", 37: "M_IT_TB_1",
	38: "M_EP_TD_1", 39: "M_EP_TE_1", 40: "M_EP_TF_1",
	45: "C_SC_NA_1", 46: "C_DC_NA_1", 47: "C_RC_NA_1", 48: "C_SE_NA_1",
	49: "C_SE_NB_1", 50: "C_SE_NC_1", 51: "C_BO_NA_1",
	58: "C_SC_TA_1", 59: "C_DC_TA_1", 60: "C_RC_TA_1", 61: "C_SE_TA_1",
	62: "C_SE_TB_1", 63: "C_SE_TC_1", 64: "C_BO_TA_1",
	70:  "M_EI_NA_1",
	100: "C_IC_NA_1", 101: "C_CI_NA_1", 102: "C_RD_NA_1", 103: "C_CS_NA_1",
	104: "C_TS_NA_1", 105: "C_RP_NA_1", 106: "C_CD_NA_1", 107: "C_TS_TA_1",
	110: "P_ME_NA_1", 111: "P_ME_NB_1", 112: "P_ME_NC_1", 113: "P_AC_NA_1",
	120: "F_FR_NA_1", 121: "F_SR_NA_1", 122: "F_SC_NA_1", 123: "F_LS_NA_1",
	124: "F_AF_NA_1", 125: "F_SG_NA_1", 126: "F_DR_TA_1", 127: "F_SC_NB_1",
}

var (
	// ErrShortASDU means fewer than six ASDU header octets were available.
	ErrShortASDU = errors.New("iec104: short asdu")
	// ErrTruncatedASDU means a declared information object is incomplete.
	ErrTruncatedASDU = errors.New("iec104: truncated asdu")
	// ErrTrailingASDU means bytes remain after the declared objects.
	ErrTrailingASDU = errors.New("iec104: trailing asdu bytes")
)
