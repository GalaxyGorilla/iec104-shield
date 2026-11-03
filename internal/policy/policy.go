// Package policy implements the front-leg access rules for the IEC-104
// gateway: a client IP allow-list and a command policy scoped by ASDU type,
// common address, information-object address and select/execute.
package policy

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/GalaxyGorilla/iec104-shield/internal/iec104"
)

// Rule is one command-policy rule. An empty Types, CommonAddress, IOA range
// or Select matches everything in that dimension.
type Rule struct {
	Types         []uint8
	CommonAddress *uint16
	IOAFrom       *uint32
	IOATo         *uint32
	Select        *bool
	Allow         bool
}

// Policy is a compiled command policy. A nil *Policy allows every write.
type Policy struct {
	readOnly     bool
	defaultAllow bool
	rules        []Rule
}

// New compiles a command policy. readOnly and rules are mutually exclusive:
// read_only is the coarse switch, rules are the fine-grained form.
func New(readOnly, defaultAllow bool, rules []Rule) (*Policy, error) {
	if readOnly && len(rules) > 0 {
		return nil, errors.New("policy: read_only and command rules are mutually exclusive")
	}
	for i, r := range rules {
		for _, t := range r.Types {
			if t == 0 {
				return nil, fmt.Errorf("policy: rule %d: type 0 is not valid", i)
			}
		}
		if (r.IOAFrom == nil) != (r.IOATo == nil) {
			return nil, fmt.Errorf("policy: rule %d: ioa from/to must be set together", i)
		}
		if r.IOAFrom != nil {
			if *r.IOAFrom > *r.IOATo {
				return nil, fmt.Errorf("policy: rule %d: ioa from must be <= to", i)
			}
			if *r.IOATo > 0xffffff {
				return nil, fmt.Errorf("policy: rule %d: ioa outside 0..16777215", i)
			}
		}
	}
	return &Policy{readOnly: readOnly, defaultAllow: defaultAllow, rules: rules}, nil
}

// ReadOnly reports whether the coarse read-only switch is set.
func (p *Policy) ReadOnly() bool { return p != nil && p.readOnly }

// DefaultAllow reports the verdict for writes no rule matches.
func (p *Policy) DefaultAllow() bool { return p != nil && p.defaultAllow }

// Len returns the number of rules.
func (p *Policy) Len() int {
	if p == nil {
		return 0
	}
	return len(p.rules)
}

// Allowed reports whether the ASDU may cross the proxy. Non-write types are
// always allowed. A write is allowed when no deny rule matches and either an
// allow rule matches or the default is allow. A malformed command (no parsed
// object where an address is required) is denied by a range-scoped rule; the
// proxy itself rejects an unparseable ASDU before calling this method.
func (p *Policy) Allowed(a iec104.ASDU) bool {
	if p == nil {
		return true
	}
	if !iec104.IsWrite(a.TypeID) {
		return true
	}
	if p.readOnly {
		return false
	}
	allowed := false
	for _, r := range p.rules {
		if !matchesType(r.Types, a.TypeID) {
			continue
		}
		if r.CommonAddress != nil && *r.CommonAddress != a.CommonAddr {
			continue
		}
		if r.Select != nil && iec104.Select(a) != *r.Select {
			continue
		}
		if r.IOAFrom != nil && !matchesIOA(a, *r.IOAFrom, *r.IOATo, r.Allow) {
			continue
		}
		if !r.Allow {
			return false // deny overrides
		}
		allowed = true
	}
	return allowed || p.defaultAllow
}

// matchesIOA applies the allow-must-cover / deny-on-intersection rule. A
// range-scoped rule cannot authorize a command that carries no information
// object address (interrogation, clock sync, file transfer).
func matchesIOA(a iec104.ASDU, from, to uint32, allow bool) bool {
	if len(a.Objects) == 0 {
		return false
	}
	if allow {
		for _, o := range a.Objects {
			if o.IOA < from || o.IOA > to {
				return false
			}
		}
		return true
	}
	for _, o := range a.Objects {
		if o.IOA >= from && o.IOA <= to {
			return true
		}
	}
	return false
}

func matchesType(types []uint8, t uint8) bool {
	if len(types) == 0 {
		return true
	}
	for _, v := range types {
		if v == t {
			return true
		}
	}
	return false
}

// List is a client IP allow-list. A nil *List allows every client.
type List struct {
	mu    sync.RWMutex
	ips   []net.IP
	cidrs []*net.IPNet
}

// NewList parses allow-list entries (bare IPs or CIDR ranges).
func NewList(entries []string) (*List, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	l := &List{}
	for _, e := range entries {
		if ip := net.ParseIP(e); ip != nil {
			l.ips = append(l.ips, ip)
			continue
		}
		_, cidr, err := net.ParseCIDR(e)
		if err != nil {
			return nil, err
		}
		l.cidrs = append(l.cidrs, cidr)
	}
	return l, nil
}

// Allowed reports whether ip passes the allow-list.
func (l *List) Allowed(ip net.IP) bool {
	if l == nil {
		return true
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, allowed := range l.ips {
		if allowed.Equal(ip) {
			return true
		}
	}
	for _, cidr := range l.cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}
