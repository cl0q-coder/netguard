// Q1 (Track Q): SSRF fuzz/property hardening for the netguard guard.
//
// These tests never touch prod code (netguard code changes are RED-tier).
// They pin three properties:
//
//  1. The optimized Public fast path (first-octet/hextet lookup tables +
//     precomputed net/mask pairs) can never disagree with the naive,
//     obviously-correct reading of the reserved list.
//  2. Exotic IP literal spellings (decimal/octal/hex) of non-public
//     addresses can never yield an allowed dial.
//  3. The Control dial hook is stateless per attempt: a DNS-rebound
//     hostname is re-checked on every dial, so a private rebind is
//     refused even after a public first resolution (and vice versa).
package netguard

import (
	"errors"
	"net"
	"net/netip"
	"testing"
)

// referencePublic (the naive, obviously-correct oracle: stdlib predicates
// plus a linear Prefix.Contains scan of the reserved list) lives in
// scan_diff_test.go and is reused here. The prod fast path is an
// optimization of exactly that; the fuzz test below proves the
// optimization never changes a verdict.

// FuzzPublicMatchesReference proves the optimized Public implementation
// agrees with the naive reference oracle on arbitrary addresses. Any drift
// between the lookup tables / precomputed masks and the reserved list they
// are derived from fails loudly here.
func FuzzPublicMatchesReference(f *testing.F) {
	seeds := []string{
		"1.1.1.1", "8.8.8.8", // ordinary public
		"127.0.0.1", "10.0.0.0", "10.255.255.255", "172.16.0.0", "172.31.255.255",
		"192.168.0.0", "192.168.255.255", // private boundaries
		"0.0.0.0", "255.255.255.255", "224.0.0.0", "239.255.255.255", // v4 edges
		"100.63.255.255", "100.64.0.0", "100.127.255.255", "100.128.0.0", // CGNAT edges
		"169.253.255.255", "169.254.0.0", "169.254.255.255", "169.255.0.0", // link-local edges
		"192.0.1.255", "192.0.2.0", "192.0.2.255", "192.0.3.0", // TEST-NET-1 edges
		"::1", "::", "::ffff:1.1.1.1", "::ffff:127.0.0.1",
		"::ffff:0:10.0.0.1", "::ffff:0:1.1.1.1", // SIIT spellings
		"::10.0.0.1", "::1.1.1.1", // IPv4-compatible spellings
		"::0:5efe:10.0.0.1", "::0:5efe:8.8.8.8", // ISATAP spellings
		"64:ff9b::a9fe:a9fe", "64:ff9b::101:101", // NAT64, private + public embedded
		"2001::1", "2001:db8::1", "2002:a00:1::1", "2002:808:808::1", // Teredo/doc/6to4
		"fe80::1", "fc00::1", "ff02::1",
	}
	for _, s := range seeds {
		a := netip.MustParseAddr(s)
		raw := a.As16()
		f.Add(raw[:])
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) != 16 {
			return
		}
		var b16 [16]byte
		copy(b16[:], raw)
		b4 := [4]byte{b16[0], b16[1], b16[2], b16[3]}
		addrs := []netip.Addr{
			netip.AddrFrom16(b16),
			netip.AddrFrom4(b4),
			// Zoned variants: the zone strip must not change the verdict
			// relative to the oracle (P0-class bypass if it ever did).
			netip.AddrFrom16(b16).WithZone("eth0"),
			netip.AddrFrom4(b4).WithZone("eth0"),
		}
		for _, a := range addrs {
			if got, want := Public(a), referencePublic(a); got != want {
				t.Fatalf("Public(%s) = %v, reference oracle = %v", a, got, want)
			}
		}
	})
}

// TestPublicReferenceAgreement runs a fixed, deterministic sample of the
// address space through both implementations so the property holds even in
// CI jobs that don't run the fuzzer.
func TestPublicReferenceAgreement(t *testing.T) {
	// Deterministic xorshift64* over the full 32-bit space.
	state := uint64(0x123456789abcdef)
	next := func() uint64 {
		state ^= state >> 12
		state ^= state << 25
		state ^= state >> 27
		return state * 0x2545F4914F6CDD1D
	}
	for i := 0; i < 20000; i++ {
		x := uint32(next() >> 32)
		a := netip.AddrFrom4([4]byte{byte(x >> 24), byte(x >> 16), byte(x >> 8), byte(x)})
		if got, want := Public(a), referencePublic(a); got != want {
			t.Fatalf("Public(%s) = %v, reference oracle = %v", a, got, want)
		}
	}
}

// TestExoticLiteralFormsNeverDial proves that non-standard IP spellings of
// non-public addresses (decimal/octal/hex — the classic SSRF bypass
// alphabet) can never produce an allowed dial: either resolution fails
// closed (no dial happens) or the resolved address is refused by Control.
func TestExoticLiteralFormsNeverDial(t *testing.T) {
	allowNonPublic.Store(false)
	// All of these are spellings of 127.0.0.1 in resolvers that accept them.
	forms := []string{
		"2130706433",       // decimal
		"0177.0.0.1",       // octal first quad
		"0177.0.0.01",      // octal throughout
		"0x7f.0.0.1",       // hex first quad
		"0x7f000001",       // hex packed
		"0x7F.0x0.0x0.0x1", // hex throughout
		"127.0x0.0x1",      // mixed
	}
	for _, form := range forms {
		ip, err := net.ResolveIPAddr("ip", form)
		if err != nil {
			// Failed closed at resolution: no dial, nothing to bypass.
			continue
		}
		addr := net.JoinHostPort(ip.String(), "80")
		if derr := Control("tcp", addr, nil); !errors.Is(derr, ErrNotPublic) {
			t.Errorf("exotic literal %q resolved to %s and was NOT refused", form, ip)
		}
	}
}

// TestControlDNSRebindStateless proves the dial hook re-checks the freshly
// resolved address on every attempt with no verdict caching: a hostname
// that rebinds from public to private (TTL-0 attacker DNS) is refused on
// the rebound attempt, and a rebind back to public is allowed again.
// Redirect hops dial anew, so they get the same per-attempt check.
func TestControlDNSRebindStateless(t *testing.T) {
	allowNonPublic.Store(false)
	// First resolution: public — dial proceeds.
	if err := Control("tcp", "93.184.215.14:80", nil); err != nil {
		t.Fatalf("public first resolution must be allowed, got %v", err)
	}
	// Attacker rebinds the name to cloud metadata — must be refused.
	if err := Control("tcp", "169.254.169.254:80", nil); !errors.Is(err, ErrNotPublic) {
		t.Fatalf("rebound private resolution must be refused, got %v", err)
	}
	// Rebind back to public — allowed again; no refusal is cached.
	if err := Control("tcp", "93.184.215.14:80", nil); err != nil {
		t.Fatalf("public re-resolution must be allowed again, got %v", err)
	}
	// Same for the IPv6 embedded bypass spellings on rebind.
	for _, s := range []string{"::ffff:0:169.254.169.254", "::0:5efe:10.0.0.1", "::10.0.0.1"} {
		a := netip.MustParseAddr(s)
		if err := Control("tcp", net.JoinHostPort(a.String(), "80"), nil); !errors.Is(err, ErrNotPublic) {
			t.Errorf("rebound embedded-private %s must be refused", s)
		}
	}
}

// TestControlRefusesReservedPrefixBoundaries walks every reserved prefix and
// asserts Control refuses its first, middle, and last address: the lookup
// tables cover each prefix's full span, not just interior samples.
func TestControlRefusesReservedPrefixBoundaries(t *testing.T) {
	allowNonPublic.Store(false)
	for _, s := range reservedPrefixes {
		p := netip.MustParsePrefix(s)
		addrs := []netip.Addr{p.Addr()}
		if last := prefixLast(p); last.IsValid() {
			addrs = append(addrs, last)
		}
		if mid := prefixMid(p); mid.IsValid() {
			addrs = append(addrs, mid)
		}
		for _, a := range addrs {
			addr := net.JoinHostPort(a.String(), "443")
			if err := Control("tcp", addr, nil); !errors.Is(err, ErrNotPublic) {
				t.Errorf("Control allowed %s inside reserved %s", a, p)
			}
		}
	}
}

// prefixLast returns the last address of p. prefixMid returns an interior
// address (network + 1 where the prefix is narrower than the address).
func prefixLast(p netip.Prefix) netip.Addr {
	if p.Addr().Is4() {
		b := p.Masked().Addr().As4()
		hostBits := 32 - p.Bits()
		ip := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		ip |= ^uint32(0) >> (32 - hostBits)
		return netip.AddrFrom4([4]byte{byte(ip >> 24), byte(ip >> 16), byte(ip >> 8), byte(ip)})
	}
	b := p.Masked().Addr().As16()
	var out [16]byte
	copy(out[:], b[:])
	for i := p.Bits(); i < 128; i++ {
		out[i/8] |= 1 << (7 - (i % 8))
	}
	return netip.AddrFrom16(out)
}

func prefixMid(p netip.Prefix) netip.Addr {
	if p.Addr().Is4() {
		b := p.Masked().Addr().As4()
		ip := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		if p.Bits() < 32 {
			ip |= 1 // network+1 stays inside unless /32
		}
		return netip.AddrFrom4([4]byte{byte(ip >> 24), byte(ip >> 16), byte(ip >> 8), byte(ip)})
	}
	b := p.Masked().Addr().As16()
	var out [16]byte
	copy(out[:], b[:])
	if p.Bits() < 128 {
		out[15] |= 1
	}
	a := netip.AddrFrom16(out)
	if !p.Contains(a) {
		return netip.Addr{} // invalid marker: skip
	}
	return a
}
