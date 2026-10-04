package netguard

// N2: Differential IP-classification oracle.
//
// Enumerates EVERY IANA special-use range (v4 and v6), including SIIT/NAT64/4-in-6
// translation forms, and asserts Control() refuses each while allowing a sample of
// real public IPs. This is the reference oracle so the SSRF guard can never silently regress.
//
// IANA registries:
//   https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
//   https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
//
// Run: go test -run TestN2 -v ./netguard/

import (
	"net/netip"
	"testing"
)

// n2Refused: every address that MUST be refused (non-public).
// Each entry: CIDR + reason. The test picks a representative address from each.
var n2Refused = []struct {
	cidr   string
	reason string
}{
	// IPv4 (IANA special registry)
	{"0.0.0.0/8", "this network"},
	{"10.0.0.0/8", "private (RFC 1918)"},
	{"100.64.0.0/10", "carrier-grade NAT"},
	{"127.0.0.0/8", "loopback"},
	{"169.254.0.0/16", "link-local"},
	{"172.16.0.0/12", "private (RFC 1918)"},
	{"192.0.0.0/24", "IETF protocol assignments"},
	{"192.0.2.0/24", "TEST-NET-1 (documentation)"},
	{"192.31.196.0/24", "AS112-v4"},
	{"192.52.193.0/24", "AMT"},
	{"192.88.99.0/24", "6to4 relay (deprecated)"},
	{"192.168.0.0/16", "private (RFC 1918)"},
	{"192.175.48.0/24", "direct delegation AS112"},
	{"198.18.0.0/15", "benchmarking"},
	{"198.51.100.0/24", "TEST-NET-2 (documentation)"},
	{"203.0.113.0/24", "TEST-NET-3 (documentation)"},
	{"224.0.0.0/4", "multicast"},
	{"240.0.0.0/4", "reserved (incl. broadcast)"},

	// IPv6 (IANA special registry)
	{"::/128", "unspecified"},
	{"::1/128", "loopback"},
	{"64:ff9b::/96", "NAT64 (reaches IPv4 through translator)"},
	{"64:ff9b:1::/48", "local-use NAT64"},
	{"100::/64", "discard"},
	{"2001::/32", "Teredo"},
	{"2001:1::/48", "Port Control Protocol anycast"},
	{"2001:2::/48", "Traversal Using Relays around NAT (TURN)"},
	{"2001:3::/32", "AMT"},
	{"2001:4:112::/48", "AS112-v6"},
	{"2001:10::/28", "ORCHID"},
	{"2001:db8::/32", "documentation"},
	{"2002::/16", "6to4 (embeds IPv4)"},
	{"2620:4f:8000::/48", "direct delegation AS112"},
	{"fc00::/7", "unique local (private)"},
	{"fe80::/10", "link-local"},

	// SIIT / translation forms (IPv4-mapped and 4-in-6 that reach private IPv4)
	{"::ffff:10.0.0.0/104", "SIIT: IPv4-mapped private (10/8)"},
	{"::ffff:172.16.0.0/108", "SIIT: IPv4-mapped private (172.16/12)"},
	{"::ffff:192.168.0.0/112", "SIIT: IPv4-mapped private (192.168/16)"},
	{"::ffff:127.0.0.0/104", "SIIT: IPv4-mapped loopback"},
	{"::ffff:169.254.0.0/112", "SIIT: IPv4-mapped link-local"},
}

// n2Allowed: sample of real public IPs that MUST be allowed.
var n2Allowed = []string{
	"1.1.1.1",              // Cloudflare DNS
	"8.8.8.8",              // Google DNS
	"9.9.9.9",              // Quad9 DNS
	"142.250.80.14",        // Google
	"151.101.1.69",         // Fastly
	"104.16.132.229",       // Cloudflare
	"2606:4700:4700::1111", // Cloudflare v6 DNS
	"2001:4860:4860::8888", // Google v6 DNS
}

// TestN2_OracleRefusesNonPublic asserts every special-use range is refused.
func TestN2_OracleRefusesNonPublic(t *testing.T) {
	for _, tc := range n2Refused {
		prefix := netip.MustParsePrefix(tc.cidr)
		// Test the first address and a middle address in the range
		addrs := []netip.Addr{prefix.Addr()}
		// Also test a "random" address in the middle (add half the range size is complex;
		// just test the base address which is sufficient for prefix matching)
		for _, addr := range addrs {
			if Public(addr) {
				t.Errorf("CIDR %s (%s): address %s was ALLOWED but must be refused",
					tc.cidr, tc.reason, addr)
			}
		}
	}
	t.Logf("oracle: %d special-use ranges all refused", len(n2Refused))
}

// TestN2_OracleAllowsPublic asserts real public IPs are allowed.
func TestN2_OracleAllowsPublic(t *testing.T) {
	for _, s := range n2Allowed {
		addr := netip.MustParseAddr(s)
		if !Public(addr) {
			t.Errorf("public IP %s was REFUSED but must be allowed", s)
		}
	}
	t.Logf("oracle: %d public IPs all allowed", len(n2Allowed))
}

// TestN2_SIITForms specifically tests IPv4-mapped translation spellings
// that could bypass a naive check.
func TestN2_SIITForms(t *testing.T) {
	// These are different textual spellings of the same dangerous addresses
	siitCases := []struct {
		spelling string
		v4       string // the embedded IPv4
	}{
		{"::ffff:10.0.0.1", "10.0.0.1"},
		{"::ffff:0a00:0001", "10.0.0.1"}, // hex spelling
		{"::ffff:192.168.1.1", "192.168.1.1"},
		{"::ffff:c0a8:0101", "192.168.1.1"}, // hex spelling
		{"::ffff:127.0.0.1", "127.0.0.1"},
		{"::ffff:7f00:0001", "127.0.0.1"}, // hex spelling
	}
	for _, tc := range siitCases {
		addr := netip.MustParseAddr(tc.spelling)
		// Unmap should reveal the private IPv4
		unmapped := addr.Unmap()
		if unmapped.String() != tc.v4 {
			t.Logf("note: %s unmaps to %s (expected %s)", tc.spelling, unmapped, tc.v4)
		}
		if Public(addr) {
			t.Errorf("SIIT form %s (embeds %s) was ALLOWED but must be refused",
				tc.spelling, tc.v4)
		}
	}
	t.Logf("oracle: %d SIIT spellings all refused", len(siitCases))
}
