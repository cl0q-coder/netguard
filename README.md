# netguard

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Go 1.25](https://img.shields.io/badge/Go-1.25-00ADD8.svg)

A `net.Dialer` `Control` hook that refuses to connect to any address that is not a
public unicast address — loopback, RFC 1918 / ULA, link-local (including 169.254.169.254
cloud metadata), carrier-grade NAT / VPN overlay ranges, multicast and the reserved /
documentation blocks. Install it on every HTTP transport a crawler uses and a page that
links to an internal address (or a hostname that resolves to one) is never fetched — SSRF
closed at dial time, after DNS, on every redirect hop.

## Installation

```bash
go get cl0q/netguard
```

Requires Go 1.25+. Standard library only, no external dependencies.

## Quick start

```bash
go test -race ./...
go build ./...
```

## How it works

One file (`netguard.go`), stdlib only:

- `netguard.Control` is a `net.Dialer.Control` hook: it resolves the dial
  address and refuses anything that isn't a public unicast IP, closing SSRF at
  dial time — after DNS, on every redirect hop.
- `netguard.PublicIP(s)` is the predicate the hook uses, exposed for tests and
  pre-flight checks.
- `netguard.AllowNonPublic` is a test-only escape hatch for fake servers on
  127.0.0.1. There is no flag or environment variable for it; it can only be
  flipped in-process by test code.

## Usage

```go
import (
    "cl0q/netguard"
    "net"
    "net/http"
)

// Install on your HTTP transport
d := &net.Dialer{Control: netguard.Control}
transport := &http.Transport{
    DialContext: d.DialContext,
}
client := &http.Client{Transport: transport}

// Now every connection is SSRF-guarded:
// - http://169.254.169.254/ → refused (cloud metadata)
// - http://127.0.0.1/ → refused (loopback)
// - http://10.0.0.1/ → refused (private)
// - https://example.com/ → allowed (public)
```

### Checking addresses directly

```go
netguard.PublicIP("169.254.169.254") // false
netguard.PublicIP("8.8.8.8")         // true

addr := netip.MustParseAddr("10.0.0.1")
netguard.Public(addr) // false
```

## API Reference

### `Control(network, address string, _ syscall.RawConn) error`

A `net.Dialer` Control hook. Returns `ErrNotPublic` if the address is not a public
unicast IP. Install via `net.Dialer{Control: netguard.Control}`.

### `Public(a netip.Addr) bool`

Reports whether the address is a public unicast address safe to connect to.
Returns false for loopback, private, link-local, multicast, reserved, and all
IANA special-use ranges (including SIIT/NAT64 translation forms).

### `PublicIP(s string) bool`

Like `Public` but parses the string first. Returns false on parse error.

### `AllowNonPublic`

Package-level bool, default false. When true, `Control` allows all addresses.
**For tests only** (e.g., fake servers on 127.0.0.1). Never set in production.

## Coverage

The guard covers all IANA IPv4 and IPv6 special-use registries, including:
- RFC 1918 private, loopback, link-local, multicast
- Carrier-grade NAT (100.64.0.0/10), benchmarking (198.18.0.0/15)
- Documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32)
- NAT64 (64:ff9b::/96), Teredo (2001::/32), 6to4 (2002::/16)
- SIIT IPv4-mapped forms (::ffff:10.0.0.0/104, etc.)

See `iana_test.go` for the complete oracle.

## Configuration

None — this is a library with no knobs, by design. There is deliberately no way
to switch the guard off in production.

## Testing

```bash
go test ./...
go test -race ./...
```

## Contributing

Pull requests welcome. If you find a bypass (an address that should be refused but isn't),
please report it as a security issue.

## Related repositories

- [crawler-node](../crawler-node) — the crawler that installs this hook on every transport (vendored as `netguard/`).
- [robotstxt](../robotstxt) — the robots.txt parser the crawler obeys.
- [botid](../botid) — the crawler's bot identity.

## License

MIT. See `LICENSE`.
