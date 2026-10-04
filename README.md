# netguard

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Go 1.25](https://img.shields.io/badge/Go-1.25-00ADD8.svg)

A `net.Dialer` `Control` hook that refuses to connect to any address that is not a
public unicast address — loopback, RFC 1918 / ULA, link-local (including 169.254.169.254
cloud metadata), carrier-grade NAT / VPN overlay ranges, multicast and the reserved /
documentation blocks. Install it on every HTTP transport a crawler uses and a page that
links to an internal address (or a hostname that resolves to one) is never fetched — SSRF
closed at dial time, after DNS, on every redirect hop.

```go
d := &net.Dialer{Control: netguard.Control}
// ... Transport{DialContext: d.DialContext}
netguard.PublicIP("169.254.169.254") // false
```

`netguard.AllowNonPublic` exists only for tests (fake servers on 127.0.0.1). Stdlib only.

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

## Configuration

None — this is a library with no knobs, by design. There is deliberately no way
to switch the guard off in production.

## Related repositories

- [crawler-node](../crawler-node) — the crawler that installs this hook on every transport (vendored as `netguard/`).
- [robotstxt](../robotstxt) — the robots.txt parser the crawler obeys.
- [botid](../botid) — the crawler's bot identity.

Tests: `go test -race ./...`. MIT licensed.
