# netguard

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

Tests: `go test -race ./...`
