# mdns-sim

Simulated multicast DNS / DNS-SD devices in each answer style found on real networks, as a Go package and a command.

[![Go Reference](https://pkg.go.dev/badge/github.com/cB-Sigma/mdns-sim.svg)](https://pkg.go.dev/github.com/cB-Sigma/mdns-sim) [![test](https://github.com/cB-Sigma/mdns-sim/actions/workflows/test.yml/badge.svg)](https://github.com/cB-Sigma/mdns-sim/actions/workflows/test.yml) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.27.1-00ADD8.svg)](go.mod)

It is the test peer of [mdns](https://github.com/cB-Sigma/mdns), and can be
used to try any mDNS browser (dns-sd, avahi-browse, another library)
against responders that answer in different ways. The packets are built
with golang.org/x/net/dns/dnsmessage, not with the mdns module's encoder.

## What is simulated

Each device advertises one service instance (PTR, SRV, TXT and A records)
in one of three styles:

| Style | Flag value | Answers queries | Announces | Behaves like |
|---|---|---|---|---|
| `Legacy` | `legacy` | by unicast to the query's source address and port only | no | hashicorp/mdns, some cast receivers |
| `Multicast` | `multicast` | by multicast to the group only; ignores one-shot queries | on start; goodbye on Close | the Go zeroconf forks, some media receivers |
| `AnnounceOnly` | `announce` | never | on start, every `Repeat`, after `SetTXT`; goodbye on Close | a device that reports state changes in its TXT record |

A browser that queries only from the mDNS port misses `Legacy` where the
operating system's responder also holds port 5353; one that sends only
one-shot queries from an ephemeral port never hears `Multicast`.

Any style can also:

| Config or method | Does | Tests with it |
|---|---|---|
| `Config.NoTXT` | no TXT record at all | browsers that wait for a TXT record |
| `Config.NSEC` | answers questions for the types it lacks with NSEC (RFC 6762 clause 6.1), and adds that NSEC to PTR answers | browsers that read NSEC |
| `Device.Announce` | multicasts every record now, without probing | a conflict after probing: a `Multicast` device with the same instance name as a running responder |
| `Device.Vanish` | stops without a goodbye | passive observation of failures, reconfirmation |
| `Device.Asked` | counts the questions received, by type | what a browser asks for |

| `Config.IPv6` | an AAAA record beside the A record (answered, announced, in additionals; NSEC lists it) | browsers that collect IPv6 addresses |
| `Config.Subtypes` | subtype PTRs (RFC 6763 7.1), answered and announced | subtype browsing |
| `Config.ServiceTypes` | answers the service type enumeration (RFC 6763 9) | type enumeration |
| `Config.Domains` | answers the browse domain enumeration (RFC 6763 11) | domain enumeration |
| `Config.Probe` | probes for the instance name before announcing (RFC 6762 8.1), renames to "<name> (2)" on a conflict, and waits a second after losing a simultaneous-probe tie-break (8.2); `Device.Instance` | responders that defend a name, tie-breaking |

Not simulated: the IPv6 transport (devices talk over IPv4; the mdns
module's interop tests run IPv6-only networks against python-zeroconf),
truncated known-answer trains and rate limits as a peer.

## Install

```
go get github.com/cB-Sigma/mdns-sim@latest
go install github.com/cB-Sigma/mdns-sim/cmd/mdnssim@latest
```

Requires Go 1.27.1 or later.

## Command

`mdnssim` starts one device per style asked for and runs until interrupted.

| Flag | Default | Meaning |
|---|---|---|
| `-style` | `legacy,multicast` | answer styles, comma separated: `legacy`, `multicast`, `announce` |
| `-type` | `_sigmasim._tcp` | DNS-SD service type |
| `-instance` | `SigmaM2M sim` | instance name; the style is added in brackets |
| `-host` | `sigmasim` | host label; the style is added |
| `-port` | `8080` | service port |
| `-txt` | `model=sim` | TXT records, `key=value` pairs separated by commas |
| `-ip` | the interface's | IPv4 address in the A record |
| `-iface` | the first multicast-capable one with IPv4 | interface name |
| `-mdns-port` | `5353` | multicast DNS port |
| `-loopback` | false | multicast loopback, so a browser on this host hears the devices; allows the loopback interface |
| `-ttl` | `2m0s` | TTL of every record |
| `-repeat` | `0` | interval of the `announce` style's announcements (0: at start only) |
| `-no-txt` | false | no TXT record |
| `-nsec` | false | answer questions for missing record types with NSEC |
| `-ip6` | none | IPv6 address for an AAAA record |
| `-subtypes` | none | subtype labels, comma separated |
| `-types` | false | answer the service type enumeration |
| `-domains` | none | browse domains to answer, comma separated |
| `-probe` | false | probe for the instance name first (multicast and announce styles) |

On port 5353, next to the operating system's responder, and then browse
with the system tools:

```
mdnssim -style legacy,multicast -type _sigmasim._tcp
dns-sd -B _sigmasim._tcp          # macOS; avahi-browse _sigmasim._tcp on Linux
```

On a test port on the loopback interface, so nothing reaches the LAN
(output observed on macOS):

```
$ mdnssim -style legacy,multicast,announce -type _demo._tcp -loopback -mdns-port 15353
mdnssim: "SigmaM2M sim (legacy)" (legacy) as _demo._tcp on lo0, mDNS port 15353
mdnssim: "SigmaM2M sim (multicast)" (multicast) as _demo._tcp on lo0, mDNS port 15353
mdnssim: "SigmaM2M sim (announce)" (announce) as _demo._tcp on lo0, mDNS port 15353
```

## In Go tests

```go
import (
	"github.com/cB-Sigma/mdns"
	"github.com/cB-Sigma/mdns-sim/sim"
)

ifi, _ := mdns.TestInterface(port) // an interface on which multicast loops back
d, err := sim.Start(ctx, sim.Config{Style: sim.Legacy, Type: "_sigmasim._tcp",
	Instance: "legacy device", Host: "legacy-dev", Port: 8080,
	MDNSPort: port, Interface: ifi, Loopback: true, TXT: map[string]string{"id": "x"}})
if err != nil {
	t.Fatal(err)
}
defer d.Close()

found, err := mdns.Browse(ctx, "_sigmasim._tcp", mdns.Options{
	Interfaces: []net.Interface{*ifi}, Port: port, Loopback: true, Wait: 2 * time.Second})
```

This mirrors `TestBrowseFindsEveryAnswerStyle` in
sim/browse_integration_test.go; `sim.Example` shows the same on the real
port. `Device.Queries` counts the queries a device answered, and
`Device.SetTXT` changes its TXT record (announced at once by the
`announce` style).

## Documentation

API reference: https://pkg.go.dev/github.com/cB-Sigma/mdns-sim

| Package | What it does |
|---|---|
| `sim` | `Start` a `Device` from a `Config` in one `Style`; `ParseStyle`, `DefaultInterface` |
| `cmd/mdnssim` | the command above |
| `internal/reuse` | SO_REUSEADDR and SO_REUSEPORT, so the devices share the mDNS port with the operating system's responder |

## Testing

```
go test -race ./...
```

The tests use multicast on a random port and skip when no interface loops
multicast back to the host, or with `-short`. sim/browse_integration_test.go
holds the mdns module's browse and watch tests against each style, and
sim/rfc6762_integration_test.go its v0.2.0 tests (a conflict after
probing, NSEC, a device that vanishes); they live here so the library
does not depend on its simulator. Tests carry `// Covers: SIG-...`
comments: these are requirement IDs of the SigmaM2M project's compliance
report and have no meaning outside it.

## Demo values

Every instance name, host name, port, TXT value and address in this module
is a made-up demo value. There are no keys or credentials.

## Related repositories

- [mdns](https://github.com/cB-Sigma/mdns): the responder and browser this
  simulator tests.

## Status

v0.x: the API may change before v1.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability privately.

## Licence

Apache-2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). Copyright 2026
Abhinav Gautam.
