# Provenance

## How the code was written

Written in Go for SigmaM2M, a oneM2M platform, as the test peer of the
mdns module. No code was ported or copied from another implementation.
The simulator lived inside the mdns module until 2026-10-11 and was moved
into this module so that the library does not depend on it; the browse
and watch tests that use it moved with it.

The three answer styles reproduce behaviour observed, not code read: how
hashicorp/mdns, grandcat/zeroconf and devices on a LAN (a cast receiver, a
media receiver, a Spotify desktop responder) answer queries, as compared
on 2026-10-06 (see the mdns module's README). The packets are built with
golang.org/x/net/dns/dnsmessage rather than the mdns module's encoder, so
tests that use the simulator do not only check that the module agrees with
itself.

Added in v0.2.0 (2026-10-11), from the RFCs: devices without a TXT
record, NSEC answers (written with their own encoder, not the mdns
module's), on-demand announcements for staging a conflict after probing,
devices that vanish without a goodbye, and per-type question counts.

`internal/reuse` is the same code as the mdns module's `internal/reuse`
(setting SO_REUSEADDR and SO_REUSEPORT). It is copied because Go does not
allow an internal package to be imported from another module.

## Sources

| Area (files) | Followed |
|---|---|
| Records and answers (sim/sim.go) | RFC 6762 clauses 5.1, 6, 6.1, 6.7, 8.3, 9, 10.1; RFC 6763 clauses 4, 6; RFC 4034 clause 4 for the NSEC record |
| Message format | RFC 1035, through golang.org/x/net/dns/dnsmessage |

No RFC text is included; comments cite clause numbers in our own words.

## Test data

Instance names, host names, ports, TXT values and addresses in the code,
tests and command defaults are made up.
