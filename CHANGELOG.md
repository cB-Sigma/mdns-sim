# Changelog

## v0.2.0 (2026-10-11)

For testing mdns v0.2.0. The API only grows; code written for v0.1 builds
unchanged.

### Added

- `Config.NoTXT`: a device with no TXT record.
- `Config.NSEC`: answers questions for the types a device lacks with NSEC
  (RFC 6762 clause 6.1) and adds that NSEC to PTR answers; written with
  dnsmessage, not with the mdns module's encoder.
- `Device.Announce`: multicast every record now, without probing, to stage
  a conflict after probing.
- `Device.Vanish`: stop without a goodbye.
- `Device.Asked`: questions received, by type.
- Command flags `-no-txt` and `-nsec`.
- Integration tests of mdns v0.2.0 (sim/rfc6762_integration_test.go): an
  announcer renames after a late conflict, a browser stops asking for TXT
  after NSEC, a Watcher drops a device that vanished once other hosts'
  queries go unanswered.

## v0.1.x

First published releases; see the repository history.
