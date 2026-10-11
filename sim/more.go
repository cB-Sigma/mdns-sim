// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package sim

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func (d *Device) subName(sub string) string {
	return strings.TrimSuffix(sub, ".") + "._sub." + d.typeName()
}

// subRR is the PTR of a subtype name to the instance (RFC 6763 7.1).
func (d *Device) subRR(sub string) func(*dnsmessage.Builder, uint32) error {
	return func(b *dnsmessage.Builder, ttl uint32) error {
		h, err := d.hdr(d.subName(sub), ttl, false)
		if err != nil {
			return err
		}
		t, err := dnsmessage.NewName(d.instName())
		if err != nil {
			return err
		}
		return b.PTRResource(h, dnsmessage.PTRResource{PTR: t})
	}
}

// metaRR answers the service type enumeration (RFC 6763 9).
func (d *Device) metaRR(b *dnsmessage.Builder, ttl uint32) error {
	h, err := d.hdr("_services._dns-sd._udp.local.", ttl, false)
	if err != nil {
		return err
	}
	t, err := dnsmessage.NewName(d.typeName())
	if err != nil {
		return err
	}
	return b.PTRResource(h, dnsmessage.PTRResource{PTR: t})
}

// domainRRs answer the browse domain enumeration (RFC 6763 11).
func (d *Device) domainRRs(b *dnsmessage.Builder, ttl uint32) error {
	for _, dom := range d.cfg.Domains {
		h, err := d.hdr("b._dns-sd._udp.local.", ttl, false)
		if err != nil {
			return err
		}
		if !strings.HasSuffix(dom, ".") {
			dom += "."
		}
		t, err := dnsmessage.NewName(dom)
		if err != nil {
			return err
		}
		if err := b.PTRResource(h, dnsmessage.PTRResource{PTR: t}); err != nil {
			return err
		}
	}
	return nil
}

func (d *Device) aaaaRR(b *dnsmessage.Builder, ttl uint32) error {
	h, err := d.hdr(d.hostName(), ttl, true)
	if err != nil {
		return err
	}
	var a [16]byte
	copy(a[:], d.cfg.IPv6.To16())
	return b.AAAAResource(h, dnsmessage.AAAAResource{AAAA: a})
}

// probeHit is what the reader saw while probing: a response holding the
// name (conflict) or another host's probe that wins the tie-break (lost).
type probeHit int

const (
	hitConflict probeHit = iota + 1
	hitLost
)

// probe claims the instance name (RFC 6762 8.1): three probes 250 ms
// apart after a random wait under 250 ms; a conflict renames and starts
// again, a lost tie-break (8.2) waits a second and starts again. It gives
// up after 15 conflicts.
func (d *Device) probe(ctx context.Context) error {
	d.probing.Store(true)
	defer d.probing.Store(false)
	base, n := d.Instance(), 1
	for attempts := 0; attempts < 16; attempts++ {
		// Drain what an earlier round saw.
		for len(d.probeHit) > 0 {
			<-d.probeHit
		}
		select {
		case <-time.After(time.Duration(time.Now().UnixNano()%250) * time.Millisecond):
		case <-ctx.Done():
			return ctx.Err()
		}
		hit := probeHit(0)
		for i := 0; i < 3 && hit == 0; i++ {
			d.sendProbe()
			select {
			case hit = <-d.probeHit:
			case <-time.After(250 * time.Millisecond):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		switch hit {
		case 0:
			return nil
		case hitConflict:
			n++
			d.nameMu.Lock()
			d.instance = fmt.Sprintf("%s (%d)", base, n)
			d.nameMu.Unlock()
		case hitLost:
			select {
			case <-time.After(time.Second):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return fmt.Errorf("sim: no free name for %q after 15 conflicts", base)
}

// sendProbe multicasts a probe for the instance name: an ANY question
// with the proposed SRV and TXT records in the authority section.
func (d *Device) sendProbe() {
	name, err := dnsmessage.NewName(d.instName())
	if err != nil {
		return
	}
	ttl := uint32(d.cfg.TTL / time.Second)
	b := dnsmessage.NewBuilder(make([]byte, 0, 512), dnsmessage.Header{})
	b.EnableCompression()
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeALL, Class: dnsmessage.ClassINET})
	_ = b.StartAuthorities()
	for _, f := range d.authority() {
		_ = f(&b, ttl)
	}
	pkt, err := b.Finish()
	if err != nil {
		return
	}
	_, _ = d.p.WriteTo(pkt, nil, &net.UDPAddr{IP: group, Port: d.port})
}

func (d *Device) authority() []func(*dnsmessage.Builder, uint32) error {
	recs := []func(*dnsmessage.Builder, uint32) error{d.srvRR}
	if !d.cfg.NoTXT {
		recs = append(recs, d.txtRR)
	}
	return recs
}

// inspect looks at a packet received while probing.
func (d *Device) inspect(pkt []byte) {
	var p dnsmessage.Parser
	h, err := p.Start(pkt)
	if err != nil {
		return
	}
	mine := strings.ToLower(d.instName())
	qs, err := p.AllQuestions()
	if err != nil {
		return
	}
	if h.Response {
		answers, _ := p.AllAnswers()
		_ = p.SkipAllAuthorities()
		adds, _ := p.AllAdditionals()
		for _, r := range append(answers, adds...) {
			if strings.ToLower(r.Header.Name.String()) == mine && (r.Header.Type == dnsmessage.TypeSRV || r.Header.Type == dnsmessage.TypeTXT) {
				d.hit(hitConflict)
				return
			}
		}
		return
	}
	asks := false
	for _, q := range qs {
		asks = asks || strings.ToLower(q.Name.String()) == mine
	}
	if !asks {
		return
	}
	_ = p.SkipAllAnswers()
	auth, err := p.AllAuthorities()
	if err != nil || len(auth) == 0 {
		return
	}
	var theirs []dnsmessage.Resource
	for _, r := range auth {
		if strings.ToLower(r.Header.Name.String()) == mine {
			theirs = append(theirs, r)
		}
	}
	if len(theirs) == 0 {
		return
	}
	if compareSets(d.ownAuthority(), canonical(theirs)) < 0 {
		d.hit(hitLost)
	}
}

func (d *Device) hit(h probeHit) {
	select {
	case d.probeHit <- h:
	default:
	}
}

// ownAuthority is this device's probe authority records in canonical
// form, parsed back from what sendProbe writes.
func (d *Device) ownAuthority() [][]byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{})
	_ = b.StartAuthorities()
	for _, f := range d.authority() {
		_ = f(&b, 120)
	}
	pkt, err := b.Finish()
	if err != nil {
		return nil
	}
	var p dnsmessage.Parser
	if _, err := p.Start(pkt); err != nil {
		return nil
	}
	_ = p.SkipAllQuestions()
	_ = p.SkipAllAnswers()
	auth, _ := p.AllAuthorities()
	return canonical(auth)
}

// canonical writes records as class, type and uncompressed rdata, sorted,
// for the lexicographic comparison of RFC 6762 8.2.
func canonical(rs []dnsmessage.Resource) [][]byte {
	var out [][]byte
	for _, r := range rs {
		var x []byte
		x = binary.BigEndian.AppendUint16(x, uint16(r.Header.Class)&0x7fff)
		x = binary.BigEndian.AppendUint16(x, uint16(r.Header.Type))
		switch v := r.Body.(type) {
		case *dnsmessage.SRVResource:
			x = binary.BigEndian.AppendUint16(x, v.Priority)
			x = binary.BigEndian.AppendUint16(x, v.Weight)
			x = binary.BigEndian.AppendUint16(x, v.Port)
			x = appendName(x, v.Target.String())
		case *dnsmessage.TXTResource:
			for _, s := range v.TXT {
				x = append(x, byte(len(s)))
				x = append(x, s...)
			}
		case *dnsmessage.AResource:
			x = append(x, v.A[:]...)
		case *dnsmessage.AAAAResource:
			x = append(x, v.AAAA[:]...)
		}
		out = append(out, x)
	}
	sortBytes(out)
	return out
}

func appendName(x []byte, name string) []byte {
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		x = append(x, byte(len(l)))
		x = append(x, strings.ToLower(l)...)
	}
	return append(x, 0)
}

func sortBytes(s [][]byte) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && bytes.Compare(s[j], s[j-1]) < 0; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// compareSets compares two sorted record sets record by record; the set
// that runs out first is the lesser (RFC 6762 8.2).
func compareSets(a, b [][]byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if c := bytes.Compare(a[i], b[i]); c != 0 {
			return c
		}
	}
	return len(a) - len(b)
}
