// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package sim runs simulated mDNS/DNS-SD devices for tests and demos. Each
// simulated device advertises one service instance in one of the answer
// styles found on real networks:
//
//   - Legacy answers every query by unicast to the address and port the
//     query came from, and never multicasts or announces (the way
//     hashicorp/mdns and some cast receivers behave). A browser that
//     queries only from port 5353 misses it where the operating system's
//     responder also holds 5353, because the unicast reply reaches only one
//     of the sockets bound there.
//   - Multicast answers by multicast to the group only, announces itself
//     on start and says goodbye on Close (the way the Go zeroconf forks and
//     some media receivers behave). A browser that only sends one-shot
//     queries from an ephemeral port never hears it.
//   - AnnounceOnly answers nothing; it sends unsolicited announcements on
//     start, every Repeat and after SetTXT, and a goodbye on Close (a
//     device that reports state changes in its TXT record).
//
// A device can also lack a TXT record (Config.NoTXT), answer with NSEC
// records for the types it lacks (Config.NSEC), announce again on demand
// (Device.Announce: two Multicast devices with one instance name make a
// conflict after probing, since neither probes) and disappear without a
// goodbye (Device.Vanish). Device.Asked counts the questions it received
// by type.
//
// The packets are built with golang.org/x/net/dns/dnsmessage, not with the
// mdns package's own encoder, so the tests that use the simulator do not
// only check that the package agrees with itself. IPv4 only.
package sim

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"

	"github.com/cB-Sigma/mdns-sim/internal/reuse"
)

// Style is how a simulated device answers.
type Style int

// The answer styles; see the package documentation.
const (
	Legacy Style = iota + 1
	Multicast
	AnnounceOnly
)

func (s Style) String() string {
	switch s {
	case Legacy:
		return "legacy"
	case Multicast:
		return "multicast"
	case AnnounceOnly:
		return "announce"
	}
	return "style(" + strconv.Itoa(int(s)) + ")"
}

// ParseStyle reads "legacy", "multicast" or "announce".
func ParseStyle(s string) (Style, error) {
	for _, st := range []Style{Legacy, Multicast, AnnounceOnly} {
		if strings.EqualFold(s, st.String()) {
			return st, nil
		}
	}
	return 0, fmt.Errorf("sim: style %q is not legacy, multicast or announce", s)
}

var group = net.IPv4(224, 0, 0, 251)

// Config describes one simulated device.
type Config struct {
	Style Style
	// Type is the service type, "_hue._tcp".
	Type string
	// Instance is the instance label, "Hue Bridge - 1A2B3C".
	Instance string
	// Host is the host label ("hue-1a2b3c"); ".local" is added.
	Host string
	// Port is the service's port.
	Port int
	// TXT is the TXT metadata.
	TXT map[string]string
	// IP is the address in the A record; the interface's first IPv4
	// address when nil.
	IP net.IP
	// TTL is the TTL of every record; 120 s when zero.
	TTL time.Duration
	// MDNSPort is the multicast DNS port; 5353 when zero.
	MDNSPort int
	// Interface is where the device listens and sends; required.
	Interface *net.Interface
	// Loopback turns on multicast loopback, so a browser in the same
	// process or on the same host hears the device.
	Loopback bool
	// Repeat is the interval of the AnnounceOnly style's announcements;
	// only at start (and after SetTXT) when zero.
	Repeat time.Duration
	// NoTXT gives the device no TXT record at all.
	NoTXT bool
	// NSEC makes the device answer questions for its instance and host
	// names about types it does not have with an NSEC record (RFC 6762
	// clause 6.1), and add that record to answers that leave the type
	// out (no TXT with a PTR answer, no AAAA with an A record).
	NSEC bool
}

// Device is a running simulated device.
type Device struct {
	cfg  Config
	c    net.PacketConn
	p    *ipv4.PacketConn
	ip   net.IP
	port int

	mu  sync.Mutex
	txt map[string]string

	queries atomic.Int64
	askMu   sync.Mutex
	asked   map[dnsmessage.Type]int
	silent  atomic.Bool
	done    chan struct{}
	wg      sync.WaitGroup
	once    sync.Once
}

// Start runs a device until Close or the end of ctx.
func Start(ctx context.Context, cfg Config) (*Device, error) {
	if cfg.Style < Legacy || cfg.Style > AnnounceOnly {
		return nil, fmt.Errorf("sim: unknown style %d", cfg.Style)
	}
	if cfg.Interface == nil {
		return nil, errors.New("sim: Config.Interface is required")
	}
	if cfg.Type == "" || cfg.Instance == "" || cfg.Host == "" {
		return nil, errors.New("sim: Type, Instance and Host are required")
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 120 * time.Second
	}
	d := &Device{cfg: cfg, port: cfg.MDNSPort, txt: cfg.TXT, asked: map[dnsmessage.Type]int{}, done: make(chan struct{})}
	if d.port == 0 {
		d.port = 5353
	}
	d.ip = cfg.IP.To4()
	if d.ip == nil {
		addrs, err := cfg.Interface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
				d.ip = n.IP.To4()
				break
			}
		}
		if d.ip == nil {
			return nil, fmt.Errorf("sim: %s has no IPv4 address", cfg.Interface.Name)
		}
	}
	lc := net.ListenConfig{Control: reuse.Control}
	c, err := lc.ListenPacket(ctx, "udp4", net.JoinHostPort("0.0.0.0", strconv.Itoa(d.port)))
	if err != nil {
		return nil, fmt.Errorf("sim: listen on %d: %w", d.port, err)
	}
	p := ipv4.NewPacketConn(c)
	if err := p.JoinGroup(cfg.Interface, &net.UDPAddr{IP: group}); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("sim: join on %s: %w", cfg.Interface.Name, err)
	}
	_ = p.SetMulticastInterface(cfg.Interface)
	_ = p.SetMulticastTTL(255)
	_ = p.SetMulticastLoopback(cfg.Loopback)
	d.c, d.p = c, p

	d.wg.Add(1)
	go d.read()
	if cfg.Style != Legacy {
		d.announce(false)
	}
	if cfg.Style == AnnounceOnly && cfg.Repeat > 0 {
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			t := time.NewTicker(cfg.Repeat)
			defer t.Stop()
			for {
				select {
				case <-d.done:
					return
				case <-t.C:
					d.announce(false)
				}
			}
		}()
	}
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		select {
		case <-ctx.Done():
			go func() { _ = d.Close() }()
		case <-d.done:
		}
	}()
	return d, nil
}

// Queries is the number of queries for the device's names it has answered.
func (d *Device) Queries() int { return int(d.queries.Load()) }

// Asked is the number of questions of type t for the device's names
// (service type, instance or host) it has received.
func (d *Device) Asked(t dnsmessage.Type) int {
	d.askMu.Lock()
	defer d.askMu.Unlock()
	return d.asked[t]
}

// Announce multicasts every record now (not for the Legacy style). Two
// Multicast devices with the same instance name started one after the
// other make a late conflict: neither probes.
func (d *Device) Announce() {
	if d.cfg.Style != Legacy && !d.silent.Load() {
		d.announce(false)
	}
}

// Vanish stops the device without a goodbye, like a device that loses
// power: caches keep its records until they expire or are found stale.
func (d *Device) Vanish() error {
	d.silent.Store(true)
	return d.Close()
}

// SetTXT changes the TXT metadata; the Multicast and AnnounceOnly styles
// announce the change at once.
func (d *Device) SetTXT(txt map[string]string) {
	d.mu.Lock()
	d.txt = txt
	d.mu.Unlock()
	if d.cfg.Style != Legacy {
		d.announce(false)
	}
}

// Close sends a goodbye (Multicast and AnnounceOnly styles) and stops.
func (d *Device) Close() error {
	var err error
	d.once.Do(func() {
		if d.cfg.Style != Legacy && !d.silent.Load() {
			d.announce(true)
		}
		close(d.done)
		err = d.c.Close()
		d.wg.Wait()
	})
	return err
}

func (d *Device) typeName() string { return strings.TrimSuffix(d.cfg.Type, ".") + ".local." }
func (d *Device) instName() string { return d.cfg.Instance + "." + d.typeName() }
func (d *Device) hostName() string { return d.cfg.Host + ".local." }

func (d *Device) read() {
	defer d.wg.Done()
	buf := make([]byte, 9000)
	for {
		n, _, src, err := d.p.ReadFrom(buf)
		if err != nil {
			select {
			case <-d.done:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if d.cfg.Style == AnnounceOnly {
			continue
		}
		udp, ok := src.(*net.UDPAddr)
		if !ok {
			continue
		}
		d.handle(buf[:n], udp)
	}
}

// handle answers one query.
func (d *Device) handle(pkt []byte, src *net.UDPAddr) {
	var p dnsmessage.Parser
	h, err := p.Start(pkt)
	if err != nil || h.Response {
		return
	}
	qs, err := p.AllQuestions()
	if err != nil {
		return
	}
	ptr, srv, txt, a := false, false, false, false
	nsecInst, nsecHost := false, false
	hasTXT := !d.cfg.NoTXT
	for _, q := range qs {
		name := strings.ToLower(q.Name.String())
		switch {
		case name == strings.ToLower(d.typeName()):
			d.ask(q.Type)
			ptr = ptr || q.Type == dnsmessage.TypePTR || q.Type == dnsmessage.TypeALL
		case name == strings.ToLower(d.instName()):
			d.ask(q.Type)
			srv = srv || q.Type == dnsmessage.TypeSRV || q.Type == dnsmessage.TypeALL
			txt = txt || hasTXT && (q.Type == dnsmessage.TypeTXT || q.Type == dnsmessage.TypeALL)
			nsecInst = nsecInst || d.cfg.NSEC && q.Type != dnsmessage.TypeSRV && q.Type != dnsmessage.TypeALL && (q.Type != dnsmessage.TypeTXT || !hasTXT)
		case name == strings.ToLower(d.hostName()):
			d.ask(q.Type)
			a = a || q.Type == dnsmessage.TypeA || q.Type == dnsmessage.TypeALL
			nsecHost = nsecHost || d.cfg.NSEC && q.Type != dnsmessage.TypeA && q.Type != dnsmessage.TypeALL
		}
	}
	if !ptr && !srv && !txt && !a && !nsecInst && !nsecHost {
		return
	}
	d.queries.Add(1)
	var ans, add []func(*dnsmessage.Builder, uint32) error
	if ptr {
		ans = append(ans, d.ptrRR)
		add = append(add, d.srvRR)
		if hasTXT {
			add = append(add, d.txtRR)
		} else if d.cfg.NSEC {
			add = append(add, d.nsecInstRR)
		}
		add = append(add, d.aRR)
		if d.cfg.NSEC {
			add = append(add, d.nsecHostRR)
		}
	}
	if srv {
		ans = append(ans, d.srvRR)
	}
	if txt {
		ans = append(ans, d.txtRR)
	}
	if nsecInst {
		ans = append(ans, d.nsecInstRR)
	}
	if a {
		ans = append(ans, d.aRR)
	}
	if nsecHost {
		ans = append(ans, d.nsecHostRR)
	}
	hdr := dnsmessage.Header{Response: true, Authoritative: true}
	var echo []dnsmessage.Question
	if d.cfg.Style == Legacy {
		hdr.ID = h.ID
		for _, q := range qs {
			q.Class &^= 0x8000
			echo = append(echo, q)
		}
	}
	b, err := d.build(hdr, echo, ans, add, false)
	if err != nil {
		return
	}
	if d.cfg.Style == Legacy {
		_, _ = d.p.WriteTo(b, nil, src)
		return
	}
	_, _ = d.p.WriteTo(b, nil, &net.UDPAddr{IP: group, Port: d.port})
}

func (d *Device) ask(t dnsmessage.Type) {
	d.askMu.Lock()
	d.asked[t]++
	d.askMu.Unlock()
}

// announce multicasts every record (goodbye: with TTL 0).
func (d *Device) announce(goodbye bool) {
	recs := []func(*dnsmessage.Builder, uint32) error{d.ptrRR, d.srvRR}
	if !d.cfg.NoTXT {
		recs = append(recs, d.txtRR)
	}
	recs = append(recs, d.aRR)
	b, err := d.build(dnsmessage.Header{Response: true, Authoritative: true}, nil, recs, nil, goodbye)
	if err != nil {
		return
	}
	_, _ = d.p.WriteTo(b, nil, &net.UDPAddr{IP: group, Port: d.port})
}

func (d *Device) build(h dnsmessage.Header, qs []dnsmessage.Question, ans, add []func(*dnsmessage.Builder, uint32) error, goodbye bool) ([]byte, error) {
	ttl := uint32(d.cfg.TTL / time.Second)
	if goodbye {
		ttl = 0
	}
	b := dnsmessage.NewBuilder(make([]byte, 0, 512), h)
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	for _, q := range qs {
		if err := b.Question(q); err != nil {
			return nil, err
		}
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	for _, f := range ans {
		if err := f(&b, ttl); err != nil {
			return nil, err
		}
	}
	if err := b.StartAdditionals(); err != nil {
		return nil, err
	}
	for _, f := range add {
		if err := f(&b, ttl); err != nil {
			return nil, err
		}
	}
	return b.Finish()
}

func (d *Device) hdr(name string, ttl uint32, flush bool) (dnsmessage.ResourceHeader, error) {
	n, err := dnsmessage.NewName(name)
	class := dnsmessage.ClassINET
	if flush && d.cfg.Style != Legacy {
		class |= 0x8000
	}
	return dnsmessage.ResourceHeader{Name: n, Class: class, TTL: ttl}, err
}

func (d *Device) ptrRR(b *dnsmessage.Builder, ttl uint32) error {
	h, err := d.hdr(d.typeName(), ttl, false)
	if err != nil {
		return err
	}
	t, err := dnsmessage.NewName(d.instName())
	if err != nil {
		return err
	}
	return b.PTRResource(h, dnsmessage.PTRResource{PTR: t})
}

func (d *Device) srvRR(b *dnsmessage.Builder, ttl uint32) error {
	h, err := d.hdr(d.instName(), ttl, true)
	if err != nil {
		return err
	}
	t, err := dnsmessage.NewName(d.hostName())
	if err != nil {
		return err
	}
	return b.SRVResource(h, dnsmessage.SRVResource{Target: t, Port: uint16(d.cfg.Port)})
}

func (d *Device) txtRR(b *dnsmessage.Builder, ttl uint32) error {
	h, err := d.hdr(d.instName(), ttl, true)
	if err != nil {
		return err
	}
	d.mu.Lock()
	keys := make([]string, 0, len(d.txt))
	for k := range d.txt {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	strs := make([]string, 0, len(keys))
	for _, k := range keys {
		strs = append(strs, k+"="+d.txt[k])
	}
	d.mu.Unlock()
	if len(strs) == 0 {
		strs = []string{""}
	}
	return b.TXTResource(h, dnsmessage.TXTResource{TXT: strs})
}

func (d *Device) aRR(b *dnsmessage.Builder, ttl uint32) error {
	h, err := d.hdr(d.hostName(), ttl, true)
	if err != nil {
		return err
	}
	var a [4]byte
	copy(a[:], d.ip)
	return b.AResource(h, dnsmessage.AResource{A: a})
}

// nsecInstRR says the instance has an SRV record and, unless NoTXT, a TXT
// record; nsecHostRR says the host has only an A record.
func (d *Device) nsecInstRR(b *dnsmessage.Builder, ttl uint32) error {
	types := []uint16{uint16(dnsmessage.TypeSRV)}
	if !d.cfg.NoTXT {
		types = append(types, uint16(dnsmessage.TypeTXT))
	}
	return d.nsecRR(b, ttl, d.instName(), types)
}

func (d *Device) nsecHostRR(b *dnsmessage.Builder, ttl uint32) error {
	return d.nsecRR(b, ttl, d.hostName(), []uint16{uint16(dnsmessage.TypeA)})
}

// nsecRR writes an NSEC record in the restricted form of RFC 6762 clause
// 6.1: the next domain name is the record's own name, written out, and
// one bitmap window covers types below 256.
func (d *Device) nsecRR(b *dnsmessage.Builder, ttl uint32, name string, types []uint16) error {
	h, err := d.hdr(name, ttl, true)
	if err != nil {
		return err
	}
	var data []byte
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		data = append(data, byte(len(l)))
		data = append(data, l...)
	}
	data = append(data, 0)
	var bits [32]byte
	n := 0
	for _, t := range types {
		bits[t/8] |= 0x80 >> (t % 8)
		n = max(n, int(t/8)+1)
	}
	data = append(data, 0, byte(n))
	data = append(data, bits[:n]...)
	return b.UnknownResource(h, dnsmessage.UnknownResource{Type: 47, Data: data})
}

// DefaultInterface picks an interface for a device: the first one that is
// up, multicast-capable, not point-to-point and has an IPv4 address, the
// loopback interface only when loopback is set (and then first).
func DefaultInterface(loopback bool) (*net.Interface, error) {
	all, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var pick *net.Interface
	for i := range all {
		ifi := all[i]
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagMulticast == 0 || ifi.Flags&net.FlagPointToPoint != 0 {
			continue
		}
		isLo := ifi.Flags&net.FlagLoopback != 0
		if isLo && !loopback {
			continue
		}
		addrs, _ := ifi.Addrs()
		has4 := false
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
				has4 = true
			}
		}
		if !has4 {
			continue
		}
		if isLo {
			return &ifi, nil
		}
		if pick == nil {
			pick = &ifi
		}
	}
	if pick == nil {
		return nil, errors.New("sim: no up, multicast-capable interface with an IPv4 address")
	}
	return pick, nil
}
