// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package sim_test

import (
	"context"
	"math/rand/v2"
	"net"
	"strconv"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"

	"github.com/cB-Sigma/mdns"
	"github.com/cB-Sigma/mdns-sim/internal/reuse"
	"github.com/cB-Sigma/mdns-sim/sim"
)

var group = net.IPv4(224, 0, 0, 251)

// query packs a PTR question for typ with the given ID.
func query(t *testing.T, id uint16, typ string) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(typ + ".local."), Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET})
	p, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// responses reads DNS responses on c until d passes.
func responses(c net.PacketConn, d time.Duration) []dnsmessage.Header {
	var out []dnsmessage.Header
	_ = c.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, 9000)
	for {
		n, _, err := c.ReadFrom(buf)
		if err != nil {
			return out
		}
		var p dnsmessage.Parser
		if h, err := p.Start(buf[:n]); err == nil && h.Response {
			out = append(out, h)
		}
	}
}

// Each style answers the way it says: a one-shot query from an ephemeral
// port gets a unicast reply with its ID from the legacy device only; the
// multicast device answers on the group; the announce-only device answers
// nothing but announces.
// Covers: SIG-IPE-7352
func TestStyles(t *testing.T) {
	if testing.Short() {
		t.Skip("uses multicast; skipped with -short")
	}
	port := 20000 + rand.IntN(30000)
	ifi, err := mdns.TestInterface(port)
	if err != nil {
		t.Skip(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// A listener on the group sees multicast answers and announcements.
	lc := net.ListenConfig{Control: reuse.Control}
	gc, err := lc.ListenPacket(ctx, "udp4", "0.0.0.0:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	defer gc.Close()
	if err := ipv4.NewPacketConn(gc).JoinGroup(ifi, &net.UDPAddr{IP: group}); err != nil {
		t.Fatal(err)
	}
	for _, st := range []sim.Style{sim.Legacy, sim.Multicast, sim.AnnounceOnly} {
		t.Run(st.String(), func(t *testing.T) {
			typ := "_" + st.String() + "sim._tcp"
			responses(gc, 100*time.Millisecond) // drain
			d, err := sim.Start(ctx, sim.Config{Style: st, Type: typ, Instance: "dev", Host: "dev", Port: 1, MDNSPort: port, Interface: ifi, Loopback: true})
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			announced := len(responses(gc, 300*time.Millisecond))
			oc, err := net.ListenPacket("udp4", "0.0.0.0:0")
			if err != nil {
				t.Fatal(err)
			}
			defer oc.Close()
			op := ipv4.NewPacketConn(oc)
			_ = op.SetMulticastInterface(ifi)
			_ = op.SetMulticastLoopback(true)
			if _, err := op.WriteTo(query(t, 0x4242, typ), nil, &net.UDPAddr{IP: group, Port: port}); err != nil {
				t.Fatal(err)
			}
			uni := responses(oc, 500*time.Millisecond)
			multi := responses(gc, 100*time.Millisecond)
			switch st {
			case sim.Legacy:
				if announced != 0 || len(uni) != 1 || uni[0].ID != 0x4242 || len(multi) != 0 || d.Queries() != 1 {
					t.Errorf("announced %d, unicast %+v, multicast %d, queries %d", announced, uni, len(multi), d.Queries())
				}
			case sim.Multicast:
				if announced != 1 || len(uni) != 0 || len(multi) != 1 || d.Queries() != 1 {
					t.Errorf("announced %d, unicast %d, multicast %d, queries %d", announced, len(uni), len(multi), d.Queries())
				}
			case sim.AnnounceOnly:
				if announced != 1 || len(uni) != 0 || len(multi) != 0 || d.Queries() != 0 {
					t.Errorf("announced %d, unicast %d, multicast %d, queries %d", announced, len(uni), len(multi), d.Queries())
				}
			}
		})
	}
}

// A device without TXT and with NSEC answers a TXT question with an NSEC
// record listing only SRV, counts the question, and vanishes without a
// goodbye.
// Covers: SIG-IPE-7340
func TestNSECAndVanish(t *testing.T) {
	if testing.Short() {
		t.Skip("uses multicast; skipped with -short")
	}
	port := 20000 + rand.IntN(30000)
	ifi, err := mdns.TestInterface(port)
	if err != nil {
		t.Skip(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	lc := net.ListenConfig{Control: reuse.Control}
	gc, err := lc.ListenPacket(ctx, "udp4", "0.0.0.0:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	defer gc.Close()
	gp := ipv4.NewPacketConn(gc)
	if err := gp.JoinGroup(ifi, &net.UDPAddr{IP: group}); err != nil {
		t.Fatal(err)
	}
	_ = gp.SetMulticastInterface(ifi)
	_ = gp.SetMulticastLoopback(true)
	d, err := sim.Start(ctx, sim.Config{Style: sim.Multicast, Type: "_ns._tcp", Instance: "dev", Host: "dev", Port: 1, MDNSPort: port, Interface: ifi, Loopback: true, NoTXT: true, NSEC: true})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	responses(gc, 200*time.Millisecond) // the announcement
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("dev._ns._tcp.local."), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET})
	q, _ := b.Finish()
	if _, err := gp.WriteTo(q, nil, &net.UDPAddr{IP: group, Port: port}); err != nil {
		t.Fatal(err)
	}
	_ = gc.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 9000)
	found := false
	for !found {
		n, _, err := gc.ReadFrom(buf)
		if err != nil {
			break
		}
		var p dnsmessage.Parser
		if h, err := p.Start(buf[:n]); err != nil || !h.Response {
			continue
		}
		_ = p.SkipAllQuestions()
		ans, _ := p.AllAnswers()
		for _, r := range ans {
			if u, ok := r.Body.(*dnsmessage.UnknownResource); ok && r.Header.Type == 47 {
				// Next name, then window 0, length 5, bit for SRV (33).
				want := append([]byte("\x03dev\x03_ns\x04_tcp\x05local\x00"), 0, 5, 0, 0, 0, 0, 0x40)
				if string(u.Data) != string(want) {
					t.Fatalf("NSEC rdata % x", u.Data)
				}
				found = true
			}
		}
	}
	if !found {
		t.Fatal("no NSEC answer")
	}
	if d.Asked(dnsmessage.TypeTXT) != 1 {
		t.Fatalf("asked %d", d.Asked(dnsmessage.TypeTXT))
	}
	if err := d.Vanish(); err != nil {
		t.Fatal(err)
	}
	if got := responses(gc, 300*time.Millisecond); len(got) != 0 {
		t.Fatalf("vanished device sent %d responses", len(got))
	}
}

// Covers: SIG-IPE-7352
func TestConfigChecks(t *testing.T) {
	ifi := &net.Interface{Name: "x"}
	for _, c := range []sim.Config{{}, {Style: sim.Legacy, Type: "_a._tcp", Instance: "i", Host: "h"}, {Style: 9, Interface: ifi}, {Style: sim.Legacy, Interface: ifi}} {
		if d, err := sim.Start(context.Background(), c); err == nil {
			_ = d.Close()
			t.Errorf("%+v accepted", c)
		}
	}
	if _, err := sim.ParseStyle("loud"); err == nil {
		t.Error("ParseStyle accepted loud")
	}
	if st, _ := sim.ParseStyle("Announce"); st != sim.AnnounceOnly {
		t.Errorf("ParseStyle(Announce) = %v", st)
	}
}

// Example runs a device that only answers one-shot queries by unicast and
// one that only answers by multicast, and finds both with one browse.
func Example() {
	ctx := context.Background()
	ifi, _ := sim.DefaultInterface(false)
	for _, st := range []sim.Style{sim.Legacy, sim.Multicast} {
		d, err := sim.Start(ctx, sim.Config{Style: st, Type: "_sigmasim._tcp", Instance: "demo " + st.String(), Host: "demo-" + st.String(),
			Port: 8080, Interface: ifi})
		if err != nil {
			return
		}
		defer d.Close()
	}
	found, _ := mdns.Browse(ctx, "_sigmasim._tcp", mdns.Options{Wait: 2 * time.Second})
	_ = found // both instances
}
