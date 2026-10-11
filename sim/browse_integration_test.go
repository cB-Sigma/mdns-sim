// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package sim_test

// Integration tests of github.com/cB-Sigma/mdns against the simulated
// devices: browsing and watching each answer style over real multicast
// sockets on a random port. They moved here from the library so that the
// library never imports its simulator.

import (
	"context"
	"math/rand/v2"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/mdns"

	"github.com/cB-Sigma/mdns-sim/sim"
)

// testPort picks a random port for a test's mDNS traffic and an interface
// on which multicast comes back to this host, or skips.
func testPort(t *testing.T) (int, *net.Interface) {
	t.Helper()
	if testing.Short() {
		t.Skip("uses multicast; skipped with -short")
	}
	port := 20000 + rand.IntN(30000)
	ifi, err := mdns.TestInterface(port)
	if err != nil {
		t.Skipf("%v", err)
	}
	return port, ifi
}

func startSim(t *testing.T, ctx context.Context, cfg sim.Config) *sim.Device {
	t.Helper()
	d, err := sim.Start(ctx, cfg)
	if err != nil {
		t.Fatalf("sim %s: %v", cfg.Instance, err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func instances(list []mdns.Service) map[string]mdns.Service {
	out := map[string]mdns.Service{}
	for _, s := range list {
		out[s.Instance] = s
	}
	return out
}

// events collects a Watcher's events for a test.
type events struct {
	mu   sync.Mutex
	list []mdns.Event
	ch   chan mdns.Event
}

func newEvents() *events { return &events{ch: make(chan mdns.Event, 64)} }

func (e *events) add(ev mdns.Event) {
	e.mu.Lock()
	e.list = append(e.list, ev)
	e.mu.Unlock()
	select {
	case e.ch <- ev:
	default:
	}
}

func (e *events) all() []mdns.Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]mdns.Event(nil), e.list...)
}

// wait returns the first event (from now on) that match accepts.
func (e *events) wait(t *testing.T, d time.Duration, what string, match func(mdns.Event) bool) mdns.Event {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case ev := <-e.ch:
			if match(ev) {
				return ev
			}
		case <-deadline:
			t.Fatalf("no %s within %v; events so far %+v", what, d, e.all())
			return mdns.Event{}
		}
	}
}

// TestBrowseFindsEveryAnswerStyle: a default Browse finds a responder that
// answers only by unicast to the query's source (hashicorp/mdns style, a
// cast receiver on the LAN) and one that answers only by multicast and
// ignores one-shot queries (the zeroconf forks, a media receiver on the
// LAN) in the same browse (RFC 6762 clauses 5.1, 5.2 and 6.7).
//
// Covers: SIG-IPE-6420
func TestBrowseFindsEveryAnswerStyle(t *testing.T) {
	port, ifi := testPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const typ = "_sigmasim._tcp"
	base := sim.Config{Type: typ, Port: 8080, MDNSPort: port, Interface: ifi, Loopback: true, TXT: map[string]string{"id": "x"}}
	leg := base
	leg.Style, leg.Instance, leg.Host = sim.Legacy, "legacy device", "legacy-dev"
	mc := base
	mc.Style, mc.Instance, mc.Host = sim.Multicast, "multicast device", "multicast-dev"
	startSim(t, ctx, leg)
	startSim(t, ctx, mc)

	got, err := mdns.Browse(ctx, typ, mdns.Options{Interfaces: []net.Interface{*ifi}, Port: port, Loopback: true, Wait: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	found := instances(got)
	for _, want := range []string{"legacy device", "multicast device"} {
		s, ok := found[want]
		if !ok {
			t.Errorf("default Browse on %s port %d missed %q; found %+v", ifi.Name, port, want, got)
			continue
		}
		if s.Port != 8080 || s.TXT["id"] != "x" || len(s.IPs) == 0 {
			t.Errorf("%q resolved as %+v", want, s)
		}
	}
}

// TestWatchFollowsAnnouncements: a device that answers no query and only
// announces (on start, on a TXT change, a goodbye when it stops) is
// followed by a Watcher from what it hears on the mDNS port: added,
// updated with the new TXT, removed on the goodbye (RFC 6762 clauses 8.3,
// 8.4, 10.1 and 10.2).
//
// Covers: SIG-IPE-6421
func TestWatchFollowsAnnouncements(t *testing.T) {
	port, ifi := testPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const typ = "_ewsim._tcp"
	ev := newEvents()
	w, err := mdns.Watch(ctx, []string{typ}, mdns.Options{Interfaces: []net.Interface{*ifi}, Port: port, Loopback: true, Wait: time.Second}, ev.add)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	d := startSim(t, ctx, sim.Config{Style: sim.AnnounceOnly, Type: typ, Instance: "eWeLink_1000aabbcc", Host: "plug-1000aabbcc",
		Port: 8081, TXT: map[string]string{"id": "1000aabbcc", "seq": "1", "data1": `{"switch":"off"}`}, MDNSPort: port, Interface: ifi, Loopback: true})
	added := ev.wait(t, 5*time.Second, "added event", func(e mdns.Event) bool { return e.Kind == mdns.Added })
	if added.Type != typ || added.Service.Instance != "eWeLink_1000aabbcc" || added.Service.TXT["seq"] != "1" || added.Service.Port != 8081 {
		t.Fatalf("added %+v", added)
	}
	if d.Queries() != 0 {
		t.Fatalf("the announce-only device answered %d queries", d.Queries())
	}
	if got := w.Services(typ); len(got) != 1 || got[0].TXT["data1"] != `{"switch":"off"}` {
		t.Fatalf("Services %+v", got)
	}

	d.SetTXT(map[string]string{"id": "1000aabbcc", "seq": "2", "data1": `{"switch":"on"}`})
	up := ev.wait(t, 5*time.Second, "updated event", func(e mdns.Event) bool { return e.Kind == mdns.Updated })
	if up.Service.TXT["seq"] != "2" || up.Service.TXT["data1"] != `{"switch":"on"}` {
		t.Fatalf("updated %+v", up)
	}

	_ = d.Close()
	gone := ev.wait(t, 5*time.Second, "removed event", func(e mdns.Event) bool { return e.Kind == mdns.Removed })
	if gone.Service.Instance != "eWeLink_1000aabbcc" {
		t.Fatalf("removed %+v", gone)
	}
	if got := w.Services(typ); len(got) != 0 {
		t.Fatalf("after goodbye %+v", got)
	}
}

// TestWatchRefreshesBeforeExpiry: a device that only answers queries
// (unicast to the source, never announcing) with short TTLs stays known
// past the end of the opening query train, because the Watcher asks again
// before its records expire (RFC 6762 clause 5.2); when the device goes
// silent, its instance is removed once the records expire.
//
// Covers: SIG-IPE-6421
func TestWatchRefreshesBeforeExpiry(t *testing.T) {
	port, ifi := testPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	const typ = "_castsim._tcp"
	d := startSim(t, ctx, sim.Config{Style: sim.Legacy, Type: typ, Instance: "Living Room TV", Host: "tv-1", Port: 8009,
		TTL: 2 * time.Second, MDNSPort: port, Interface: ifi, Loopback: true})
	ev := newEvents()
	w, err := mdns.Watch(ctx, []string{typ}, mdns.Options{Interfaces: []net.Interface{*ifi}, Port: port, Loopback: true, Wait: time.Second}, ev.add)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	ev.wait(t, 3*time.Second, "added event", func(e mdns.Event) bool { return e.Kind == mdns.Added })
	select {
	case <-w.Settled():
	case <-time.After(3 * time.Second):
		t.Fatal("not settled")
	}
	// The opening train ends at 7 s and the next periodic query is 8 s
	// later; at 11 s only refreshes keep 2 s records alive.
	time.Sleep(11 * time.Second)
	if got := w.Services(typ); len(got) != 1 {
		t.Fatalf("after 11 s: %+v (events %+v)", got, ev.all())
	}
	for _, e := range ev.all() {
		if e.Kind == mdns.Removed {
			t.Fatalf("removed while the device still answers: %+v", ev.all())
		}
	}
	if d.Queries() < 6 {
		t.Errorf("device answered %d queries; refreshes expected", d.Queries())
	}
	_ = d.Close()
	ev.wait(t, 6*time.Second, "removed event after expiry", func(e mdns.Event) bool { return e.Kind == mdns.Removed })
}

// TestBrowseTypesOneSocketSet: several types are browsed with one socket
// set and one query train, each result under its own type; the same holds
// for a Watcher of several types.
//
// Covers: SIG-IPE-6421
func TestBrowseTypesOneSocketSet(t *testing.T) {
	port, ifi := testPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	types := []string{"_huesim._tcp", "_shellysim._tcp", "_nothing._tcp"}
	startSim(t, ctx, sim.Config{Style: sim.Legacy, Type: types[0], Instance: "Hue Bridge - 1A2B3C", Host: "hue-1a2b3c", Port: 443,
		TXT: map[string]string{"bridgeid": "001788fffe1a2b3c"}, MDNSPort: port, Interface: ifi, Loopback: true})
	startSim(t, ctx, sim.Config{Style: sim.Multicast, Type: types[1], Instance: "shellyplus1-a8032ab1", Host: "shellyplus1-a8032ab1", Port: 80,
		MDNSPort: port, Interface: ifi, Loopback: true})
	opts := mdns.Options{Interfaces: []net.Interface{*ifi}, Port: port, Loopback: true, Wait: 2 * time.Second}
	got, err := mdns.BrowseTypes(ctx, types, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(got[types[0]]) != 1 || got[types[0]][0].TXT["bridgeid"] != "001788fffe1a2b3c" || len(got[types[1]]) != 1 || len(got[types[2]]) != 0 {
		t.Fatalf("BrowseTypes %+v", got)
	}
	w, err := mdns.Watch(ctx, types, opts, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	<-w.Settled()
	if len(w.Services(types[0])) != 1 || len(w.Services(types[1])) != 1 || len(w.Services(types[2])) != 0 || w.Services("_other._tcp") != nil {
		t.Fatalf("Watch %v %v", w.Services(types[0]), w.Services(types[1]))
	}
}

// TestBrowseModes: the one-shot mode hears only the unicast answerer and
// the multicast mode hears the multicast answerer; the default hears both
// (TestBrowseFindsEveryAnswerStyle).
//
// Covers: SIG-IPE-6420
func TestBrowseModes(t *testing.T) {
	port, ifi := testPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const typ = "_modesim._tcp"
	startSim(t, ctx, sim.Config{Style: sim.Legacy, Type: typ, Instance: "legacy", Host: "l", Port: 1, MDNSPort: port, Interface: ifi, Loopback: true})
	startSim(t, ctx, sim.Config{Style: sim.Multicast, Type: typ, Instance: "multicast", Host: "m", Port: 1, MDNSPort: port, Interface: ifi, Loopback: true})
	opts := mdns.Options{Interfaces: []net.Interface{*ifi}, Port: port, Loopback: true, Wait: 1500 * time.Millisecond}
	opts.Mode = mdns.BrowseOneShot
	got, err := mdns.Browse(ctx, typ, opts)
	if err != nil {
		t.Fatal(err)
	}
	if f := instances(got); len(f) != 1 || f["legacy"].Port != 1 {
		t.Errorf("one-shot found %+v", got)
	}
	opts.Mode = mdns.BrowseMulticast
	got, err = mdns.Browse(ctx, typ, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := instances(got)["multicast"]; !ok {
		t.Errorf("multicast mode found %+v", got)
	}
}
