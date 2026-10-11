// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package sim_test

// Integration tests of the mdns v0.2.0 behaviour against simulated
// devices: a conflict that appears after probing, NSEC answers, and a
// device that vanishes without a goodbye.

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/cB-Sigma/mdns"

	"github.com/cB-Sigma/mdns-sim/sim"
)

// TestLateConflictRenames: a device that does not probe announces our
// instance name with its own data after we have probed. The announcer
// notices, probes again, meets the device's answers and renames itself
// (RFC 6762 clause 9); a browse then finds both.
func TestLateConflictRenames(t *testing.T) {
	port, ifi := testPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	const typ = "_latesim._tcp"
	var mu sync.Mutex
	var kinds []mdns.ConflictKind
	var renamed mdns.ConflictEvent
	opts := mdns.Options{Interfaces: []net.Interface{*ifi}, Port: port, Loopback: true, Wait: 2 * time.Second, Rename: mdns.RenameInstance,
		OnConflict: func(e mdns.ConflictEvent) {
			mu.Lock()
			kinds = append(kinds, e.Kind)
			if e.Kind == mdns.ConflictRenamed {
				renamed = e
			}
			mu.Unlock()
		}}
	a, err := mdns.Announce(ctx, mdns.Service{Instance: "Kitchen light", Host: "sigma-light", Port: 8080}, typ, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	time.Sleep(500 * time.Millisecond)
	startSim(t, ctx, sim.Config{Style: sim.Multicast, Type: typ, Instance: "Kitchen light", Host: "other-light", Port: 9090,
		MDNSPort: port, Interface: ifi, Loopback: true})
	deadline := time.Now().Add(6 * time.Second)
	for {
		mu.Lock()
		done := renamed.Kind == mdns.ConflictRenamed
		got := append([]mdns.ConflictKind(nil), kinds...)
		mu.Unlock()
		if done {
			if len(got) != 2 || got[0] != mdns.ConflictSeen {
				t.Fatalf("events %v", got)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no rename; events %v", got)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if renamed.Service.Instance != "Kitchen light (2)" || renamed.Previous.Instance != "Kitchen light" || a.Service().Instance != "Kitchen light (2)" {
		t.Fatalf("renamed %+v", renamed)
	}
	found, err := mdns.Browse(ctx, typ, opts)
	if err != nil {
		t.Fatal(err)
	}
	f := instances(found)
	if f["Kitchen light"].Port != 9090 || f["Kitchen light (2)"].Port != 8080 {
		t.Fatalf("found %+v", found)
	}
}

// TestBrowserStopsAskingOnNSEC: a device without a TXT record that says so
// with NSEC is not asked for TXT again and again; one that stays silent
// about it is (RFC 6762 clause 6.1). Both are found.
func TestBrowserStopsAskingOnNSEC(t *testing.T) {
	port, ifi := testPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	base := sim.Config{Style: sim.Multicast, Port: 80, MDNSPort: port, Interface: ifi, Loopback: true, NoTXT: true}
	withNSEC := base
	withNSEC.Type, withNSEC.Instance, withNSEC.Host, withNSEC.NSEC = "_nsecsim._tcp", "says so", "nsec-dev", true
	silent := base
	silent.Type, silent.Instance, silent.Host = "_quietsim._tcp", "says nothing", "quiet-dev"
	dn := startSim(t, ctx, withNSEC)
	dq := startSim(t, ctx, silent)
	got, err := mdns.BrowseTypes(ctx, []string{withNSEC.Type, silent.Type}, mdns.Options{Interfaces: []net.Interface{*ifi}, Port: port, Loopback: true, Wait: 4 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(got[withNSEC.Type]) != 1 || len(got[silent.Type]) != 1 {
		t.Fatalf("found %+v", got)
	}
	if n := dn.Asked(dnsmessage.TypeTXT); n != 0 {
		t.Errorf("device that answered with NSEC asked for TXT %d times", n)
	}
	if n := dq.Asked(dnsmessage.TypeTXT); n < 2 {
		t.Errorf("silent device asked for TXT %d times; the comparison says nothing", n)
	}
}

// TestWatchDropsVanishedDevice: a device that loses power sends no
// goodbye; once another host has asked for it twice without an answer, a
// Watcher removes it after ten seconds instead of waiting for its TTL
// (RFC 6762 clause 10.5).
func TestWatchDropsVanishedDevice(t *testing.T) {
	port, ifi := testPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	const typ = "_vanishsim._tcp"
	ev := newEvents()
	opts := mdns.Options{Interfaces: []net.Interface{*ifi}, Port: port, Loopback: true, Wait: time.Second}
	w, err := mdns.Watch(ctx, []string{typ}, opts, ev.add)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	start := time.Now()
	d := startSim(t, ctx, sim.Config{Style: sim.Multicast, Type: typ, Instance: "Plug", Host: "plug", Port: 80, TTL: 4500 * time.Second,
		MDNSPort: port, Interface: ifi, Loopback: true})
	ev.wait(t, 3*time.Second, "added event", func(e mdns.Event) bool { return e.Kind == mdns.Added })
	// The Watcher ignores queries identical to its own recent ones from
	// this host; let those age out before another browser asks.
	time.Sleep(time.Until(start.Add(6 * time.Second)))
	_ = d.Vanish()
	t0 := time.Now()
	o := opts
	o.Mode, o.Wait = mdns.BrowseMulticast, 1500*time.Millisecond
	if got, err := mdns.Browse(ctx, typ, o); err != nil || len(got) != 0 {
		t.Fatalf("browse after the device vanished: %+v %v", got, err)
	}
	gone := ev.wait(t, 12*time.Second, "removed event", func(e mdns.Event) bool { return e.Kind == mdns.Removed })
	if d := time.Since(t0); d < 9*time.Second || gone.Service.Instance != "Plug" {
		t.Fatalf("removed %+v after %v", gone, d)
	}
}
