// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package sim_test

import (
	"context"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/cB-Sigma/mdns"
	"github.com/cB-Sigma/mdns-sim/sim"
)

// Covers: SIG-IPE-7359
//
// A simulated device with an IPv6 address, subtypes, the service type
// enumeration and a browse domain: the mdns browser finds it by type and
// by subtype with both addresses, lists its type and its domain.
func TestSimAAAASubtypesTypesDomains(t *testing.T) {
	port, ifi := testPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	v6 := net.ParseIP("fd00:5353::42")
	for _, style := range []sim.Style{sim.Legacy, sim.Multicast} {
		cfg := sim.Config{Style: style, Type: "_simv3._tcp", Instance: "Sim V3 " + style.String(), Host: "simv3-" + style.String(), Port: 9000,
			TXT: map[string]string{"k": "v"}, IPv6: v6, Subtypes: []string{"_printer"}, ServiceTypes: true,
			Domains: []string{"example.com"}, MDNSPort: port, Interface: ifi, Loopback: true}
		startSim(t, ctx, cfg)
	}
	opts := mdns.Options{Interfaces: []net.Interface{*ifi}, Port: port, Loopback: true, Wait: 2 * time.Second}
	all, err := mdns.Browse(ctx, "_simv3._tcp", opts)
	if err != nil {
		t.Fatal(err)
	}
	got := instances(all)
	for _, name := range []string{"Sim V3 legacy", "Sim V3 multicast"} {
		s, ok := got[name]
		if !ok || !slices.ContainsFunc(s.IPs, func(ip net.IP) bool { return ip.Equal(v6) }) {
			t.Errorf("%s: %+v", name, s)
		}
	}
	sub, err := mdns.Browse(ctx, "_printer._sub._simv3._tcp", opts)
	if err != nil || len(sub) != 2 {
		t.Errorf("subtype browse: %+v %v", sub, err)
	}
	types, err := mdns.BrowseServiceTypes(ctx, opts)
	if err != nil || !slices.Contains(types, "_simv3._tcp") {
		t.Errorf("types %v %v", types, err)
	}
	d, err := mdns.BrowseDomains(ctx, opts)
	if err != nil || !slices.Equal(d.Browse, []string{"example.com."}) {
		t.Errorf("domains %+v %v", d, err)
	}
}

// Covers: SIG-IPE-7359
//
// A probing simulated device renames when an mdns announcer holds its
// name; an mdns announcer renames when the probing device holds it.
func TestSimProbing(t *testing.T) {
	port, ifi := testPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	opts := mdns.Options{Interfaces: []net.Interface{*ifi}, Port: port, Loopback: true, Rename: mdns.RenameInstance}
	a, err := mdns.Announce(ctx, mdns.Service{Instance: "Held", Host: "holder", Port: 9001, IPs: []net.IP{net.IPv4(192, 0, 2, 1)}}, "_simprobe._tcp", opts)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	d := startSim(t, ctx, sim.Config{Style: sim.Multicast, Type: "_simprobe._tcp", Instance: "Held", Host: "simprober", Port: 9002,
		MDNSPort: port, Interface: ifi, Loopback: true, Probe: true})
	if d.Instance() != "Held (2)" || a.Service().Instance != "Held" {
		t.Fatalf("the sim took %q, the announcer %q", d.Instance(), a.Service().Instance)
	}
	d2 := startSim(t, ctx, sim.Config{Style: sim.Multicast, Type: "_simprobe2._tcp", Instance: "Sim First", Host: "simfirst", Port: 9003,
		MDNSPort: port, Interface: ifi, Loopback: true, Probe: true})
	b, err := mdns.Announce(ctx, mdns.Service{Instance: "Sim First", Host: "second", Port: 9004, IPs: []net.IP{net.IPv4(192, 0, 2, 2)}}, "_simprobe2._tcp", opts)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if d2.Instance() != "Sim First" || b.Service().Instance == "Sim First" {
		t.Fatalf("the sim holds %q, the announcer took %q", d2.Instance(), b.Service().Instance)
	}
}

// Covers: SIG-IPE-7359
//
// Two probes for one name at once (RFC 6762 8.2): the device and the mdns
// announcer start together, and exactly one keeps the name.
func TestSimSimultaneousProbe(t *testing.T) {
	port, ifi := testPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	opts := mdns.Options{Interfaces: []net.Interface{*ifi}, Port: port, Loopback: true, Rename: mdns.RenameInstance}
	type res struct {
		d   *sim.Device
		err error
	}
	ch := make(chan res, 1)
	go func() {
		d, err := sim.Start(ctx, sim.Config{Style: sim.Multicast, Type: "_simtie._tcp", Instance: "Tie", Host: "simtie", Port: 9010,
			MDNSPort: port, Interface: ifi, Loopback: true, Probe: true})
		ch <- res{d, err}
	}()
	a, err := mdns.Announce(ctx, mdns.Service{Instance: "Tie", Host: "goTie", Port: 9011, IPs: []net.IP{net.IPv4(192, 0, 2, 3)}}, "_simtie._tcp", opts)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	defer r.d.Close()
	keep := 0
	if r.d.Instance() == "Tie" {
		keep++
	}
	if a.Service().Instance == "Tie" {
		keep++
	}
	if keep != 1 {
		t.Fatalf("the sim has %q, the announcer %q", r.d.Instance(), a.Service().Instance)
	}
	t.Logf("the sim has %q, the announcer %q", r.d.Instance(), a.Service().Instance)
}
