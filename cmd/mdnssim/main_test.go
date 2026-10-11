// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/mdns"
	"github.com/cB-Sigma/mdns-sim/sim"
)

func TestRunner(t *testing.T) {
	if testing.Short() {
		t.Skip("uses multicast; skipped with -short")
	}
	port := 20000 + rand.IntN(30000)
	ifi, err := mdns.TestInterface(port)
	if err != nil {
		t.Skip(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan []*sim.Device, 1)
	var out bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"-style", "legacy,multicast", "-iface", ifi.Name, "-mdns-port", strconv.Itoa(port), "-loopback", "-txt", "model=sim,fw=1"}, &out,
			func(d []*sim.Device) { got <- d })
	}()
	select {
	case <-got:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("not ready")
	}
	found, err := mdns.Browse(ctx, "_sigmasim._tcp", mdns.Options{Interfaces: []net.Interface{*ifi}, Port: port, Loopback: true, Wait: 1500 * time.Millisecond})
	if err != nil || len(found) != 2 || found[0].TXT["fw"] != "1" {
		t.Fatalf("browse: %+v %v", found, err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"SigmaM2M sim (legacy)"`) || !strings.Contains(out.String(), `"SigmaM2M sim (multicast)"`) {
		t.Errorf("output = %s", out.String())
	}
}

func TestRunnerFlags(t *testing.T) {
	for _, args := range [][]string{{"-style", "shouting"}, {"-port", "70000"}, {"-ip", "nowhere"}, {"-iface", "no-such-if0"}, {"-bogus"}} {
		if err := run(context.Background(), args, &bytes.Buffer{}, nil); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}
