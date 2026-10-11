// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Command mdnssim runs simulated mDNS/DNS-SD devices (package sim of this
// module), one per answer style asked for, so a browser can be tried
// against each:
//
//	legacy     answers by unicast to the query's source, never multicasts
//	multicast  answers only by multicast, announces, says goodbye
//	announce   answers nothing, announces every -repeat
//
// For example, both answer styles on port 5353 next to the operating
// system's responder:
//
//	mdnssim -style legacy,multicast -type _sigmasim._tcp
//
// and then dns-sd -B _sigmasim._tcp (macOS) or avahi-browse _sigmasim._tcp
// (Linux) to compare. With -loopback and -mdns-port, a test port on the
// loopback interface keeps the traffic off the LAN.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cB-Sigma/mdns-sim/sim"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, nil); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "mdnssim:", err)
		os.Exit(1)
	}
}

// run serves until ctx ends. ready, when not nil, receives the devices once
// they run.
func run(ctx context.Context, args []string, out io.Writer, ready func([]*sim.Device)) error {
	fs := flag.NewFlagSet("mdnssim", flag.ContinueOnError)
	fs.SetOutput(out)
	styles := fs.String("style", "legacy,multicast", "answer styles, comma separated: legacy, multicast, announce")
	typ := fs.String("type", "_sigmasim._tcp", "DNS-SD service type")
	instance := fs.String("instance", "SigmaM2M sim", "instance name; the style is added in brackets")
	host := fs.String("host", "sigmasim", "host label; the style is added")
	port := fs.Int("port", 8080, "service port")
	txt := fs.String("txt", "model=sim", "TXT records, key=value pairs separated by commas")
	ip := fs.String("ip", "", "address in the A record (default: the interface's)")
	iface := fs.String("iface", "", "interface name (default: the first multicast-capable one with IPv4)")
	mport := fs.Int("mdns-port", 5353, "multicast DNS port")
	loopback := fs.Bool("loopback", false, "multicast loopback, so a browser on this host hears the devices; allows the loopback interface")
	ttl := fs.Duration("ttl", 120*time.Second, "TTL of every record")
	repeat := fs.Duration("repeat", 0, "interval of the announce style's announcements (0: at start only)")
	noTXT := fs.Bool("no-txt", false, "no TXT record")
	nsec := fs.Bool("nsec", false, "answer questions for missing record types with NSEC")
	ip6 := fs.String("ip6", "", "IPv6 address for an AAAA record (none by default)")
	subtypes := fs.String("subtypes", "", "subtype labels, comma separated (_printer)")
	types := fs.Bool("types", false, "answer the service type enumeration (_services._dns-sd._udp)")
	domains := fs.String("domains", "", "browse domains to answer for b._dns-sd._udp, comma separated")
	probe := fs.Bool("probe", false, "probe for the instance name first (multicast and announce styles)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *port < 1 || *port > 65535 || *mport < 1 || *mport > 65535 {
		return fmt.Errorf("-port %d or -mdns-port %d is out of range", *port, *mport)
	}
	meta := map[string]string{}
	for _, kv := range strings.Split(*txt, ",") {
		if kv = strings.TrimSpace(kv); kv == "" {
			continue
		}
		k, v, _ := strings.Cut(kv, "=")
		meta[k] = v
	}
	var addr net.IP
	if *ip != "" {
		if addr = net.ParseIP(*ip).To4(); addr == nil {
			return fmt.Errorf("-ip %q is not an IPv4 address", *ip)
		}
	}
	var ifi *net.Interface
	var err error
	if *iface != "" {
		ifi, err = net.InterfaceByName(*iface)
	} else {
		ifi, err = sim.DefaultInterface(*loopback)
	}
	if err != nil {
		return err
	}
	var devs []*sim.Device
	defer func() {
		for _, d := range devs {
			_ = d.Close()
		}
	}()
	for _, name := range strings.Split(*styles, ",") {
		st, err := sim.ParseStyle(strings.TrimSpace(name))
		if err != nil {
			return err
		}
		d, err := sim.Start(ctx, sim.Config{Style: st, Type: *typ, Instance: fmt.Sprintf("%s (%s)", *instance, st), Host: *host + "-" + st.String(),
			Port: *port, TXT: meta, IP: addr, TTL: *ttl, MDNSPort: *mport, Interface: ifi, Loopback: *loopback, Repeat: *repeat,
			NoTXT: *noTXT, NSEC: *nsec, IPv6: net.ParseIP(*ip6), Subtypes: list(*subtypes), ServiceTypes: *types,
			Domains: list(*domains), Probe: *probe})
		if err != nil {
			return err
		}
		devs = append(devs, d)
		fmt.Fprintf(out, "mdnssim: %q (%s) as %s on %s, mDNS port %d\n", fmt.Sprintf("%s (%s)", *instance, st), st, *typ, ifi.Name, *mport)
	}
	if ready != nil {
		ready(devs)
	}
	<-ctx.Done()
	return nil
}

// list splits a comma-separated flag value, dropping empty items.
func list(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}
