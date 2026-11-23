package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const version = "0.2.0"

type common struct {
	doh         string
	decoy       string
	state       string
	netLabel    string
	ipv6        string
	attempt     time.Duration
	stagger     time.Duration
	maxAttempts int
	verbose     bool
}

func addCommon(fs *flag.FlagSet) *common {
	c := &common{}
	fs.StringVar(&c.doh, "doh", "cloudflare-dns.com@1.1.1.1,dns.google@8.8.8.8", "DoH servers as name@ip, comma separated")
	fs.StringVar(&c.decoy, "decoy", "letsencrypt.org", "decoy SNI names for fake-packet strategies, comma separated")
	fs.StringVar(&c.state, "state", "", "state file (default ~/.mahak/state.json)")
	fs.StringVar(&c.netLabel, "net", "", "network label (default: derived from the local address)")
	fs.StringVar(&c.ipv6, "ipv6", "first", "IPv6 use: first, last or off")
	fs.DurationVar(&c.attempt, "attempt-timeout", 3500*time.Millisecond, "how long to wait for the server's first bytes per strategy")
	fs.DurationVar(&c.stagger, "stagger", 300*time.Millisecond, "delay before the next address is tried in parallel")
	fs.IntVar(&c.maxAttempts, "max-attempts", 6, "strategies tried per connection")
	fs.BoolVar(&c.verbose, "v", false, "verbose log")
	return c
}

func usage() {
	fmt.Fprintf(os.Stderr, `mahak %s - adaptive DPI-evasion SOCKS5 engine

Usage:
  mahak serve [-listen 127.0.0.1:10808] [flags]   run the local SOCKS5 proxy
  mahak probe [-targets a.com,b.com] [flags]      test every strategy on this network
  mahak speed [-url https://host/file] [flags]    measure download speed per strategy, IPv4 and IPv6
  mahak strategies                                list built-in strategies
  mahak version
`, version)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		cmdServe(os.Args[2:])
	case "probe":
		cmdProbe(os.Args[2:])
	case "speed":
		cmdSpeed(os.Args[2:])
	case "strategies":
		for _, s := range validStrategies(buildStrategies(splitCSV("letsencrypt.org"))) {
			fmt.Println(s.Name)
		}
	case "version":
		fmt.Println("mahak", version)
	default:
		usage()
		os.Exit(2)
	}
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cf := addCommon(fs)
	listen := fs.String("listen", "127.0.0.1:10808", "SOCKS5 listen address")
	_ = fs.Parse(args)

	e, err := newEngine(cf)
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	e.store.StartAutoSave(ctx)
	log.Printf("mahak %s listening on %s, net=%s, %d strategies, ipv6=%s", version, *listen, e.netKey, len(e.strategies), e.ipv6)
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			continue
		}
		go e.handleSocks(ctx, c)
	}
	e.store.Save()
}
