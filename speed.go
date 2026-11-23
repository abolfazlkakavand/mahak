package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
	"time"
)

// The handshake test of 'probe' says whether a strategy gets past the filter, not how fast the
// connection is afterwards. 'speed' downloads a file with each strategy, over IPv4 and over IPv6,
// because a flow can pass and still be slow. The same measurement drives the calibration.

var defaultSpeedURLs = []string{
	"https://speed.cloudflare.com/__down?bytes=8000000",
	"https://proof.ovh.net/files/100Mb.dat",
}

// measure opens a connection with the strategy, downloads from host/path for up to secs seconds
// (or maxBytes, when it is not zero) and returns the speed in KB/s. A non-empty second value says
// why there is no speed.
func (e *Engine) measure(ctx context.Context, host, path string, ip net.IP, st Strategy, secs time.Duration, maxBytes int64) (float64, string) {
	tc, err := e.tlsAttempt(ctx, ip.String(), "443", host, st)
	if err != nil {
		return 0, classify(err)
	}
	defer tc.Close()
	_ = tc.SetDeadline(time.Now().Add(secs + 8*time.Second))
	if _, err := fmt.Fprintf(tc, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: mahak-speed\r\nAccept: */*\r\nConnection: close\r\n\r\n", path, host); err != nil {
		return 0, classify(err)
	}
	br := bufio.NewReaderSize(tc, 64<<10)
	status, err := br.ReadString('\n')
	if err != nil {
		return 0, classify(err)
	}
	if !strings.Contains(status, " 200") {
		return 0, "http " + strings.TrimSpace(strings.TrimPrefix(status, "HTTP/1.1"))
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return 0, classify(err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	start := time.Now()
	deadline := start.Add(secs)
	var total int64
	buf := make([]byte, 64<<10)
	for time.Now().Before(deadline) && (maxBytes == 0 || total < maxBytes) {
		_ = tc.SetReadDeadline(deadline.Add(2 * time.Second))
		n, err := br.Read(buf)
		total += int64(n)
		if err != nil {
			break
		}
	}
	elapsed := time.Since(start).Seconds()
	if total == 0 || elapsed <= 0 {
		return 0, "no data"
	}
	return float64(total) / 1024 / elapsed, ""
}

func (e *Engine) speedOnce(ctx context.Context, host, path string, ip net.IP, st Strategy, secs time.Duration) string {
	kb, why := e.measure(ctx, host, path, ip, st, secs, 0)
	if why != "" {
		return why
	}
	return fmt.Sprintf("%.0f KB/s", kb)
}

func cmdSpeed(args []string) {
	fs := flag.NewFlagSet("speed", flag.ExitOnError)
	cf := addCommon(fs)
	urls := fs.String("url", strings.Join(defaultSpeedURLs, ","), "https URLs to download, comma separated")
	secs := fs.Int("secs", 5, "seconds per measurement")
	all := fs.Bool("all", false, "also test the low-TTL strategies")
	_ = fs.Parse(args)

	e, err := newEngine(cf)
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	dur := time.Duration(*secs) * time.Second
	for _, raw := range splitCSV(*urls) {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" {
			fmt.Println("skipping", raw)
			continue
		}
		host := u.Hostname()
		path := u.RequestURI()
		lctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		ips, err := e.dns.LookupAll(lctx, host)
		cancel()
		if err != nil {
			fmt.Printf("%s: DNS failed: %v\n", host, err)
			continue
		}
		var v4, v6 net.IP
		for _, ip := range ips {
			if ip.To4() != nil {
				if v4 == nil {
					v4 = ip
				}
			} else if v6 == nil {
				v6 = ip
			}
		}
		fmt.Println(host)
		targets := []struct {
			name string
			ip   net.IP
		}{{"v4", v4}, {"v6", v6}}
		for _, st := range e.strategies {
			if !*all && strings.Contains(st.Name, "fake") {
				continue
			}
			line := fmt.Sprintf("  %-14s", st.Name)
			for _, t := range targets {
				if t.ip == nil {
					line += fmt.Sprintf("  %s: %-16s", t.name, "-")
					continue
				}
				pctx, pc := context.WithTimeout(ctx, dur+e.attemptTimeout*2+15*time.Second)
				res := e.speedOnce(pctx, host, path, t.ip, st, dur)
				pc()
				line += fmt.Sprintf("  %s: %-16s", t.name, res)
			}
			fmt.Println(line)
		}
	}
}
