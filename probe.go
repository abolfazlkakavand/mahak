package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/Nemu-x/desync"
)

var defaultTargets = []string{
	"example.com", "www.youtube.com", "www.instagram.com", "x.com",
	"telegram.org", "discord.com", "www.hrw.org", "www.reddit.com", "web.whatsapp.com",
}

type probeResult struct {
	Target   string `json:"target"`
	Strategy string `json:"strategy"`
	Outcome  string `json:"outcome"`
	MS       int64  `json:"ms"`
}

type probeReport struct {
	Version string        `json:"version"`
	Time    string        `json:"time"`
	Net     string        `json:"net,omitempty"`
	Results []probeResult `json:"results"`
}

func classify(err error) string {
	if err == nil {
		return "ok"
	}
	var ne net.Error
	var ua x509.UnknownAuthorityError
	var he x509.HostnameError
	var ci x509.CertificateInvalidError
	switch {
	case errors.Is(err, desync.ErrFakeUnsupported), errors.Is(err, desync.ErrDisorderUnsupported),
		errors.Is(err, desync.ErrOOBUnsupported), errors.Is(err, desync.ErrSplitWaitUnsupported):
		return "unsupported"
	case errors.Is(err, syscall.ECONNRESET):
		return "reset"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "eof"
	case errors.As(err, &ne) && ne.Timeout(), errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.As(err, &ua), errors.As(err, &he), errors.As(err, &ci):
		return "cert"
	}
	msg := err.Error()
	if strings.Contains(msg, "reset by peer") {
		return "reset"
	}
	if strings.Contains(msg, "x509") || strings.Contains(msg, "certificate") {
		return "cert"
	}
	return "error"
}

func (e *Engine) probeOnce(ctx context.Context, host string, ip net.IP, st Strategy) string {
	tc, err := e.tlsAttempt(ctx, ip.String(), "443", host, st)
	if err != nil {
		return classify(err)
	}
	defer tc.Close()
	_ = tc.SetDeadline(time.Now().Add(e.attemptTimeout))
	if _, err := fmt.Fprintf(tc, "HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: mahak-probe\r\nConnection: close\r\n\r\n", host); err != nil {
		return classify(err)
	}
	line, err := bufio.NewReader(tc).ReadString('\n')
	if strings.HasPrefix(line, "HTTP/") {
		return "ok"
	}
	if err != nil {
		return classify(err)
	}
	return "badresp"
}

func cmdProbe(args []string) {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	cf := addCommon(fs)
	targets := fs.String("targets", strings.Join(defaultTargets, ","), "hosts to test, comma separated")
	out := fs.String("out", "mahak-report.json", "report file")
	seed := fs.Bool("seed", true, "remember the best strategy per host for 'serve'")
	_ = fs.Parse(args)

	e, err := newEngine(cf)
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	var results []probeResult
	okBy := map[string]int{}
	best := map[string]string{}

	for _, h := range splitCSV(*targets) {
		lctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		ips, err := e.dns.Lookup(lctx, h)
		cancel()
		if err != nil {
			fmt.Printf("%s  DNS FAILED: %v\n", h, err)
			results = append(results, probeResult{Target: h, Strategy: "-", Outcome: "dns-fail"})
			continue
		}
		fmt.Println(h)
		for _, st := range e.strategies {
			start := time.Now()
			pctx, pc := context.WithTimeout(ctx, e.attemptTimeout*3)
			oc := e.probeOnce(pctx, h, ips[0], st)
			pc()
			ms := time.Since(start).Milliseconds()
			results = append(results, probeResult{Target: h, Strategy: st.Name, Outcome: oc, MS: ms})
			mark := "--"
			if oc == "ok" {
				mark = "OK"
				okBy[st.Name]++
				if best[h] == "" {
					best[h] = st.Name
				}
			}
			fmt.Printf("  %-16s %-2s %-12s %5d ms\n", st.Name, mark, oc, ms)
		}
	}

	fmt.Println("\nSummary (hosts passed per strategy):")
	names := make([]string, 0, len(e.strategies))
	for _, s := range e.strategies {
		names = append(names, s.Name)
	}
	sort.SliceStable(names, func(i, j int) bool { return okBy[names[i]] > okBy[names[j]] })
	for _, n := range names {
		fmt.Printf("  %-16s %d\n", n, okBy[n])
	}

	rep := probeReport{Version: version, Time: time.Now().UTC().Format(time.RFC3339), Results: results}
	if cf.netLabel != "" {
		rep.Net = cf.netLabel
	}
	if b, err := json.MarshalIndent(rep, "", " "); err == nil {
		if err := os.WriteFile(*out, b, 0o644); err == nil {
			fmt.Println("\nreport written to", *out)
		}
	}
	if *seed {
		for h, s := range best {
			e.store.Success(e.netKey, h, s)
		}
		e.store.Save()
	}
}
