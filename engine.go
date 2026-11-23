package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Nemu-x/desync"
)

type Engine struct {
	strategies     []Strategy
	store          *Store
	netKey         string
	roots          *x509.CertPool
	attemptTimeout time.Duration
	dialTimeout    time.Duration
	stagger        time.Duration
	maxAttempts    int
	ipv6           string
	dns            *Resolver
	verbose        bool
}

// dialErr marks a failure to open the TCP connection at all (timeout, refusal, no route). That says
// something about the address, nothing about the strategy, so it neither counts against a strategy
// nor is retried with the others.
type dialErr struct{ err error }

func (d *dialErr) Error() string { return "connect: " + d.err.Error() }
func (d *dialErr) Unwrap() error { return d.err }

func newEngine(cf *common) (*Engine, error) {
	strategies := validStrategies(buildStrategies(splitCSV(cf.decoy)))
	if len(strategies) == 0 {
		return nil, errors.New("no usable strategies on this system")
	}
	statePath := cf.state
	if statePath == "" {
		home, _ := os.UserHomeDir()
		statePath = filepath.Join(home, ".mahak", "state.json")
	}
	key := cf.netLabel
	if key == "" {
		key = autoNetKey()
	}
	mode := strings.ToLower(cf.ipv6)
	if mode != "first" && mode != "last" && mode != "off" {
		mode = "first"
	}
	e := &Engine{
		strategies:     strategies,
		store:          loadStore(statePath),
		netKey:         key,
		roots:          loadRoots(),
		attemptTimeout: cf.attempt,
		dialTimeout:    5 * time.Second,
		stagger:        cf.stagger,
		maxAttempts:    cf.maxAttempts,
		ipv6:           mode,
		verbose:        cf.verbose,
	}
	e.dns = newResolver(e, parseDoH(cf.doh))
	return e, nil
}

func (e *Engine) logf(format string, a ...any) {
	if e.verbose {
		log.Printf(format, a...)
	}
}

// autoNetKey labels the current network by the first two octets of the local
// IPv4 address. Dialing UDP sends no packet. A different network gives a
// different key, so what was learned elsewhere is not reused blindly.
func autoNetKey() string {
	c, err := net.Dial("udp4", "1.1.1.1:53")
	if err != nil {
		return "default"
	}
	defer c.Close()
	if ua, ok := c.LocalAddr().(*net.UDPAddr); ok {
		if ip := ua.IP.To4(); ip != nil {
			return fmt.Sprintf("%d.%d", ip[0], ip[1])
		}
	}
	return "default"
}

func loadRoots() *x509.CertPool {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	cands := []string{os.Getenv("SSL_CERT_FILE")}
	if p := os.Getenv("PREFIX"); p != "" {
		cands = append(cands, filepath.Join(p, "etc/tls/cert.pem"))
	}
	cands = append(cands, "/data/data/com.termux/files/usr/etc/tls/cert.pem", "/etc/ssl/certs/ca-certificates.crt")
	for _, f := range cands {
		if f == "" {
			continue
		}
		if b, err := os.ReadFile(f); err == nil {
			pool.AppendCertsFromPEM(b)
		}
	}
	return pool
}

// orderIPs keeps at most two addresses per family and orders the families by the ipv6 mode.
func orderIPs(ips []net.IP, mode string) []net.IP {
	var v4, v6 []net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	if len(v4) > 2 {
		v4 = v4[:2]
	}
	if len(v6) > 2 {
		v6 = v6[:2]
	}
	switch mode {
	case "off":
		return v4
	case "last":
		return append(v4, v6...)
	}
	return append(v6, v4...)
}

func family(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err == nil {
		if ip := net.ParseIP(h); ip != nil && ip.To4() == nil {
			return "v6"
		}
	}
	return "v4"
}

func (e *Engine) dialStrategy(ctx context.Context, addr string, st Strategy) (net.Conn, error) {
	d := net.Dialer{Timeout: e.dialTimeout}
	if st.Opts.Fake != nil && st.Opts.Fake.AutoTTL != nil {
		d.Control = desync.ControlAutoTTL
	}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, &dialErr{err}
	}
	return desync.WrapConn(raw, st.Opts), nil
}

// tlsAttempt makes a full TLS handshake with one strategy. Used for the DoH
// resolver and for probing.
func (e *Engine) tlsAttempt(ctx context.Context, ip, port, serverName string, st Strategy) (*tls.Conn, error) {
	c, err := e.dialStrategy(ctx, net.JoinHostPort(ip, port), st)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(c, &tls.Config{
		ServerName: serverName,
		RootCAs:    e.roots,
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	})
	hctx, cancel := context.WithTimeout(ctx, e.attemptTimeout)
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		c.Close()
		return nil, err
	}
	return tc, nil
}

func (e *Engine) dialTLSRotate(ctx context.Context, ip, port, serverName string) (net.Conn, error) {
	key := "tls:" + serverName
	order := e.store.Order(e.netKey, key, e.strategies)
	if len(order) > e.maxAttempts {
		order = order[:e.maxAttempts]
	}
	var last error
	for _, st := range order {
		tc, err := e.tlsAttempt(ctx, ip, port, serverName, st)
		if err == nil {
			e.store.Success(e.netKey, key, st.Name)
			e.logf("doh %s via %s", serverName, st.Name)
			return tc, nil
		}
		last = err
		var de *dialErr
		if errors.As(err, &de) {
			break
		}
		e.store.Fail(e.netKey, key, st.Name)
		e.logf("doh %s via %s failed: %s", serverName, st.Name, classify(err))
		if ctx.Err() != nil {
			break
		}
	}
	return nil, fmt.Errorf("all strategies failed for %s: %v", serverName, last)
}

// attempt sends the buffered ClientHello with one strategy and waits for the
// first TLS record from the server. A handshake or alert record means the
// hello got through; a reset, silence or anything else means it did not.
func (e *Engine) attempt(ctx context.Context, addr string, st Strategy, hello []byte) (net.Conn, []byte, error) {
	c, err := e.dialStrategy(ctx, addr, st)
	if err != nil {
		return nil, nil, err
	}
	if _, err := c.Write(hello); err != nil {
		c.Close()
		return nil, nil, err
	}
	_ = c.SetReadDeadline(time.Now().Add(e.attemptTimeout))
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c, hdr); err != nil {
		c.Close()
		return nil, nil, err
	}
	_ = c.SetReadDeadline(time.Time{})
	if hdr[0] != 0x16 && hdr[0] != 0x15 {
		c.Close()
		return nil, nil, errors.New("unexpected first record")
	}
	return c, hdr, nil
}

func resetTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}

// joinErrs reports a dial failure only when every candidate failed to connect; otherwise it
// returns the last error that was not a dial failure.
func joinErrs(errs []error) error {
	var de *dialErr
	var last error
	for _, err := range errs {
		last = err
	}
	for i := len(errs) - 1; i >= 0; i-- {
		if !errors.As(errs[i], &de) {
			return errs[i]
		}
	}
	return last
}

// race tries the candidate addresses with one strategy, the next one starting when the stagger time
// has passed or the previous one has failed, and keeps the first that gets a TLS record back.
// This is the same idea as the happy-eyeballs dialling of the Xray core, with "the server answered
// the hello" as the definition of success.
func (e *Engine) race(ctx context.Context, cands []string, st Strategy, hello []byte) (net.Conn, []byte, string, error) {
	type result struct {
		c    net.Conn
		hdr  []byte
		addr string
		err  error
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ch := make(chan result, len(cands))
	launched, finished := 0, 0
	launch := func() {
		addr := cands[launched]
		launched++
		go func() {
			c, hdr, err := e.attempt(ctx, addr, st, hello)
			ch <- result{c, hdr, addr, err}
		}()
	}
	launch()
	timer := time.NewTimer(e.stagger)
	defer timer.Stop()
	var errs []error
	for finished < launched {
		select {
		case r := <-ch:
			finished++
			if r.err == nil {
				go func(pending int) {
					for i := 0; i < pending; i++ {
						if x := <-ch; x.c != nil {
							x.c.Close()
						}
					}
				}(launched - finished)
				return r.c, r.hdr, r.addr, nil
			}
			errs = append(errs, r.err)
			if launched < len(cands) {
				launch()
				resetTimer(timer, e.stagger)
			}
		case <-timer.C:
			if launched < len(cands) {
				launch()
				timer.Reset(e.stagger)
			}
		}
	}
	return nil, nil, "", joinErrs(errs)
}

func (e *Engine) proxyTLS(ctx context.Context, client net.Conn, host string, port int, hello []byte, extra []byte) {
	key := strings.ToLower(host)
	if h, err := desync.ParseHello(hello); err == nil && h.SNI != "" {
		key = strings.ToLower(h.SNI)
	}
	lctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	ips, err := e.dns.LookupAll(lctx, host)
	cancel()
	if err != nil || len(ips) == 0 {
		log.Printf("%s: no address (%v)", key, err)
		return
	}
	cands := orderIPs(ips, e.ipv6)
	if len(cands) == 0 {
		log.Printf("%s: no usable address", key)
		return
	}
	p := strconv.Itoa(port)
	addrs := make([]string, len(cands))
	for i, ip := range cands {
		addrs[i] = net.JoinHostPort(ip.String(), p)
	}
	order := e.store.Order(e.netKey, key, e.strategies)
	if len(order) > e.maxAttempts {
		order = order[:e.maxAttempts]
	}
	for i, st := range order {
		if ctx.Err() != nil {
			return
		}
		start := time.Now()
		up, hdr, addr, err := e.race(ctx, addrs, st, hello)
		if err != nil {
			var de *dialErr
			if errors.As(err, &de) {
				log.Printf("%s: unreachable: %v", key, de.err)
				return
			}
			e.store.Fail(e.netKey, key, st.Name)
			e.logf("%s try %d %s: %s", key, i+1, st.Name, classify(err))
			continue
		}
		e.store.Success(e.netKey, key, st.Name)
		e.logf("%s ok via %s %s (%d ms)", key, st.Name, family(addr), time.Since(start).Milliseconds())
		if _, err := client.Write(hdr); err != nil {
			up.Close()
			return
		}
		if len(extra) > 0 {
			_, _ = up.Write(extra)
		}
		relay(client, up)
		return
	}
	log.Printf("%s: all strategies failed", key)
}

func (e *Engine) proxyPlain(ctx context.Context, client net.Conn, host string, port int, first []byte) {
	lctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	ips, err := e.dns.LookupAll(lctx, host)
	cancel()
	if err != nil || len(ips) == 0 {
		log.Printf("%s: no address (%v)", host, err)
		return
	}
	cands := orderIPs(ips, e.ipv6)
	if len(cands) == 0 {
		return
	}
	d := net.Dialer{Timeout: e.dialTimeout}
	var up net.Conn
	for _, ip := range cands {
		up, err = d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
		if err == nil {
			break
		}
	}
	if up == nil {
		log.Printf("%s: unreachable: %v", host, err)
		return
	}
	if len(first) > 0 {
		if _, err := up.Write(first); err != nil {
			up.Close()
			return
		}
	}
	relay(client, up)
}

func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		closeWrite(dst)
		done <- struct{}{}
	}
	go pipe(a, b)
	go pipe(b, a)
	<-done
	dl := time.Now().Add(30 * time.Second)
	_ = a.SetDeadline(dl)
	_ = b.SetDeadline(dl)
	<-done
	a.Close()
	b.Close()
}

func closeWrite(c net.Conn) {
	for {
		if cw, ok := c.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
			return
		}
		if u, ok := c.(interface{ NetConn() net.Conn }); ok {
			c = u.NetConn()
			continue
		}
		return
	}
}
