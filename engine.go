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
	maxAttempts    int
	dns            *Resolver
	verbose        bool
}

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
	e := &Engine{
		strategies:     strategies,
		store:          loadStore(statePath),
		netKey:         key,
		roots:          loadRoots(),
		attemptTimeout: cf.attempt,
		dialTimeout:    5 * time.Second,
		maxAttempts:    cf.maxAttempts,
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

func (e *Engine) dialStrategy(ctx context.Context, addr string, st Strategy) (net.Conn, error) {
	d := net.Dialer{Timeout: e.dialTimeout}
	if st.Opts.Fake != nil && st.Opts.Fake.AutoTTL != nil {
		d.Control = desync.ControlAutoTTL
	}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
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
		e.store.Fail(e.netKey, key, st.Name)
		e.logf("doh %s via %s failed: %s", serverName, st.Name, classify(err))
		last = err
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

type try struct {
	st Strategy
	ip net.IP
}

func (e *Engine) proxyTLS(ctx context.Context, client net.Conn, host string, port int, hello []byte, extra []byte) {
	key := strings.ToLower(host)
	if h, err := desync.ParseHello(hello); err == nil && h.SNI != "" {
		key = strings.ToLower(h.SNI)
	}
	lctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	ips, err := e.dns.Lookup(lctx, host)
	cancel()
	if err != nil || len(ips) == 0 {
		e.logf("%s: %v", host, err)
		return
	}
	order := e.store.Order(e.netKey, key, e.strategies)
	if len(order) > e.maxAttempts {
		order = order[:e.maxAttempts]
	}
	var plan []try
	for _, st := range order {
		plan = append(plan, try{st, ips[0]})
	}
	for i := 1; i < len(ips) && i < 3; i++ {
		plan = append(plan, try{order[0], ips[i]})
	}
	p := strconv.Itoa(port)
	for i, t := range plan {
		if ctx.Err() != nil {
			return
		}
		start := time.Now()
		up, hdr, err := e.attempt(ctx, net.JoinHostPort(t.ip.String(), p), t.st, hello)
		if err != nil {
			e.store.Fail(e.netKey, key, t.st.Name)
			e.logf("%s try %d %s: %s", key, i+1, t.st.Name, classify(err))
			continue
		}
		e.store.Success(e.netKey, key, t.st.Name)
		e.logf("%s ok via %s (%d ms)", key, t.st.Name, time.Since(start).Milliseconds())
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
	e.logf("%s: all strategies failed", key)
}

func (e *Engine) proxyPlain(ctx context.Context, client net.Conn, host string, port int, first []byte) {
	lctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	ips, err := e.dns.Lookup(lctx, host)
	cancel()
	if err != nil || len(ips) == 0 {
		e.logf("%s: %v", host, err)
		return
	}
	d := net.Dialer{Timeout: e.dialTimeout}
	up, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ips[0].String(), strconv.Itoa(port)))
	if err != nil {
		e.logf("%s: %v", host, err)
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
