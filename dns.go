package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type dohServer struct {
	Name string
	IP   string
}

func parseDoH(s string) []dohServer {
	var out []dohServer
	for _, p := range splitCSV(s) {
		parts := strings.SplitN(p, "@", 2)
		if len(parts) == 2 {
			out = append(out, dohServer{Name: parts[0], IP: parts[1]})
		}
	}
	return out
}

type cacheEntry struct {
	ips []net.IP
	exp time.Time
}

// Resolver does DNS over HTTPS to a fixed IP, and uses the same strategy
// rotation as normal traffic for its own TLS connection, because resolvers
// are filtered by SNI too.
type Resolver struct {
	e       *Engine
	servers []dohServer
	mu      sync.Mutex
	cache   map[string]cacheEntry
	clients map[string]*http.Client
}

func newResolver(e *Engine, servers []dohServer) *Resolver {
	return &Resolver{e: e, servers: servers, cache: map[string]cacheEntry{}, clients: map[string]*http.Client{}}
}

func (r *Resolver) client(s dohServer) *http.Client {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c := r.clients[s.Name]; c != nil {
		return c
	}
	c := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return r.e.dialTLSRotate(ctx, s.IP, "443", s.Name)
			},
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     60 * time.Second,
			DisableCompression:  true,
		},
	}
	r.clients[s.Name] = c
	return c
}

// Lookup returns the IPv4 addresses of host.
func (r *Resolver) Lookup(ctx context.Context, host string) ([]net.IP, error) {
	return r.lookup(ctx, host, false)
}

// LookupAll returns the IPv4 and, unless IPv6 is switched off, the IPv6 addresses of host.
func (r *Resolver) LookupAll(ctx context.Context, host string) ([]net.IP, error) {
	return r.lookup(ctx, host, true)
}

func (r *Resolver) lookup(ctx context.Context, host string, all bool) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	key := host
	if all {
		key += "|all"
	}
	r.mu.Lock()
	if ce, ok := r.cache[key]; ok && time.Now().Before(ce.exp) {
		r.mu.Unlock()
		return ce.ips, nil
	}
	r.mu.Unlock()

	withV6 := all && r.e.ipv6 != "off"
	var last error = errors.New("no DoH server configured")
	for _, s := range r.servers {
		ips, ttl, err := r.queryTypes(ctx, s, host, withV6)
		if err != nil {
			last = err
			continue
		}
		if ttl < 60 {
			ttl = 60
		}
		if ttl > 600 {
			ttl = 600
		}
		r.mu.Lock()
		r.cache[key] = cacheEntry{ips: ips, exp: time.Now().Add(time.Duration(ttl) * time.Second)}
		r.mu.Unlock()
		return ips, nil
	}
	return nil, fmt.Errorf("doh lookup %s: %v", host, last)
}

// queryTypes asks for A, and for AAAA as well when withV6 is set, at the same time.
func (r *Resolver) queryTypes(ctx context.Context, s dohServer, host string, withV6 bool) ([]net.IP, uint32, error) {
	types := []uint16{1}
	if withV6 {
		types = append(types, 28)
	}
	type result struct {
		ips []net.IP
		ttl uint32
		err error
	}
	ch := make(chan result, len(types))
	for _, t := range types {
		go func(t uint16) {
			ips, ttl, err := r.query(ctx, s, host, t)
			ch <- result{ips, ttl, err}
		}(t)
	}
	var all []net.IP
	minTTL := uint32(600)
	var firstErr error
	for range types {
		x := <-ch
		if x.err != nil {
			if firstErr == nil {
				firstErr = x.err
			}
			continue
		}
		all = append(all, x.ips...)
		if len(x.ips) > 0 && x.ttl < minTTL {
			minTTL = x.ttl
		}
	}
	if len(all) == 0 {
		if firstErr != nil {
			return nil, 0, firstErr
		}
		return nil, 0, errors.New("no address records")
	}
	return all, minTTL, nil
}

func (r *Resolver) query(ctx context.Context, s dohServer, host string, qtype uint16) ([]net.IP, uint32, error) {
	q, err := buildQuery(host, qtype)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+s.Name+"/dns-query", bytes.NewReader(q))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := r.client(s).Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("doh status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, 0, err
	}
	return parseAnswers(body)
}

func buildQuery(name string, qtype uint16) ([]byte, error) {
	b := make([]byte, 12, 64)
	if _, err := rand.Read(b[0:2]); err != nil {
		return nil, err
	}
	b[2], b[3] = 0x01, 0x00
	b[5] = 1
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return nil, fmt.Errorf("bad name %q", name)
		}
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0, byte(qtype>>8), byte(qtype), 0, 1)
	return b, nil
}

var errShort = errors.New("short dns message")

func skipName(msg []byte, off int) (int, error) {
	for {
		if off >= len(msg) {
			return 0, errShort
		}
		l := int(msg[off])
		switch {
		case l == 0:
			return off + 1, nil
		case l&0xC0 == 0xC0:
			if off+2 > len(msg) {
				return 0, errShort
			}
			return off + 2, nil
		default:
			off += 1 + l
		}
	}
}

// parseAnswers returns the A and AAAA records of a DNS response and the lowest TTL among them.
func parseAnswers(msg []byte) ([]net.IP, uint32, error) {
	if len(msg) < 12 {
		return nil, 0, errShort
	}
	if rc := msg[3] & 0x0F; rc != 0 {
		return nil, 0, fmt.Errorf("dns rcode %d", rc)
	}
	qd := int(msg[4])<<8 | int(msg[5])
	an := int(msg[6])<<8 | int(msg[7])
	off := 12
	var err error
	for i := 0; i < qd; i++ {
		if off, err = skipName(msg, off); err != nil {
			return nil, 0, err
		}
		off += 4
	}
	var ips []net.IP
	minTTL := uint32(600)
	for i := 0; i < an; i++ {
		if off, err = skipName(msg, off); err != nil {
			return nil, 0, err
		}
		if off+10 > len(msg) {
			return nil, 0, errShort
		}
		t := uint16(msg[off])<<8 | uint16(msg[off+1])
		ttl := uint32(msg[off+4])<<24 | uint32(msg[off+5])<<16 | uint32(msg[off+6])<<8 | uint32(msg[off+7])
		rl := int(msg[off+8])<<8 | int(msg[off+9])
		off += 10
		if off+rl > len(msg) {
			return nil, 0, errShort
		}
		if (t == 1 && rl == 4) || (t == 28 && rl == 16) {
			ips = append(ips, net.IP(append([]byte(nil), msg[off:off+rl]...)))
			if ttl < minTTL {
				minTTL = ttl
			}
		}
		off += rl
	}
	return ips, minTTL, nil
}
