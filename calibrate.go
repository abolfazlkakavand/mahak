package main

import (
	"context"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// calibrate measures, once per network and then every few hours, how fast a connection runs after
// each strategy and over each IP family, against a host the filter does not block. A flow whose
// first packets the filter cannot read may pass and then be throttled; this finds which
// strategies do that on the current network. The numbers feed Store.Order and filterByFamily.
func (e *Engine) calibrate(ctx context.Context) {
	if !e.store.NeedsCalibration(e.netKey, 6*time.Hour) {
		return
	}
	const host = "speed.cloudflare.com"
	lctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	ips, err := e.dns.LookupAll(lctx, host)
	cancel()
	if err != nil {
		log.Printf("calibration skipped: %v", err)
		return
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
	log.Printf("calibration started")
	var wg sync.WaitGroup
	for fam, ip := range map[string]net.IP{"v4": v4, "v6": v6} {
		if ip == nil {
			continue
		}
		wg.Add(1)
		go func(fam string, ip net.IP) {
			defer wg.Done()
			for _, st := range e.strategies {
				if ctx.Err() != nil {
					return
				}
				if strings.Contains(st.Name, "fake") {
					continue
				}
				pctx, pc := context.WithTimeout(ctx, 20*time.Second)
				kb, why := e.measure(pctx, host, "/__down?bytes=400000", ip, st, 2*time.Second, 400000)
				pc()
				if why != "" {
					kb = 0
				}
				e.store.SetSpeed(e.netKey, fam, st.Name, kb)
				e.logf("calibration %s %s: %.0f KB/s %s", fam, st.Name, kb, why)
			}
		}(fam, ip)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return
	}
	e.store.MarkCalibrated(e.netKey)
	e.store.Save()
	log.Printf("calibration done")
}

// filterByFamily drops, for one strategy, the addresses of an IP family where that strategy is
// known to be slow, as long as another family is left. Without this, the parallel dial can pick
// the slow family only because it answered a few milliseconds earlier.
func (e *Engine) filterByFamily(st Strategy, addrs []string) []string {
	var keep []string
	for _, a := range addrs {
		if sp, ok := e.store.GetSpeed(e.netKey, family(a), st.Name); ok && sp < slowKBps {
			continue
		}
		keep = append(keep, a)
	}
	if len(keep) == 0 {
		return addrs
	}
	return keep
}
