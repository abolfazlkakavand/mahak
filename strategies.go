package main

import (
	"log"
	"strings"
	"time"

	"github.com/Nemu-x/desync"
)

// Strategy is one way of sending the first TLS ClientHello of a connection.
// The wire tricks themselves come from the MIT-licensed desync library
// (which in turn follows ByeDPI and zapret); Mahak's own part is choosing
// among them per network and per host, see engine.go and store.go.
type Strategy struct {
	Name string
	Opts desync.Options
}

func sni(off int) desync.Pos { return desync.Pos{Offset: off, FromSNI: true} }

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// buildStrategies returns the default order. It follows the first field probe
// (MCI, Nov 2026): TLS record splitting and the urgent byte passed every
// reachable host, plain and TCP splitting were reset, and the low-TTL decoys
// were unreliable. Order only matters until a network has taught the store
// something better; the store then reorders by what worked.
func buildStrategies(decoys []string) []Strategy {
	fake := func(ttl int) *desync.FakeOptions {
		return &desync.FakeOptions{TTL: ttl, Prefix: -1, SNI: decoys, Randomize: true}
	}
	one := []desync.Pos{sni(1)}
	return []Strategy{
		{"tlsrec-1s", desync.Options{TLSRec: []desync.Pos{sni(1)}}},
		{"tlsrec-m3s", desync.Options{TLSRec: []desync.Pos{sni(-3)}}},
		{"oob-1s", desync.Options{Split: one, OOB: &desync.OOBOptions{}}},
		{"tlsrec-split", desync.Options{TLSRec: []desync.Pos{sni(1)}, Split: one}},
		{"tlsrec-multi", desync.Options{TLSRec: []desync.Pos{sni(-8), sni(1), sni(8)}}},
		{"disoob-1s", desync.Options{Split: one, Disorder: true, OOB: &desync.OOBOptions{}}},
		{"split-1s", desync.Options{Split: one}},
		{"split-1s-wait", desync.Options{Split: one, SplitWait: desync.SplitWaitAcked, SplitWaitTimeout: time.Second}},
		{"disorder-1s", desync.Options{Split: one, Disorder: true}},
		{"plain", desync.Options{}},
		{"fake-ttl3", desync.Options{Fake: fake(3)}},
		{"disorder-fake5", desync.Options{Split: one, Disorder: true, Fake: fake(5)}},
		{"fake-ttl5", desync.Options{Fake: fake(5)}},
		{"fake-ttl8", desync.Options{Fake: fake(8)}},
		{"fake-auto", desync.Options{Fake: &desync.FakeOptions{AutoTTL: &desync.AutoTTL{}, TTL: 5, Prefix: -1, SNI: decoys, Randomize: true}}},
		{"tlsrec-fake5", desync.Options{TLSRec: []desync.Pos{sni(1)}, Fake: fake(5)}},
		{"split-fake5", desync.Options{Split: one, Fake: fake(5)}},
	}
}

func validStrategies(in []Strategy) []Strategy {
	var out []Strategy
	for _, s := range in {
		if s.Name != "plain" {
			if err := s.Opts.Validate(); err != nil {
				log.Printf("strategy %s skipped: %v", s.Name, err)
				continue
			}
		}
		out = append(out, s)
	}
	return out
}
