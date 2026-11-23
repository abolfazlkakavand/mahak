package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type score struct {
	OK   int `json:"ok"`
	Fail int `json:"fail"`
}

type hostStat struct {
	Best string `json:"best,omitempty"`
}

type netStat struct {
	Hosts   map[string]*hostStat `json:"hosts"`
	Global  map[string]*score    `json:"global"`
	Speed   map[string]float64   `json:"speed,omitempty"`
	CalibAt int64                `json:"calib_at,omitempty"`
}

// Store remembers, per network, which strategy worked for which host, how often each strategy
// works overall, and how fast a connection is after each strategy and IP family (the numbers the
// calibration measures). The first reason to keep speeds: on the first field test a strategy got
// through the filter and then ran at 9 KB/s, so "passes" alone is not a good enough rule.
type Store struct {
	mu    sync.Mutex
	path  string
	Nets  map[string]*netStat `json:"nets"`
	dirty bool
}

const (
	slowKBps    = 40.0
	neutralKBps = 300.0
)

func loadStore(path string) *Store {
	s := &Store{path: path, Nets: map[string]*netStat{}}
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, s); err != nil {
			log.Printf("state file ignored: %v", err)
			s.Nets = map[string]*netStat{}
		}
	}
	if s.Nets == nil {
		s.Nets = map[string]*netStat{}
	}
	return s
}

func (s *Store) net(key string) *netStat {
	n := s.Nets[key]
	if n == nil {
		n = &netStat{}
		s.Nets[key] = n
	}
	if n.Hosts == nil {
		n.Hosts = map[string]*hostStat{}
	}
	if n.Global == nil {
		n.Global = map[string]*score{}
	}
	if n.Speed == nil {
		n.Speed = map[string]float64{}
	}
	return n
}

func (n *netStat) rate(name string) float64 {
	sc := n.Global[name]
	if sc == nil {
		return 0.5
	}
	return float64(sc.OK+1) / float64(sc.OK+sc.Fail+2)
}

func speedKey(fam, name string) string { return fam + "|" + name }

// speedOf is the measured speed in KB/s, or a neutral guess when this strategy has not been measured.
func (n *netStat) speedOf(fam, name string) float64 {
	if v, ok := n.Speed[speedKey(fam, name)]; ok {
		return v
	}
	return neutralKBps
}

// tier groups speeds so that measurement noise between two fast strategies does not reorder them.
func tier(v float64) int {
	switch {
	case v < slowKBps:
		return 0
	case v < 400:
		return 1
	case v < 1000:
		return 2
	}
	return 3
}

// Order returns all strategies, best guess first: the host's last working strategy (unless it is
// known to be slow on this IP family), then the rest by speed tier on this family, then by how
// often they get through (ties keep the default order).
func (s *Store) Order(netKey, host, fam string, all []Strategy) []Strategy {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.net(netKey)
	out := make([]Strategy, 0, len(all))
	used := map[string]bool{}
	if hs := n.Hosts[host]; hs != nil && hs.Best != "" {
		for _, st := range all {
			if st.Name == hs.Best && n.speedOf(fam, st.Name) >= slowKBps {
				out = append(out, st)
				used[st.Name] = true
			}
		}
	}
	var rest []Strategy
	for _, st := range all {
		if !used[st.Name] {
			rest = append(rest, st)
		}
	}
	sort.SliceStable(rest, func(i, j int) bool {
		ti, tj := tier(n.speedOf(fam, rest[i].Name)), tier(n.speedOf(fam, rest[j].Name))
		if ti != tj {
			return ti > tj
		}
		return n.rate(rest[i].Name) > n.rate(rest[j].Name)
	})
	return append(out, rest...)
}

func (s *Store) Success(netKey, host, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.net(netKey)
	if n.Hosts[host] == nil {
		n.Hosts[host] = &hostStat{}
	}
	n.Hosts[host].Best = name
	if n.Global[name] == nil {
		n.Global[name] = &score{}
	}
	n.Global[name].OK++
	s.dirty = true
}

func (s *Store) Fail(netKey, host, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.net(netKey)
	if hs := n.Hosts[host]; hs != nil && hs.Best == name {
		hs.Best = ""
	}
	if n.Global[name] == nil {
		n.Global[name] = &score{}
	}
	n.Global[name].Fail++
	s.dirty = true
}

func (s *Store) SetSpeed(netKey, fam, name string, kbps float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.net(netKey).Speed[speedKey(fam, name)] = kbps
	s.dirty = true
}

func (s *Store) GetSpeed(netKey, fam, name string) (float64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.net(netKey).Speed[speedKey(fam, name)]
	return v, ok
}

func (s *Store) NeedsCalibration(netKey string, maxAge time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.net(netKey)
	return n.CalibAt == 0 || time.Since(time.Unix(n.CalibAt, 0)) > maxAge
}

func (s *Store) MarkCalibrated(netKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.net(netKey).CalibAt = time.Now().Unix()
	s.dirty = true
}

func (s *Store) Save() {
	s.mu.Lock()
	if !s.dirty || s.path == "" {
		s.mu.Unlock()
		return
	}
	b, err := json.MarshalIndent(s, "", " ")
	s.dirty = false
	s.mu.Unlock()
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		log.Printf("state dir: %v", err)
		return
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		log.Printf("state write: %v", err)
		return
	}
	_ = os.Rename(tmp, s.path)
}

func (s *Store) StartAutoSave(ctx context.Context) {
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				s.Save()
				return
			case <-t.C:
				s.Save()
			}
		}
	}()
}
