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
	Hosts  map[string]*hostStat `json:"hosts"`
	Global map[string]*score    `json:"global"`
}

// Store remembers, per network, which strategy worked for which host and how
// often each strategy works overall. Mahak uses it to try the most likely
// strategy first and to learn again when the network changes.
type Store struct {
	mu    sync.Mutex
	path  string
	Nets  map[string]*netStat `json:"nets"`
	dirty bool
}

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
		n = &netStat{Hosts: map[string]*hostStat{}, Global: map[string]*score{}}
		s.Nets[key] = n
	}
	if n.Hosts == nil {
		n.Hosts = map[string]*hostStat{}
	}
	if n.Global == nil {
		n.Global = map[string]*score{}
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

// Order returns all strategies, best guess first: the host's last working
// strategy, then the rest by their success rate on this network (ties keep
// the default order).
func (s *Store) Order(netKey, host string, all []Strategy) []Strategy {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.net(netKey)
	out := make([]Strategy, 0, len(all))
	used := map[string]bool{}
	if hs := n.Hosts[host]; hs != nil && hs.Best != "" {
		for _, st := range all {
			if st.Name == hs.Best {
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
	sort.SliceStable(rest, func(i, j int) bool { return n.rate(rest[i].Name) > n.rate(rest[j].Name) })
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
