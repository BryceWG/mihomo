package dns

import (
	"sync/atomic"
	"time"
)

type DNSStatsSnapshot struct {
	Queries                uint64  `json:"queries"`
	CacheHits              uint64  `json:"cacheHits"`
	CacheMisses            uint64  `json:"cacheMisses"`
	CacheHitRate           float64 `json:"cacheHitRate"`
	OptimisticCacheHits    uint64  `json:"optimisticCacheHits"`
	OptimisticCacheHitRate float64 `json:"optimisticCacheHitRate"`
	Prefetches             uint64  `json:"prefetches"`
	PrefetchSuccesses      uint64  `json:"prefetchSuccesses"`
	PrefetchFailures       uint64  `json:"prefetchFailures"`
	ServerRequests         uint64  `json:"serverRequests"`
	TotalLatencyMs         float64 `json:"totalLatencyMs"`
	AverageLatencyMs       float64 `json:"averageLatencyMs"`
	ServerTotalLatencyMs   float64 `json:"serverTotalLatencyMs"`
	ServerAverageLatencyMs float64 `json:"serverAverageLatencyMs"`
}

type dnsStats struct {
	queries              atomic.Uint64
	cacheHits            atomic.Uint64
	cacheMisses          atomic.Uint64
	optimisticCacheHits  atomic.Uint64
	prefetches           atomic.Uint64
	prefetchSuccesses    atomic.Uint64
	prefetchFailures     atomic.Uint64
	serverRequests       atomic.Uint64
	totalLatencyNs       atomic.Uint64
	serverTotalLatencyNs atomic.Uint64
}

func newDNSStats() *dnsStats {
	return &dnsStats{}
}

func (s *dnsStats) recordQuery(duration time.Duration) {
	if s == nil {
		return
	}
	s.queries.Add(1)
	s.totalLatencyNs.Add(uint64(duration))
}

func (s *dnsStats) recordCacheHit(optimistic bool) {
	if s == nil {
		return
	}
	s.cacheHits.Add(1)
	if optimistic {
		s.optimisticCacheHits.Add(1)
	}
}

func (s *dnsStats) recordCacheMiss() {
	if s == nil {
		return
	}
	s.cacheMisses.Add(1)
}

func (s *dnsStats) recordServerRequest(duration time.Duration) {
	if s == nil {
		return
	}
	s.serverRequests.Add(1)
	s.serverTotalLatencyNs.Add(uint64(duration))
}

func (s *dnsStats) recordPrefetch(success bool) {
	if s == nil {
		return
	}
	s.prefetches.Add(1)
	if success {
		s.prefetchSuccesses.Add(1)
	} else {
		s.prefetchFailures.Add(1)
	}
}

func (s *dnsStats) snapshot() DNSStatsSnapshot {
	if s == nil {
		return DNSStatsSnapshot{}
	}
	snapshot := DNSStatsSnapshot{
		Queries:              s.queries.Load(),
		CacheHits:            s.cacheHits.Load(),
		CacheMisses:          s.cacheMisses.Load(),
		OptimisticCacheHits:  s.optimisticCacheHits.Load(),
		Prefetches:           s.prefetches.Load(),
		PrefetchSuccesses:    s.prefetchSuccesses.Load(),
		PrefetchFailures:     s.prefetchFailures.Load(),
		ServerRequests:       s.serverRequests.Load(),
		TotalLatencyMs:       nsToMs(s.totalLatencyNs.Load()),
		ServerTotalLatencyMs: nsToMs(s.serverTotalLatencyNs.Load()),
	}
	if snapshot.Queries > 0 {
		snapshot.CacheHitRate = float64(snapshot.CacheHits) / float64(snapshot.Queries)
		snapshot.OptimisticCacheHitRate = float64(snapshot.OptimisticCacheHits) / float64(snapshot.Queries)
		snapshot.AverageLatencyMs = snapshot.TotalLatencyMs / float64(snapshot.Queries)
	}
	if snapshot.ServerRequests > 0 {
		snapshot.ServerAverageLatencyMs = snapshot.ServerTotalLatencyMs / float64(snapshot.ServerRequests)
	}
	return snapshot
}

func (s *dnsStats) reset() {
	if s == nil {
		return
	}
	s.queries.Store(0)
	s.cacheHits.Store(0)
	s.cacheMisses.Store(0)
	s.optimisticCacheHits.Store(0)
	s.prefetches.Store(0)
	s.prefetchSuccesses.Store(0)
	s.prefetchFailures.Store(0)
	s.serverRequests.Store(0)
	s.totalLatencyNs.Store(0)
	s.serverTotalLatencyNs.Store(0)
}

func (s *dnsStats) addSnapshot(snapshot DNSStatsSnapshot) {
	if s == nil {
		return
	}
	s.queries.Add(snapshot.Queries)
	s.cacheHits.Add(snapshot.CacheHits)
	s.cacheMisses.Add(snapshot.CacheMisses)
	s.optimisticCacheHits.Add(snapshot.OptimisticCacheHits)
	s.prefetches.Add(snapshot.Prefetches)
	s.prefetchSuccesses.Add(snapshot.PrefetchSuccesses)
	s.prefetchFailures.Add(snapshot.PrefetchFailures)
	s.serverRequests.Add(snapshot.ServerRequests)
	s.totalLatencyNs.Add(msToNs(snapshot.TotalLatencyMs))
	s.serverTotalLatencyNs.Add(msToNs(snapshot.ServerTotalLatencyMs))
}

func nsToMs(ns uint64) float64 {
	return float64(ns) / float64(time.Millisecond)
}

func msToNs(ms float64) uint64 {
	return uint64(ms * float64(time.Millisecond))
}
