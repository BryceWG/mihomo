package dns

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

const dnsStatsBucketSize = time.Second

var dnsStatsWindowDurations = map[string]time.Duration{
	"1m": time.Minute,
	"5m": 5 * time.Minute,
	"1h": time.Hour,
}

type DNSStatsSnapshot struct {
	Queries                uint64                            `json:"queries"`
	CacheHits              uint64                            `json:"cacheHits"`
	CacheMisses            uint64                            `json:"cacheMisses"`
	CacheHitRate           float64                           `json:"cacheHitRate"`
	OptimisticCacheHits    uint64                            `json:"optimisticCacheHits"`
	OptimisticCacheHitRate float64                           `json:"optimisticCacheHitRate"`
	Prefetches             uint64                            `json:"prefetches"`
	PrefetchSuccesses      uint64                            `json:"prefetchSuccesses"`
	PrefetchFailures       uint64                            `json:"prefetchFailures"`
	ServerRequests         uint64                            `json:"serverRequests"`
	TotalLatencyMs         float64                           `json:"totalLatencyMs"`
	AverageLatencyMs       float64                           `json:"averageLatencyMs"`
	ServerTotalLatencyMs   float64                           `json:"serverTotalLatencyMs"`
	ServerAverageLatencyMs float64                           `json:"serverAverageLatencyMs"`
	Servers                map[string]DNSServerStatsSnapshot `json:"servers,omitempty"`
	Windows                map[string]DNSStatsSnapshot       `json:"windows,omitempty"`
}

type DNSServerStatsSnapshot struct {
	Address          string            `json:"address"`
	Requests         uint64            `json:"requests"`
	Successes        uint64            `json:"successes"`
	Failures         uint64            `json:"failures"`
	Cancellations    uint64            `json:"cancellations"`
	RCode            map[string]uint64 `json:"rcode,omitempty"`
	TotalLatencyMs   float64           `json:"totalLatencyMs"`
	AverageLatencyMs float64           `json:"averageLatencyMs"`
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

	serverMu sync.RWMutex
	servers  map[string]*dnsServerStats

	windows []*dnsStatsWindow
}

type dnsServerStats struct {
	requests       uint64
	successes      uint64
	failures       uint64
	cancellations  uint64
	totalLatencyNs uint64
	rcode          map[string]uint64
}

type dnsStatsCounters struct {
	queries              uint64
	cacheHits            uint64
	cacheMisses          uint64
	optimisticCacheHits  uint64
	prefetches           uint64
	prefetchSuccesses    uint64
	prefetchFailures     uint64
	serverRequests       uint64
	totalLatencyNs       uint64
	serverTotalLatencyNs uint64
}

type dnsServerStatsCounters struct {
	requests       uint64
	successes      uint64
	failures       uint64
	cancellations  uint64
	totalLatencyNs uint64
	rcode          map[string]uint64
}

type dnsStatsBucket struct {
	start   int64
	stats   dnsStatsCounters
	servers map[string]*dnsServerStatsCounters
}

type dnsStatsWindow struct {
	name       string
	duration   time.Duration
	bucketSize time.Duration
	buckets    []dnsStatsBucket
	mu         sync.Mutex
}

func newDNSStats() *dnsStats {
	stats := &dnsStats{
		servers: map[string]*dnsServerStats{},
		windows: make([]*dnsStatsWindow, 0, len(dnsStatsWindowDurations)),
	}
	for name, duration := range dnsStatsWindowDurations {
		stats.windows = append(stats.windows, newDNSStatsWindow(name, duration, dnsStatsBucketSize))
	}
	return stats
}

func newDNSStatsWindow(name string, duration, bucketSize time.Duration) *dnsStatsWindow {
	bucketCount := int(duration / bucketSize)
	if bucketCount <= 0 {
		bucketCount = 1
	}
	return &dnsStatsWindow{
		name:       name,
		duration:   duration,
		bucketSize: bucketSize,
		buckets:    make([]dnsStatsBucket, bucketCount),
	}
}

func (s *dnsStats) recordQuery(duration time.Duration) {
	if s == nil {
		return
	}
	s.queries.Add(1)
	s.totalLatencyNs.Add(uint64(duration))
	s.recordWindow(func(c *dnsStatsCounters) {
		c.queries++
		c.totalLatencyNs += uint64(duration)
	})
}

func (s *dnsStats) recordCacheHit(optimistic bool) {
	if s == nil {
		return
	}
	s.cacheHits.Add(1)
	if optimistic {
		s.optimisticCacheHits.Add(1)
	}
	s.recordWindow(func(c *dnsStatsCounters) {
		c.cacheHits++
		if optimistic {
			c.optimisticCacheHits++
		}
	})
}

func (s *dnsStats) recordCacheMiss() {
	if s == nil {
		return
	}
	s.cacheMisses.Add(1)
	s.recordWindow(func(c *dnsStatsCounters) {
		c.cacheMisses++
	})
}

func (s *dnsStats) recordServerRequest(address string, duration time.Duration, rcode string, err error) {
	if s == nil {
		return
	}

	canceled := isCanceledDNSError(err)
	success := err == nil

	s.serverRequests.Add(1)
	s.serverTotalLatencyNs.Add(uint64(duration))

	s.serverMu.Lock()
	server := s.servers[address]
	if server == nil {
		server = &dnsServerStats{rcode: map[string]uint64{}}
		s.servers[address] = server
	}
	server.requests++
	server.totalLatencyNs += uint64(duration)
	switch {
	case success:
		server.successes++
	case canceled:
		server.cancellations++
	default:
		server.failures++
	}
	if rcode != "" {
		server.rcode[rcode]++
	}
	s.serverMu.Unlock()

	s.recordServerWindow(address, duration, rcode, success, canceled)
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
	s.recordWindow(func(c *dnsStatsCounters) {
		c.prefetches++
		if success {
			c.prefetchSuccesses++
		} else {
			c.prefetchFailures++
		}
	})
}

func (s *dnsStats) recordWindow(recorders ...func(*dnsStatsCounters)) {
	for _, window := range s.windows {
		window.record(time.Now(), recorders...)
	}
}

func (s *dnsStats) recordServerWindow(address string, duration time.Duration, rcode string, success, canceled bool) {
	now := time.Now()
	for _, window := range s.windows {
		window.recordServer(now, address, duration, rcode, success, canceled)
	}
}

func (s *dnsStats) snapshot() DNSStatsSnapshot {
	if s == nil {
		return DNSStatsSnapshot{}
	}
	snapshot := dnsStatsCounters{
		queries:              s.queries.Load(),
		cacheHits:            s.cacheHits.Load(),
		cacheMisses:          s.cacheMisses.Load(),
		optimisticCacheHits:  s.optimisticCacheHits.Load(),
		prefetches:           s.prefetches.Load(),
		prefetchSuccesses:    s.prefetchSuccesses.Load(),
		prefetchFailures:     s.prefetchFailures.Load(),
		serverRequests:       s.serverRequests.Load(),
		totalLatencyNs:       s.totalLatencyNs.Load(),
		serverTotalLatencyNs: s.serverTotalLatencyNs.Load(),
	}

	result := snapshotFromCounters(snapshot)
	result.Servers = s.serverSnapshots()
	result.Windows = make(map[string]DNSStatsSnapshot, len(s.windows))
	now := time.Now()
	for _, window := range s.windows {
		result.Windows[window.name] = window.snapshot(now)
	}
	return result
}

func (s *dnsStats) serverSnapshots() map[string]DNSServerStatsSnapshot {
	s.serverMu.RLock()
	defer s.serverMu.RUnlock()

	if len(s.servers) == 0 {
		return nil
	}
	servers := make(map[string]DNSServerStatsSnapshot, len(s.servers))
	for address, server := range s.servers {
		servers[address] = serverSnapshotFromCounters(address, dnsServerStatsCounters{
			requests:       server.requests,
			successes:      server.successes,
			failures:       server.failures,
			cancellations:  server.cancellations,
			totalLatencyNs: server.totalLatencyNs,
			rcode:          cloneRCode(server.rcode),
		})
	}
	return servers
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

	s.serverMu.Lock()
	s.servers = map[string]*dnsServerStats{}
	s.serverMu.Unlock()

	for _, window := range s.windows {
		window.reset()
	}
}

func (w *dnsStatsWindow) record(now time.Time, recorders ...func(*dnsStatsCounters)) {
	bucketStart := now.Unix()
	index := int((bucketStart / int64(w.bucketSize/time.Second)) % int64(len(w.buckets)))

	w.mu.Lock()
	defer w.mu.Unlock()

	bucket := &w.buckets[index]
	if bucket.start != bucketStart {
		*bucket = dnsStatsBucket{start: bucketStart}
	}
	for _, record := range recorders {
		record(&bucket.stats)
	}
}

func (w *dnsStatsWindow) recordServer(now time.Time, address string, duration time.Duration, rcode string, success, canceled bool) {
	bucketStart := now.Unix()
	index := int((bucketStart / int64(w.bucketSize/time.Second)) % int64(len(w.buckets)))

	w.mu.Lock()
	defer w.mu.Unlock()

	bucket := &w.buckets[index]
	if bucket.start != bucketStart {
		*bucket = dnsStatsBucket{start: bucketStart}
	}
	bucket.stats.serverRequests++
	bucket.stats.serverTotalLatencyNs += uint64(duration)
	if bucket.servers == nil {
		bucket.servers = map[string]*dnsServerStatsCounters{}
	}
	server := bucket.servers[address]
	if server == nil {
		server = &dnsServerStatsCounters{rcode: map[string]uint64{}}
		bucket.servers[address] = server
	}
	server.requests++
	server.totalLatencyNs += uint64(duration)
	switch {
	case success:
		server.successes++
	case canceled:
		server.cancellations++
	default:
		server.failures++
	}
	if rcode != "" {
		server.rcode[rcode]++
	}
}

func (w *dnsStatsWindow) snapshot(now time.Time) DNSStatsSnapshot {
	w.mu.Lock()
	defer w.mu.Unlock()

	minStart := now.Add(-w.duration).Unix()
	var counters dnsStatsCounters
	servers := map[string]*dnsServerStatsCounters{}
	for i := range w.buckets {
		bucket := &w.buckets[i]
		if bucket.start < minStart {
			continue
		}
		counters.add(bucket.stats)
		for address, server := range bucket.servers {
			dst := servers[address]
			if dst == nil {
				dst = &dnsServerStatsCounters{rcode: map[string]uint64{}}
				servers[address] = dst
			}
			dst.add(*server)
		}
	}

	result := snapshotFromCounters(counters)
	if len(servers) > 0 {
		result.Servers = make(map[string]DNSServerStatsSnapshot, len(servers))
		for address, server := range servers {
			result.Servers[address] = serverSnapshotFromCounters(address, *server)
		}
	}
	return result
}

func (w *dnsStatsWindow) reset() {
	w.mu.Lock()
	defer w.mu.Unlock()
	for i := range w.buckets {
		w.buckets[i] = dnsStatsBucket{}
	}
}

func (c *dnsStatsCounters) add(other dnsStatsCounters) {
	c.queries += other.queries
	c.cacheHits += other.cacheHits
	c.cacheMisses += other.cacheMisses
	c.optimisticCacheHits += other.optimisticCacheHits
	c.prefetches += other.prefetches
	c.prefetchSuccesses += other.prefetchSuccesses
	c.prefetchFailures += other.prefetchFailures
	c.serverRequests += other.serverRequests
	c.totalLatencyNs += other.totalLatencyNs
	c.serverTotalLatencyNs += other.serverTotalLatencyNs
}

func (c *dnsServerStatsCounters) add(other dnsServerStatsCounters) {
	c.requests += other.requests
	c.successes += other.successes
	c.failures += other.failures
	c.cancellations += other.cancellations
	c.totalLatencyNs += other.totalLatencyNs
	if c.rcode == nil {
		c.rcode = map[string]uint64{}
	}
	for rcode, count := range other.rcode {
		c.rcode[rcode] += count
	}
}

func snapshotFromCounters(counters dnsStatsCounters) DNSStatsSnapshot {
	snapshot := DNSStatsSnapshot{
		Queries:              counters.queries,
		CacheHits:            counters.cacheHits,
		CacheMisses:          counters.cacheMisses,
		OptimisticCacheHits:  counters.optimisticCacheHits,
		Prefetches:           counters.prefetches,
		PrefetchSuccesses:    counters.prefetchSuccesses,
		PrefetchFailures:     counters.prefetchFailures,
		ServerRequests:       counters.serverRequests,
		TotalLatencyMs:       nsToMs(counters.totalLatencyNs),
		ServerTotalLatencyMs: nsToMs(counters.serverTotalLatencyNs),
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

func serverSnapshotFromCounters(address string, counters dnsServerStatsCounters) DNSServerStatsSnapshot {
	snapshot := DNSServerStatsSnapshot{
		Address:        address,
		Requests:       counters.requests,
		Successes:      counters.successes,
		Failures:       counters.failures,
		Cancellations:  counters.cancellations,
		RCode:          cloneRCode(counters.rcode),
		TotalLatencyMs: nsToMs(counters.totalLatencyNs),
	}
	if snapshot.Requests > 0 {
		snapshot.AverageLatencyMs = snapshot.TotalLatencyMs / float64(snapshot.Requests)
	}
	return snapshot
}

func combineDNSStatsSnapshots(snapshots ...DNSStatsSnapshot) DNSStatsSnapshot {
	var counters dnsStatsCounters
	servers := map[string]*dnsServerStatsCounters{}
	windows := map[string][]DNSStatsSnapshot{}

	for _, snapshot := range snapshots {
		counters.add(countersFromSnapshot(snapshot))
		addServerSnapshots(servers, snapshot.Servers)
		for name, window := range snapshot.Windows {
			windows[name] = append(windows[name], window)
		}
	}

	result := snapshotFromCounters(counters)
	if len(servers) > 0 {
		result.Servers = make(map[string]DNSServerStatsSnapshot, len(servers))
		for address, server := range servers {
			result.Servers[address] = serverSnapshotFromCounters(address, *server)
		}
	}
	if len(windows) > 0 {
		result.Windows = make(map[string]DNSStatsSnapshot, len(windows))
		for name, snapshots := range windows {
			result.Windows[name] = combineDNSStatsSnapshots(snapshots...)
		}
	}
	return result
}

func countersFromSnapshot(snapshot DNSStatsSnapshot) dnsStatsCounters {
	return dnsStatsCounters{
		queries:              snapshot.Queries,
		cacheHits:            snapshot.CacheHits,
		cacheMisses:          snapshot.CacheMisses,
		optimisticCacheHits:  snapshot.OptimisticCacheHits,
		prefetches:           snapshot.Prefetches,
		prefetchSuccesses:    snapshot.PrefetchSuccesses,
		prefetchFailures:     snapshot.PrefetchFailures,
		serverRequests:       snapshot.ServerRequests,
		totalLatencyNs:       msToNs(snapshot.TotalLatencyMs),
		serverTotalLatencyNs: msToNs(snapshot.ServerTotalLatencyMs),
	}
}

func addServerSnapshots(dst map[string]*dnsServerStatsCounters, snapshots map[string]DNSServerStatsSnapshot) {
	for address, snapshot := range snapshots {
		server := dst[address]
		if server == nil {
			server = &dnsServerStatsCounters{rcode: map[string]uint64{}}
			dst[address] = server
		}
		server.add(dnsServerStatsCounters{
			requests:       snapshot.Requests,
			successes:      snapshot.Successes,
			failures:       snapshot.Failures,
			cancellations:  snapshot.Cancellations,
			totalLatencyNs: msToNs(snapshot.TotalLatencyMs),
			rcode:          snapshot.RCode,
		})
	}
}

func cloneRCode(src map[string]uint64) map[string]uint64 {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]uint64, len(src))
	for rcode, count := range src {
		dst[rcode] = count
	}
	return dst
}

func isCanceledDNSError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func nsToMs(ns uint64) float64 {
	return float64(ns) / float64(time.Millisecond)
}

func msToNs(ms float64) uint64 {
	return uint64(ms * float64(time.Millisecond))
}
