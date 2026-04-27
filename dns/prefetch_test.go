package dns

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/lru"

	D "github.com/miekg/dns"
)

func TestPrefetchFailureCooldownBlocksRetry(t *testing.T) {
	now := time.Unix(1700000000, 0)
	question := D.Question{Name: "example.com.", Qtype: D.TypeA, Qclass: D.ClassINET}
	key := question.String()
	expire := now.Add(10 * time.Second)
	cache := lru.New[string, *D.Msg](lru.WithStale[string, *D.Msg](true))
	cache.SetWithExpire(key, newPrefetchTestMsg(question), expire)

	entry := &prefetchEntry{
		key:    key,
		expire: expire,
	}
	entry.question = question
	entry.refreshCount.Store(defaultPrefetchMinRefreshes)

	manager := &prefetchManager{
		resolver: &Resolver{cache: cache, optimisticCacheTTL: time.Hour},
		config: prefetchConfig{
			scanInterval: defaultPrefetchScanInterval,
			threshold:    defaultPrefetchThreshold,
			minRefreshes: defaultPrefetchMinRefreshes,
		},
	}

	if !manager.shouldPrefetch(entry, now) {
		t.Fatal("expected hot near-expiry entry to be eligible before a failure")
	}

	manager.recordPrefetchFailure(entry, now)
	nextAttempt, failureCount := prefetchTestFailureState(entry)
	firstDelay := nextAttempt.Sub(now)
	if failureCount != 1 {
		t.Fatalf("expected one failure, got %d", failureCount)
	}
	if firstDelay < defaultPrefetchBackoffBase || firstDelay > defaultPrefetchBackoffMax {
		t.Fatalf("first backoff %s outside expected range", firstDelay)
	}
	if manager.shouldPrefetch(entry, now.Add(defaultPrefetchScanInterval)) {
		t.Fatal("expected cooldown to block the next scan interval retry")
	}
	if !manager.shouldPrefetch(entry, nextAttempt) {
		t.Fatal("expected entry to become eligible when cooldown expires")
	}

	manager.recordPrefetchFailure(entry, nextAttempt)
	secondAttempt, failureCount := prefetchTestFailureState(entry)
	secondDelay := secondAttempt.Sub(nextAttempt)
	if failureCount != 2 {
		t.Fatalf("expected two failures, got %d", failureCount)
	}
	if secondDelay <= firstDelay {
		t.Fatalf("expected backoff to grow after consecutive failures, first=%s second=%s", firstDelay, secondDelay)
	}
}

func TestPrefetchSuccessClearsFailureCooldown(t *testing.T) {
	now := time.Unix(1700000000, 0)
	question := D.Question{Name: "example.net.", Qtype: D.TypeA, Qclass: D.ClassINET}
	key := question.String()
	expire := now.Add(10 * time.Second)
	cache := lru.New[string, *D.Msg](lru.WithStale[string, *D.Msg](true))
	cache.SetWithExpire(key, newPrefetchTestMsg(question), expire)

	entry := &prefetchEntry{
		key:    key,
		expire: expire,
	}
	entry.question = question
	entry.refreshCount.Store(defaultPrefetchMinRefreshes)

	manager := &prefetchManager{
		resolver: &Resolver{cache: cache, optimisticCacheTTL: time.Hour},
		config: prefetchConfig{
			scanInterval: defaultPrefetchScanInterval,
			threshold:    defaultPrefetchThreshold,
			minRefreshes: defaultPrefetchMinRefreshes,
		},
	}

	manager.recordPrefetchFailure(entry, now)
	if manager.shouldPrefetch(entry, now.Add(defaultPrefetchScanInterval)) {
		t.Fatal("expected failure cooldown to block prefetch")
	}

	manager.recordPrefetchSuccess(entry)
	if nextAttempt, failureCount := prefetchTestFailureState(entry); failureCount != 0 || !nextAttempt.IsZero() {
		t.Fatalf("expected success to clear failure state, failureCount=%d nextAttempt=%s", failureCount, nextAttempt)
	}
	if !manager.shouldPrefetch(entry, now.Add(defaultPrefetchScanInterval)) {
		t.Fatal("expected success-cleared entry to be eligible again")
	}
}

func TestPrefetchColdEntryRetainedBeforeServiceWindowEnds(t *testing.T) {
	now := time.Unix(1700000000, 0)
	question := D.Question{Name: "cold-retained.example.", Qtype: D.TypeA, Qclass: D.ClassINET}
	key := question.String()
	expire := now.Add(-30 * time.Second)
	cache := lru.New[string, *D.Msg](lru.WithStale[string, *D.Msg](true))
	cache.SetWithExpire(key, newPrefetchTestMsg(question), expire)

	entry := &prefetchEntry{
		key:      key,
		question: question,
		expire:   expire,
	}

	manager := &prefetchManager{
		resolver: &Resolver{cache: cache, optimisticCacheTTL: time.Hour},
		config: prefetchConfig{
			scanInterval: defaultPrefetchScanInterval,
			threshold:    defaultPrefetchThreshold,
			minRefreshes: defaultPrefetchMinRefreshes,
		},
		entries: map[string]*prefetchEntry{key: entry},
	}

	if manager.shouldPrefetch(entry, now) {
		t.Fatal("expected cold entry to stay ineligible for prefetch")
	}
	if manager.entry(key) == nil {
		t.Fatal("expected cold entry to be retained within optimistic service window")
	}
}

func TestPrefetchColdEntryRemovedAfterServiceWindowEnds(t *testing.T) {
	now := time.Unix(1700000000, 0)
	question := D.Question{Name: "cold-removed.example.", Qtype: D.TypeA, Qclass: D.ClassINET}
	key := question.String()
	expire := now.Add(-time.Hour - time.Second)
	cache := lru.New[string, *D.Msg](lru.WithStale[string, *D.Msg](true))
	cache.SetWithExpire(key, newPrefetchTestMsg(question), expire)

	entry := &prefetchEntry{
		key:      key,
		question: question,
		expire:   expire,
	}

	manager := &prefetchManager{
		resolver: &Resolver{cache: cache, optimisticCacheTTL: time.Hour},
		config: prefetchConfig{
			scanInterval: defaultPrefetchScanInterval,
			threshold:    defaultPrefetchThreshold,
			minRefreshes: defaultPrefetchMinRefreshes,
		},
		entries: map[string]*prefetchEntry{key: entry},
	}

	if manager.shouldPrefetch(entry, now) {
		t.Fatal("expected cold entry to stay ineligible for prefetch")
	}
	if manager.entry(key) != nil {
		t.Fatal("expected cold entry to be removed after optimistic service window")
	}
}

func TestPrefetchStoreMetaFiltersQtype(t *testing.T) {
	now := time.Unix(1700000000, 0)
	manager := &prefetchManager{
		entries: make(map[string]*prefetchEntry),
	}

	allowed := []uint16{D.TypeA, D.TypeAAAA, D.TypeCNAME, D.TypeHTTPS}
	for _, qtype := range allowed {
		question := D.Question{Name: "allowed.example.", Qtype: qtype, Qclass: D.ClassINET}
		key := question.String()
		manager.storeMeta(dnsCacheMeta{
			key:         key,
			question:    question,
			cachedAt:    now,
			expire:      now.Add(time.Minute),
			originalTTL: time.Minute,
		})

		entry := manager.entry(key)
		if entry == nil {
			t.Fatalf("expected qtype %s to be tracked", D.TypeToString[qtype])
		}
		if entry.question.Qtype != qtype {
			t.Fatalf("expected qtype %s, got %s", D.TypeToString[qtype], D.TypeToString[entry.question.Qtype])
		}
	}

	rejected := []uint16{D.TypeTXT, D.TypeMX, D.TypeSVCB}
	for _, qtype := range rejected {
		question := D.Question{Name: "rejected.example.", Qtype: qtype, Qclass: D.ClassINET}
		key := question.String()
		manager.entries[key] = &prefetchEntry{key: key, question: question}
		manager.storeMeta(dnsCacheMeta{
			key:         key,
			question:    question,
			cachedAt:    now,
			expire:      now.Add(time.Minute),
			originalTTL: time.Minute,
		})

		if manager.entry(key) != nil {
			t.Fatalf("expected qtype %s to be removed from prefetch tracking", D.TypeToString[qtype])
		}
	}
}

func TestPrefetchCandidatesSortedByUrgencyAndHeat(t *testing.T) {
	now := time.Unix(1700000000, 0)
	cache := lru.New[string, *D.Msg](lru.WithStale[string, *D.Msg](true))
	manager := &prefetchManager{
		resolver: &Resolver{cache: cache, optimisticCacheTTL: time.Hour},
		config: prefetchConfig{
			threshold:    defaultPrefetchThreshold,
			minRefreshes: defaultPrefetchMinRefreshes,
		},
	}

	expired := newPrefetchTestEntry(t, cache, "expired.example.", now.Add(-time.Second), 2)
	soonLowHeat := newPrefetchTestEntry(t, cache, "soon-low.example.", now.Add(5*time.Second), 2)
	soonHighHeat := newPrefetchTestEntry(t, cache, "soon-high.example.", now.Add(5*time.Second), 5)
	later := newPrefetchTestEntry(t, cache, "later.example.", now.Add(20*time.Second), 10)

	candidates := manager.prefetchCandidates([]*prefetchEntry{later, soonLowHeat, expired, soonHighHeat}, now)
	sortPrefetchCandidates(candidates)

	got := []string{candidates[0].key, candidates[1].key, candidates[2].key, candidates[3].key}
	want := []string{expired.key, soonHighHeat.key, soonLowHeat.key, later.key}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("candidate order = %v, want %v", got, want)
		}
	}
}

func TestPrefetchScanUsesBatchLimit(t *testing.T) {
	now := time.Unix(1700000000, 0)
	cache := lru.New[string, *D.Msg](lru.WithStale[string, *D.Msg](true))
	client := &blockingPrefetchDNSClient{release: make(chan struct{})}
	manager := &prefetchManager{
		resolver: &Resolver{
			cache:              cache,
			main:               []dnsClient{client},
			optimisticCacheTTL: time.Hour,
		},
		config: prefetchConfig{
			scanInterval:  defaultPrefetchScanInterval,
			threshold:     defaultPrefetchThreshold,
			minRefreshes:  defaultPrefetchMinRefreshes,
			maxConcurrent: defaultPrefetchConcurrency,
			timeout:       time.Second,
		},
		sem:     make(chan struct{}, defaultPrefetchConcurrency),
		entries: make(map[string]*prefetchEntry),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}

	for i := 0; i < defaultPrefetchConcurrency; i++ {
		name := D.Fqdn("batch" + string(rune('a'+i)) + ".example")
		entry := newPrefetchTestEntry(t, cache, name, now.Add(5*time.Second), 2)
		manager.entries[entry.key] = entry
	}

	manager.scan(now)
	started := waitPrefetchStarted(t, &client.started, defaultPrefetchScanBatch)
	if started != defaultPrefetchScanBatch {
		t.Fatalf("started prefetches = %d, want %d", started, defaultPrefetchScanBatch)
	}
	if len(manager.sem) != defaultPrefetchScanBatch {
		t.Fatalf("semaphore usage = %d, want %d", len(manager.sem), defaultPrefetchScanBatch)
	}
	if extra := client.started.Load(); extra != defaultPrefetchScanBatch {
		t.Fatalf("unexpected extra prefetches = %d, want %d", extra, defaultPrefetchScanBatch)
	}

	close(client.release)
	manager.wg.Wait()
}

func TestPrefetchScanSkipsInFlightCandidates(t *testing.T) {
	now := time.Unix(1700000000, 0)
	cache := lru.New[string, *D.Msg](lru.WithStale[string, *D.Msg](true))
	client := &blockingPrefetchDNSClient{release: make(chan struct{})}
	manager := &prefetchManager{
		resolver: &Resolver{
			cache:              cache,
			main:               []dnsClient{client},
			optimisticCacheTTL: time.Hour,
		},
		config: prefetchConfig{
			scanInterval:  defaultPrefetchScanInterval,
			threshold:     defaultPrefetchThreshold,
			minRefreshes:  defaultPrefetchMinRefreshes,
			maxConcurrent: defaultPrefetchConcurrency,
			timeout:       time.Second,
		},
		sem:     make(chan struct{}, defaultPrefetchConcurrency),
		entries: make(map[string]*prefetchEntry),
	}

	blocked := newPrefetchTestEntry(t, cache, "blocked.example.", now.Add(-time.Second), 5)
	next := newPrefetchTestEntry(t, cache, "next.example.", now.Add(5*time.Second), 2)
	blocked.inFlight.Store(true)
	manager.entries[blocked.key] = blocked
	manager.entries[next.key] = next

	manager.scan(now)
	if started := waitPrefetchStarted(t, &client.started, 1); started != 1 {
		t.Fatalf("started prefetches = %d, want 1", started)
	}
	if !next.inFlight.Load() {
		t.Fatal("expected scan to skip the in-flight high-priority entry and launch the next candidate")
	}

	close(client.release)
	manager.wg.Wait()
}

func newPrefetchTestMsg(question D.Question) *D.Msg {
	msg := &D.Msg{}
	msg.SetQuestion(question.Name, question.Qtype)
	msg.Question[0].Qclass = question.Qclass
	msg.Answer = []D.RR{
		&D.A{
			Hdr: D.RR_Header{
				Name:   question.Name,
				Rrtype: question.Qtype,
				Class:  question.Qclass,
				Ttl:    60,
			},
			A: net.IPv4(192, 0, 2, 1),
		},
	}
	return msg
}

func newPrefetchTestEntry(t *testing.T, cache *lru.LruCache[string, *D.Msg], name string, expire time.Time, refreshCount int32) *prefetchEntry {
	t.Helper()
	question := D.Question{Name: name, Qtype: D.TypeA, Qclass: D.ClassINET}
	key := question.String()
	cache.SetWithExpire(key, newPrefetchTestMsg(question), expire)

	entry := &prefetchEntry{
		key:      key,
		question: question,
		expire:   expire,
	}
	entry.refreshCount.Store(refreshCount)
	return entry
}

func prefetchTestFailureState(entry *prefetchEntry) (time.Time, int32) {
	entry.mu.Lock()
	defer entry.mu.Unlock()
	return entry.nextPrefetchAttempt, entry.prefetchFailureCount
}

type blockingPrefetchDNSClient struct {
	started atomic.Int32
	release chan struct{}
}

func (c *blockingPrefetchDNSClient) ExchangeContext(ctx context.Context, msg *D.Msg) (*D.Msg, error) {
	c.started.Add(1)
	select {
	case <-c.release:
		resp := msg.Copy()
		resp.Response = true
		return resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *blockingPrefetchDNSClient) Address() string {
	return "blocking-prefetch-test"
}

func (c *blockingPrefetchDNSClient) ResetConnection() {}

func waitPrefetchStarted(t *testing.T, started *atomic.Int32, want int32) int32 {
	t.Helper()
	deadline := time.After(time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if got := started.Load(); got >= want {
			return got
		}
		select {
		case <-deadline:
			return started.Load()
		case <-ticker.C:
		}
	}
}
