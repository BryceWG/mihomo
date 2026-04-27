package dns

import (
	"context"
	"hash/fnv"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/log"

	D "github.com/miekg/dns"
)

const (
	defaultPrefetchScanInterval = 5 * time.Second
	defaultPrefetchThreshold    = 30 * time.Second
	defaultPrefetchMinRefreshes = int32(2)
	defaultPrefetchDecay        = int32(1)
	defaultPrefetchConcurrency  = 10
	defaultPrefetchMinTTL       = 120
	defaultPrefetchBackoffBase  = 30 * time.Second
	defaultPrefetchBackoffMax   = 5 * time.Minute
	defaultPrefetchScanBatch    = 3
)

type prefetchConfig struct {
	enable        bool
	scanInterval  time.Duration
	threshold     time.Duration
	minRefreshes  int32
	decay         int32
	maxConcurrent int
	timeout       time.Duration
}

type prefetchEntry struct {
	key string

	mu                   sync.Mutex
	question             D.Question
	cachedAt             time.Time
	expire               time.Time
	originalTTL          time.Duration
	observedWindowExpire time.Time
	prefetchFailureCount int32
	nextPrefetchAttempt  time.Time

	refreshCount      atomic.Int32
	refreshCountDirty atomic.Bool
	inFlight          atomic.Bool
}

type prefetchManager struct {
	resolver *Resolver
	config   prefetchConfig
	sem      chan struct{}

	mu      sync.RWMutex
	entries map[string]*prefetchEntry

	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
	wg       sync.WaitGroup
}

type prefetchCandidate struct {
	entry        *prefetchEntry
	key          string
	remainingTTL time.Duration
	refreshCount int32
}

func newPrefetchConfig(config Config) prefetchConfig {
	if !config.Prefetch {
		return prefetchConfig{}
	}

	scanInterval := time.Duration(config.PrefetchScanInterval) * time.Second
	if scanInterval <= 0 {
		scanInterval = defaultPrefetchScanInterval
	}

	threshold := time.Duration(config.PrefetchThreshold) * time.Second
	if threshold <= 0 {
		threshold = defaultPrefetchThreshold
	}

	minRefreshes := int32(config.PrefetchMinRefreshes)
	if minRefreshes <= 0 {
		minRefreshes = defaultPrefetchMinRefreshes
	}

	return prefetchConfig{
		enable:        true,
		scanInterval:  scanInterval,
		threshold:     threshold,
		minRefreshes:  minRefreshes,
		decay:         defaultPrefetchDecay,
		maxConcurrent: defaultPrefetchConcurrency,
		timeout:       resolver.DefaultDNSTimeout,
	}
}

func (r *Resolver) initPrefetch(config Config) {
	cfg := newPrefetchConfig(config)
	if !cfg.enable {
		return
	}

	manager := &prefetchManager{
		resolver: r,
		config:   cfg,
		sem:      make(chan struct{}, cfg.maxConcurrent),
		entries:  make(map[string]*prefetchEntry),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	r.prefetch = manager
	manager.restore()
	go manager.loop()
}

func (p *prefetchManager) restore() {
	cache, ok := p.resolver.cache.(interface {
		PrefetchMetadata() map[string]dnsCacheMeta
	})
	if !ok {
		return
	}
	for _, meta := range cache.PrefetchMetadata() {
		p.storeMeta(meta)
	}
}

func (p *prefetchManager) stopLoop() {
	p.stopOnce.Do(func() {
		close(p.stop)
		<-p.done
		p.wg.Wait()
		p.syncRefreshCounts()
	})
}

func (p *prefetchManager) loop() {
	defer close(p.done)

	ticker := time.NewTicker(p.config.scanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.stop:
			return
		case <-ticker.C:
			p.scan(time.Now())
		}
	}
}

func (p *prefetchManager) store(meta *dnsCacheMeta) {
	if meta == nil || meta.key == "" || meta.originalTTL <= 0 {
		return
	}
	p.storeMeta(*meta)
}

func (p *prefetchManager) storeMeta(meta dnsCacheMeta) {
	if !isPrefetchQtype(meta.question.Qtype) {
		if meta.key != "" {
			p.remove(meta.key)
		}
		return
	}

	p.mu.Lock()
	entry := p.entries[meta.key]
	if entry == nil {
		entry = &prefetchEntry{key: meta.key}
		p.entries[meta.key] = entry
	}
	p.mu.Unlock()

	entry.mu.Lock()
	entry.question = meta.question
	entry.cachedAt = meta.cachedAt
	entry.expire = meta.expire
	entry.originalTTL = meta.originalTTL
	entry.observedWindowExpire = time.Time{}
	entry.mu.Unlock()

	if meta.refreshCount > 0 {
		entry.refreshCount.Store(meta.refreshCount)
	}
}

func isPrefetchQtype(qtype uint16) bool {
	switch qtype {
	case D.TypeA, D.TypeAAAA, D.TypeCNAME, D.TypeHTTPS:
		return true
	default:
		return false
	}
}

func (p *prefetchManager) clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.entries = make(map[string]*prefetchEntry)
}

func (p *prefetchManager) remove(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.entries, key)
}

func (p *prefetchManager) entry(key string) *prefetchEntry {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.entries[key]
}

func (p *prefetchManager) markNearExpiryHit(key string, expire time.Time, now time.Time) {
	entry := p.entry(key)
	if entry == nil {
		return
	}

	entry.mu.Lock()
	if !entry.expire.Equal(expire) {
		entry.mu.Unlock()
		return
	}
	if entry.expire.Sub(now) > p.config.threshold {
		entry.mu.Unlock()
		return
	}
	if entry.observedWindowExpire.Equal(entry.expire) {
		entry.mu.Unlock()
		return
	}
	entry.observedWindowExpire = entry.expire
	entry.mu.Unlock()

	p.addRefreshCount(entry, 1)
}

func (p *prefetchManager) markClientRefresh(key string) {
	entry := p.entry(key)
	if entry == nil {
		return
	}
	entry.mu.Lock()
	if entry.observedWindowExpire.Equal(entry.expire) {
		entry.mu.Unlock()
		return
	}
	entry.observedWindowExpire = entry.expire
	entry.mu.Unlock()

	p.addRefreshCount(entry, 1)
}

func (p *prefetchManager) addRefreshCount(entry *prefetchEntry, delta int32) {
	if delta <= 0 {
		return
	}
	entry.refreshCount.Add(delta)
	entry.refreshCountDirty.Store(true)
}

func (p *prefetchManager) applyDecay(entry *prefetchEntry) {
	for {
		old := entry.refreshCount.Load()
		next := old - p.config.decay
		if next < 0 {
			next = 0
		}
		if entry.refreshCount.CompareAndSwap(old, next) {
			entry.refreshCountDirty.Store(true)
			return
		}
	}
}

func (p *prefetchManager) syncRefreshCounts() {
	if p == nil || p.resolver == nil || p.resolver.cache == nil {
		return
	}

	p.mu.RLock()
	entries := make([]*prefetchEntry, 0, len(p.entries))
	for _, entry := range p.entries {
		entries = append(entries, entry)
	}
	p.mu.RUnlock()

	counts := make(map[string]int32)
	for _, entry := range entries {
		if !entry.refreshCountDirty.Swap(false) {
			continue
		}
		counts[entry.key] = entry.refreshCount.Load()
	}
	if len(counts) == 0 {
		return
	}
	p.persistRefreshCounts(counts)
}

func (p *prefetchManager) persistRefreshCounts(counts map[string]int32) {
	batchCache, ok := p.resolver.cache.(interface {
		SetPrefetchRefreshCounts(map[string]int32)
	})
	if ok {
		batchCache.SetPrefetchRefreshCounts(counts)
		return
	}

	singleCache, ok := p.resolver.cache.(interface {
		SetPrefetchRefreshCount(string, int32)
	})
	if !ok {
		return
	}
	for key, count := range counts {
		singleCache.SetPrefetchRefreshCount(key, count)
	}
}

func (p *prefetchManager) scan(now time.Time) {
	defer p.syncRefreshCounts()

	p.mu.RLock()
	entries := make([]*prefetchEntry, 0, len(p.entries))
	for _, entry := range p.entries {
		entries = append(entries, entry)
	}
	p.mu.RUnlock()

	candidates := p.prefetchCandidates(entries, now)
	sortPrefetchCandidates(candidates)

	launched := 0
	limit := p.prefetchScanBatchLimit()
	for _, candidate := range candidates {
		if launched >= limit {
			return
		}
		entry := candidate.entry
		if !entry.inFlight.CompareAndSwap(false, true) {
			continue
		}

		select {
		case p.sem <- struct{}{}:
			launched++
			p.wg.Add(1)
			go func(entry *prefetchEntry) {
				defer func() {
					<-p.sem
					entry.inFlight.Store(false)
					p.wg.Done()
				}()
				p.doPrefetch(entry)
			}(entry)
		default:
			entry.inFlight.Store(false)
			return
		}
	}
}

func (p *prefetchManager) shouldPrefetch(entry *prefetchEntry, now time.Time) bool {
	_, ok := p.prefetchCandidate(entry, now)
	return ok
}

func (p *prefetchManager) prefetchCandidates(entries []*prefetchEntry, now time.Time) []prefetchCandidate {
	candidates := make([]prefetchCandidate, 0, len(entries))
	for _, entry := range entries {
		candidate, ok := p.prefetchCandidate(entry, now)
		if !ok {
			continue
		}
		candidates = append(candidates, candidate)
	}
	return candidates
}

func (p *prefetchManager) prefetchCandidate(entry *prefetchEntry, now time.Time) (prefetchCandidate, bool) {
	entry.mu.Lock()
	nextPrefetchAttempt := entry.nextPrefetchAttempt
	expire := entry.expire
	question := entry.question
	entry.mu.Unlock()

	msg, cacheExpire, hit := getMsgFromCache(p.resolver.cache, question)
	if !hit || msg == nil {
		p.remove(entry.key)
		return prefetchCandidate{}, false
	}
	if !cacheExpire.Equal(expire) {
		return prefetchCandidate{}, false
	}
	refreshCount := entry.refreshCount.Load()
	if refreshCount < p.config.minRefreshes {
		if p.shouldRemoveColdEntry(entry, now) {
			p.remove(entry.key)
		}
		return prefetchCandidate{}, false
	}
	if !nextPrefetchAttempt.IsZero() && now.Before(nextPrefetchAttempt) {
		return prefetchCandidate{}, false
	}
	remaining := expire.Sub(now)
	if remaining > p.config.threshold {
		return prefetchCandidate{}, false
	}
	if p.resolver.optimisticCacheTTL == 0 && remaining < 0 {
		return prefetchCandidate{}, false
	}
	if p.resolver.optimisticCacheTTL > 0 && remaining < -p.resolver.optimisticCacheTTL {
		return prefetchCandidate{}, false
	}
	return prefetchCandidate{
		entry:        entry,
		key:          entry.key,
		remainingTTL: remaining,
		refreshCount: refreshCount,
	}, true
}

func sortPrefetchCandidates(candidates []prefetchCandidate) {
	sort.SliceStable(candidates, func(i, j int) bool {
		left := candidates[i]
		right := candidates[j]
		if left.remainingTTL != right.remainingTTL {
			return left.remainingTTL < right.remainingTTL
		}
		if left.refreshCount != right.refreshCount {
			return left.refreshCount > right.refreshCount
		}
		return left.key < right.key
	})
}

func (p *prefetchManager) prefetchScanBatchLimit() int {
	maxConcurrent := p.config.maxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = defaultPrefetchConcurrency
	}
	if maxConcurrent < defaultPrefetchScanBatch {
		return maxConcurrent
	}
	return defaultPrefetchScanBatch
}

func (p *prefetchManager) shouldRemoveColdEntry(entry *prefetchEntry, now time.Time) bool {
	entry.mu.Lock()
	expire := entry.expire
	entry.mu.Unlock()

	if expire.IsZero() {
		return false
	}
	if p.resolver.optimisticCacheTTL > 0 {
		expire = expire.Add(p.resolver.optimisticCacheTTL)
	}
	return now.After(expire)
}

func (p *prefetchManager) recordPrefetchFailure(entry *prefetchEntry, now time.Time) {
	entry.mu.Lock()
	entry.prefetchFailureCount++
	failureCount := entry.prefetchFailureCount
	entry.nextPrefetchAttempt = now.Add(p.prefetchFailureBackoff(entry.key, failureCount))
	entry.mu.Unlock()
}

func (p *prefetchManager) recordPrefetchSuccess(entry *prefetchEntry) {
	entry.mu.Lock()
	entry.prefetchFailureCount = 0
	entry.nextPrefetchAttempt = time.Time{}
	entry.mu.Unlock()
}

func (p *prefetchManager) prefetchFailureBackoff(key string, failureCount int32) time.Duration {
	backoff := p.config.scanInterval * 2
	if backoff < defaultPrefetchBackoffBase {
		backoff = defaultPrefetchBackoffBase
	}

	if failureCount > 1 {
		for i := int32(1); i < failureCount && backoff < defaultPrefetchBackoffMax; i++ {
			backoff *= 2
		}
	}
	if backoff > defaultPrefetchBackoffMax {
		backoff = defaultPrefetchBackoffMax
	}

	jitterWindow := p.config.scanInterval
	if jitterWindow <= 0 {
		jitterWindow = defaultPrefetchScanInterval
	}
	if maxJitter := backoff / 4; jitterWindow > maxJitter {
		jitterWindow = maxJitter
	}
	if jitterWindow <= 0 {
		return backoff
	}
	if backoff > defaultPrefetchBackoffMax-jitterWindow {
		backoff = defaultPrefetchBackoffMax - jitterWindow
	}

	hasher := fnv.New64a()
	_, _ = hasher.Write([]byte(key))
	_, _ = hasher.Write([]byte{byte(failureCount), byte(failureCount >> 8), byte(failureCount >> 16), byte(failureCount >> 24)})
	backoff += time.Duration(hasher.Sum64() % uint64(jitterWindow))
	if backoff < defaultPrefetchBackoffBase {
		return defaultPrefetchBackoffBase
	}
	if backoff > defaultPrefetchBackoffMax {
		return defaultPrefetchBackoffMax
	}
	return backoff
}

func (p *prefetchManager) doPrefetch(entry *prefetchEntry) {
	entry.mu.Lock()
	question := entry.question
	oldExpire := entry.expire
	entry.mu.Unlock()

	msg := &D.Msg{}
	msg.SetQuestion(question.Name, question.Qtype)
	msg.Question[0].Qclass = question.Qclass

	ctx, cancel := context.WithTimeout(context.Background(), p.config.timeout)
	defer cancel()

	resp, err := p.resolver.exchangeWithoutCache(ctx, msg, false)
	if err != nil || resp == nil || resp.Rcode == D.RcodeServerFailure {
		p.recordPrefetchFailure(entry, time.Now())
		p.resolver.stats.recordPrefetch(false)
		log.Debugln("[DNS] prefetch %s failed: %v", question.String(), err)
		return
	}

	if !p.prefetchUpdatedCache(question, oldExpire) {
		p.recordPrefetchFailure(entry, time.Now())
		p.resolver.stats.recordPrefetch(false)
		return
	}

	p.recordPrefetchSuccess(entry)
	p.applyDecay(entry)
	p.resolver.stats.recordPrefetch(true)
}

func (p *prefetchManager) prefetchUpdatedCache(question D.Question, oldExpire time.Time) bool {
	msg, cacheExpire, hit := getMsgFromCache(p.resolver.cache, question)
	return hit && msg != nil && cacheExpire.After(oldExpire)
}

func (r *Resolver) updatePrefetchMeta(meta *dnsCacheMeta) {
	if r == nil || r.prefetch == nil || meta == nil {
		return
	}
	if old := r.prefetch.entry(meta.key); old != nil {
		meta.refreshCount = old.refreshCount.Load()
	}
	r.prefetch.store(meta)
}

func (r *Resolver) markPrefetchNearExpiryHit(key string, expire time.Time, now time.Time) {
	if r == nil || r.prefetch == nil {
		return
	}
	r.prefetch.markNearExpiryHit(key, expire, now)
}

func (r *Resolver) markPrefetchClientRefresh(key string) {
	if r == nil || r.prefetch == nil {
		return
	}
	r.prefetch.markClientRefresh(key)
}

func (r *Resolver) tryStartRefresh(key string) func() {
	if r == nil || r.prefetch == nil {
		return func() {}
	}
	entry := r.prefetch.entry(key)
	if entry == nil {
		return func() {}
	}
	if !entry.inFlight.CompareAndSwap(false, true) {
		return nil
	}
	return func() {
		entry.inFlight.Store(false)
	}
}
