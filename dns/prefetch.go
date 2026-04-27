package dns

import (
	"context"
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

	refreshCount atomic.Int32
	inFlight     atomic.Bool
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
	newCount := entry.refreshCount.Add(delta)
	p.persistRefreshCount(entry.key, newCount)
}

func (p *prefetchManager) applyDecay(entry *prefetchEntry) {
	for {
		old := entry.refreshCount.Load()
		next := old - p.config.decay
		if next < 0 {
			next = 0
		}
		if entry.refreshCount.CompareAndSwap(old, next) {
			p.persistRefreshCount(entry.key, next)
			return
		}
	}
}

func (p *prefetchManager) persistRefreshCount(key string, count int32) {
	cache, ok := p.resolver.cache.(interface {
		SetPrefetchRefreshCount(string, int32)
	})
	if ok {
		cache.SetPrefetchRefreshCount(key, count)
	}
}

func (p *prefetchManager) scan(now time.Time) {
	p.mu.RLock()
	entries := make([]*prefetchEntry, 0, len(p.entries))
	for _, entry := range p.entries {
		entries = append(entries, entry)
	}
	p.mu.RUnlock()

	for _, entry := range entries {
		if !p.shouldPrefetch(entry, now) {
			continue
		}

		if !entry.inFlight.CompareAndSwap(false, true) {
			continue
		}

		select {
		case p.sem <- struct{}{}:
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
	if !p.resolver.cache.Exist(entry.key) {
		p.remove(entry.key)
		return false
	}
	if entry.refreshCount.Load() < p.config.minRefreshes {
		return false
	}

	entry.mu.Lock()
	expire := entry.expire
	question := entry.question
	entry.mu.Unlock()

	msg, cacheExpire, hit := getMsgFromCache(p.resolver.cache, question)
	if !hit || msg == nil {
		p.remove(entry.key)
		return false
	}
	if !cacheExpire.Equal(expire) {
		return false
	}
	remaining := expire.Sub(now)
	if remaining > p.config.threshold {
		return false
	}
	if p.resolver.optimisticCacheTTL == 0 && remaining < 0 {
		return false
	}
	if p.resolver.optimisticCacheTTL > 0 && remaining < -p.resolver.optimisticCacheTTL {
		return false
	}
	return true
}

func (p *prefetchManager) doPrefetch(entry *prefetchEntry) {
	entry.mu.Lock()
	question := entry.question
	oldCachedAt := entry.cachedAt
	entry.mu.Unlock()

	msg := &D.Msg{}
	msg.SetQuestion(question.Name, question.Qtype)
	msg.Question[0].Qclass = question.Qclass

	ctx, cancel := context.WithTimeout(context.Background(), p.config.timeout)
	defer cancel()

	start := time.Now()
	resp, err := p.resolver.exchangeWithoutCache(ctx, msg, false)
	if err != nil || resp == nil || resp.Rcode == D.RcodeServerFailure {
		p.resolver.stats.recordPrefetch(false)
		log.Debugln("[DNS] prefetch %s failed: %v", question.String(), err)
		return
	}

	entry.mu.Lock()
	refreshed := entry.cachedAt.After(oldCachedAt) && !entry.cachedAt.Before(start)
	entry.mu.Unlock()
	if !refreshed {
		p.resolver.stats.recordPrefetch(false)
		return
	}

	p.applyDecay(entry)
	p.resolver.stats.recordPrefetch(true)
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
