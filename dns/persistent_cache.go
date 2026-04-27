package dns

import (
	"container/list"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/profile/cachefile"
	"github.com/metacubex/mihomo/log"

	D "github.com/miekg/dns"
)

const dnsCacheStoreInterval = 5 * time.Minute

type persistentCacheRecord struct {
	msg          *D.Msg
	expire       time.Time
	originalTTL  time.Duration
	cachedAt     time.Time
	refreshCount int32
	elem         *list.Element
}

type persistentDNSCache struct {
	dnsCache
	namespace string
	maxSize   int
	interval  time.Duration
	staleTTL  time.Duration

	mu      sync.Mutex
	records map[string]*persistentCacheRecord
	order   *list.List
	dirty   bool
	closed  bool
	stop    chan struct{}
	done    chan struct{}
}

func newPersistentDNSCache(namespace string, cache dnsCache, maxSize int, interval, staleTTL time.Duration) *persistentDNSCache {
	if interval <= 0 {
		interval = dnsCacheStoreInterval
	}
	c := &persistentDNSCache{
		dnsCache:  cache,
		namespace: namespace,
		maxSize:   maxSize,
		interval:  interval,
		staleTTL:  staleTTL,
		records:   map[string]*persistentCacheRecord{},
		order:     list.New(),
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}
	c.restore()
	go c.storeLoop()
	log.Infoln("[DNS] persistent cache enabled for %s, save interval: %s", c.namespace, c.interval)
	return c
}

func (c *persistentDNSCache) GetWithExpire(key string) (*D.Msg, time.Time, bool) {
	msg, expire, hit := c.dnsCache.GetWithExpire(key)
	if hit {
		c.touch(key)
	}
	return msg, expire, hit
}

func (c *persistentDNSCache) SetWithExpire(key string, value *D.Msg, expire time.Time) {
	c.dnsCache.SetWithExpire(key, value, expire)
	if value == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.setRecordLocked(key, value, expire, deriveDNSCacheMeta(key, value, expire))
	c.dirty = true
}

func (c *persistentDNSCache) SetWithExpireMeta(key string, value *D.Msg, expire time.Time, meta dnsCacheMeta) {
	c.dnsCache.SetWithExpire(key, value, expire)
	if value == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.setRecordLocked(key, value, expire, meta)
	c.dirty = true
}

func (c *persistentDNSCache) Clear() {
	c.dnsCache.Clear()

	c.mu.Lock()
	defer c.mu.Unlock()

	c.records = map[string]*persistentCacheRecord{}
	c.order.Init()
	c.dirty = true
	log.Infoln("[DNS] persistent cache cleared for %s", c.namespace)
}

func (c *persistentDNSCache) Store() {
	snapshot := c.snapshot()
	cachefile.DNSCache().Store(c.namespace, snapshot)
	log.Infoln("[DNS] persistent cache stored for %s, entries: %d", c.namespace, len(snapshot))
}

func (c *persistentDNSCache) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	close(c.stop)
	c.mu.Unlock()

	<-c.done
	c.Store()
}

func (c *persistentDNSCache) restore() {
	now := time.Now()
	restored := 0
	expired := 0
	for key, record := range cachefile.DNSCache().Load(c.namespace) {
		if !c.cacheAlive(record.Expire, now) {
			expired++
			continue
		}

		msg := &D.Msg{}
		if err := msg.Unpack(record.Msg); err != nil {
			log.Warnln("[DNS] restore cache entry %s/%s failed: %s", c.namespace, key, err.Error())
			continue
		}

		meta := dnsCacheMeta{
			key:          key,
			cachedAt:     record.CachedAt,
			expire:       record.Expire,
			originalTTL:  record.OriginalTTL,
			refreshCount: record.RefreshCount,
		}
		if len(msg.Question) > 0 {
			meta.question = msg.Question[0]
		}
		if meta.cachedAt.IsZero() || meta.originalTTL <= 0 || meta.question.Name == "" {
			meta = deriveDNSCacheMeta(key, msg, record.Expire)
			meta.refreshCount = record.RefreshCount
		}

		c.dnsCache.SetWithExpire(key, msg, record.Expire)
		c.setRecordLocked(key, msg, record.Expire, meta)
		restored++
	}
	log.Infoln("[DNS] persistent cache restored for %s, restored: %d, expired skipped: %d", c.namespace, restored, expired)
}

func (c *persistentDNSCache) cacheAlive(expire, now time.Time) bool {
	return expire.After(now) || (c.staleTTL > 0 && now.Before(expire.Add(c.staleTTL)))
}

func (c *persistentDNSCache) storeLoop() {
	defer close(c.done)

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if c.isDirty() {
				c.Store()
			}
		case <-c.stop:
			return
		}
	}
}

func (c *persistentDNSCache) setRecordLocked(key string, msg *D.Msg, expire time.Time, meta dnsCacheMeta) {
	if meta.cachedAt.IsZero() || meta.originalTTL <= 0 {
		meta = deriveDNSCacheMeta(key, msg, expire)
	}

	if record, ok := c.records[key]; ok {
		record.msg = msg.Copy()
		record.expire = expire
		record.originalTTL = meta.originalTTL
		record.cachedAt = meta.cachedAt
		record.refreshCount = meta.refreshCount
		c.order.MoveToBack(record.elem)
		return
	}

	elem := c.order.PushBack(key)
	c.records[key] = &persistentCacheRecord{
		msg:          msg.Copy(),
		expire:       expire,
		originalTTL:  meta.originalTTL,
		cachedAt:     meta.cachedAt,
		refreshCount: meta.refreshCount,
		elem:         elem,
	}
	c.trimLocked()
}

func (c *persistentDNSCache) trimLocked() {
	if c.maxSize <= 0 {
		return
	}

	for len(c.records) > c.maxSize {
		elem := c.order.Front()
		if elem == nil {
			return
		}
		key := elem.Value.(string)
		delete(c.records, key)
		c.order.Remove(elem)
	}
}

func (c *persistentDNSCache) touch(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if record, ok := c.records[key]; ok {
		c.order.MoveToBack(record.elem)
	}
}

func (c *persistentDNSCache) PrefetchMetadata() map[string]dnsCacheMeta {
	c.mu.Lock()
	defer c.mu.Unlock()

	metadata := make(map[string]dnsCacheMeta, len(c.records))
	for key, record := range c.records {
		meta := dnsCacheMeta{
			key:          key,
			expire:       record.expire,
			originalTTL:  record.originalTTL,
			cachedAt:     record.cachedAt,
			refreshCount: record.refreshCount,
		}
		if len(record.msg.Question) > 0 {
			meta.question = record.msg.Question[0]
		}
		if meta.cachedAt.IsZero() || meta.originalTTL <= 0 || meta.question.Name == "" {
			meta = deriveDNSCacheMeta(key, record.msg, record.expire)
			meta.refreshCount = record.refreshCount
		}
		metadata[key] = meta
	}
	return metadata
}

func (c *persistentDNSCache) SetPrefetchRefreshCount(key string, count int32) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if record, ok := c.records[key]; ok {
		record.refreshCount = count
		c.dirty = true
	}
}

func (c *persistentDNSCache) isDirty() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.dirty
}

func (c *persistentDNSCache) snapshot() map[string]cachefile.DNSCacheRecord {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	snapshot := make(map[string]cachefile.DNSCacheRecord, len(c.records))
	for key, record := range c.records {
		if !c.cacheAlive(record.expire, now) {
			c.order.Remove(record.elem)
			delete(c.records, key)
			continue
		}

		payload, err := record.msg.Pack()
		if err != nil {
			log.Warnln("[DNS] pack cache entry %s/%s failed: %s", c.namespace, key, err.Error())
			continue
		}

		snapshot[key] = cachefile.DNSCacheRecord{
			Msg:          payload,
			Expire:       record.expire,
			OriginalTTL:  record.originalTTL,
			CachedAt:     record.cachedAt,
			RefreshCount: record.refreshCount,
		}
	}
	c.dirty = false
	return snapshot
}

func deriveDNSCacheMeta(key string, msg *D.Msg, expire time.Time) dnsCacheMeta {
	ttl := minimalTTL(loConcatDNSRecords(msg))
	if ttl == 0 && expire.After(time.Now()) {
		ttl = uint32(time.Until(expire).Seconds())
	}
	if ttl == 0 {
		ttl = 1
	}

	meta := dnsCacheMeta{
		key:         key,
		expire:      expire,
		originalTTL: time.Duration(ttl) * time.Second,
		cachedAt:    expire.Add(-time.Duration(ttl) * time.Second),
	}
	if msg != nil && len(msg.Question) > 0 {
		meta.question = msg.Question[0]
	}
	return meta
}

func loConcatDNSRecords(msg *D.Msg) []D.RR {
	if msg == nil {
		return nil
	}
	records := make([]D.RR, 0, len(msg.Answer)+len(msg.Ns)+len(msg.Extra))
	records = append(records, msg.Answer...)
	records = append(records, msg.Ns...)
	records = append(records, msg.Extra...)
	return records
}
