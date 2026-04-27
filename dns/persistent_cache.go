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
	msg    *D.Msg
	expire time.Time
	elem   *list.Element
}

type persistentDNSCache struct {
	dnsCache
	namespace string
	maxSize   int
	interval  time.Duration

	mu      sync.Mutex
	records map[string]*persistentCacheRecord
	order   *list.List
	dirty   bool
	closed  bool
	stop    chan struct{}
	done    chan struct{}
}

func newPersistentDNSCache(namespace string, cache dnsCache, maxSize int, interval time.Duration) *persistentDNSCache {
	if interval <= 0 {
		interval = dnsCacheStoreInterval
	}
	c := &persistentDNSCache{
		dnsCache:  cache,
		namespace: namespace,
		maxSize:   maxSize,
		interval:  interval,
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

	c.setRecordLocked(key, value, expire)
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
		if !record.Expire.After(now) {
			expired++
			continue
		}

		msg := &D.Msg{}
		if err := msg.Unpack(record.Msg); err != nil {
			log.Warnln("[DNS] restore cache entry %s/%s failed: %s", c.namespace, key, err.Error())
			continue
		}

		c.dnsCache.SetWithExpire(key, msg, record.Expire)
		c.setRecordLocked(key, msg, record.Expire)
		restored++
	}
	log.Infoln("[DNS] persistent cache restored for %s, restored: %d, expired skipped: %d", c.namespace, restored, expired)
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

func (c *persistentDNSCache) setRecordLocked(key string, msg *D.Msg, expire time.Time) {
	if record, ok := c.records[key]; ok {
		record.msg = msg.Copy()
		record.expire = expire
		c.order.MoveToBack(record.elem)
		return
	}

	elem := c.order.PushBack(key)
	c.records[key] = &persistentCacheRecord{
		msg:    msg.Copy(),
		expire: expire,
		elem:   elem,
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
		if !record.expire.After(now) {
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
			Msg:    payload,
			Expire: record.expire,
		}
	}
	c.dirty = false
	return snapshot
}
