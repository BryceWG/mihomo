package cachefile

import (
	"os"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/bbolt"
	"github.com/vmihailenco/msgpack/v5"
)

var (
	dnsInitOnce sync.Once
	dnsCache    *DNSCacheFile

	bucketDNSCache = []byte("dns-cache")
)

type DNSCacheRecord struct {
	Msg          []byte
	Expire       time.Time
	OriginalTTL  time.Duration
	CachedAt     time.Time
	RefreshCount int32
}

type DNSCacheFile struct {
	DB *bbolt.DB
}

func initDNSCache() {
	options := bbolt.Options{Timeout: time.Second}
	db, err := bbolt.Open(C.Path.DNSCache(), fileMode, &options)
	switch err {
	case bbolt.ErrInvalid, bbolt.ErrChecksum, bbolt.ErrVersionMismatch:
		if err = os.Remove(C.Path.DNSCache()); err != nil {
			log.Warnln("[DNS CacheFile] remove invalid cache file error: %s", err.Error())
			break
		}
		log.Infoln("[DNS CacheFile] remove invalid cache file and create new one")
		db, err = bbolt.Open(C.Path.DNSCache(), fileMode, &options)
	}
	if err != nil {
		log.Warnln("[DNS CacheFile] can't open cache file: %s", err.Error())
	}

	dnsCache = &DNSCacheFile{
		DB: db,
	}
}

func DNSCache() *DNSCacheFile {
	dnsInitOnce.Do(initDNSCache)

	return dnsCache
}

func (c *DNSCacheFile) Load(namespace string) map[string]DNSCacheRecord {
	if c == nil || c.DB == nil {
		return nil
	}

	records := map[string]DNSCacheRecord{}
	err := c.DB.View(func(t *bbolt.Tx) error {
		root := t.Bucket(bucketDNSCache)
		if root == nil {
			return nil
		}
		bucket := root.Bucket([]byte(namespace))
		if bucket == nil {
			return nil
		}
		return bucket.ForEach(func(k, v []byte) error {
			var record DNSCacheRecord
			if err := msgpack.Unmarshal(v, &record); err != nil {
				log.Warnln("[DNS CacheFile] drop corrupted cache entry %s/%s: %s", namespace, string(k), err.Error())
				return nil
			}
			records[string(k)] = record
			return nil
		})
	})
	if err != nil {
		log.Warnln("[DNS CacheFile] read cache from %s failed: %s", c.DB.Path(), err.Error())
		return nil
	}
	return records
}

func (c *DNSCacheFile) Store(namespace string, records map[string]DNSCacheRecord) {
	if c == nil || c.DB == nil {
		return
	}

	err := c.DB.Batch(func(t *bbolt.Tx) error {
		root, err := t.CreateBucketIfNotExists(bucketDNSCache)
		if err != nil {
			return err
		}
		_ = root.DeleteBucket([]byte(namespace))
		bucket, err := root.CreateBucket([]byte(namespace))
		if err != nil {
			return err
		}
		for key, record := range records {
			payload, err := msgpack.Marshal(record)
			if err != nil {
				log.Warnln("[DNS CacheFile] skip cache entry %s/%s: %s", namespace, key, err.Error())
				continue
			}
			if err := bucket.Put([]byte(key), payload); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		log.Warnln("[DNS CacheFile] write cache to %s failed: %s", c.DB.Path(), err.Error())
	}
}
