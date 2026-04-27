package dns

import (
	"net"
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

func prefetchTestFailureState(entry *prefetchEntry) (time.Time, int32) {
	entry.mu.Lock()
	defer entry.mu.Unlock()
	return entry.nextPrefetchAttempt, entry.prefetchFailureCount
}
