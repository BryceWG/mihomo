package dns

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/metacubex/mihomo/common/arc"
	"github.com/metacubex/mihomo/common/lru"
	"github.com/metacubex/mihomo/common/singleflight"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	D "github.com/miekg/dns"
	"github.com/samber/lo"
	"golang.org/x/exp/maps"
)

type dnsClient interface {
	ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error)
	Address() string
	ResetConnection()
}

type dnsCache interface {
	GetWithExpire(key string) (*D.Msg, time.Time, bool)
	SetWithExpire(key string, value *D.Msg, expire time.Time)
	Exist(key string) bool
	Clear()
}

type result struct {
	Msg   *D.Msg
	Error error
}

const (
	defaultOptimisticCacheTTL       = time.Hour
	defaultOptimisticCacheAnswerTTL = 1
)

type Resolver struct {
	ipv6                     bool
	ipv6Timeout              time.Duration
	main                     []dnsClient
	fallback                 []dnsClient
	fallbackDomainFilters    []C.DomainMatcher
	fallbackIPFilters        []C.IpMatcher
	group                    singleflight.Group[*D.Msg]
	cache                    dnsCache
	stats                    *dnsStats
	policy                   []dnsPolicy
	defaultResolver          *Resolver
	optimisticCache          bool
	optimisticCacheTTL       time.Duration
	optimisticCacheAnswerTTL uint32
	minTTL                   uint32
	maxTTL                   uint32
	prefetch                 *prefetchManager
}

func (r *Resolver) LookupIPPrimaryIPv4(ctx context.Context, host string) (ips []netip.Addr, err error) {
	ch := make(chan []netip.Addr, 1)
	go func() {
		defer close(ch)
		ip, err := r.lookupIP(ctx, host, D.TypeAAAA)
		if err != nil {
			return
		}
		ch <- ip
	}()

	ips, err = r.lookupIP(ctx, host, D.TypeA)
	if err == nil {
		return
	}

	ip, open := <-ch
	if !open {
		return nil, resolver.ErrIPNotFound
	}

	return ip, nil
}

func (r *Resolver) LookupIP(ctx context.Context, host string) (ips []netip.Addr, err error) {
	ch := make(chan []netip.Addr, 1)
	go func() {
		defer close(ch)
		ip, err := r.lookupIP(ctx, host, D.TypeAAAA)
		if err != nil {
			return
		}

		ch <- ip
	}()

	ips, err = r.lookupIP(ctx, host, D.TypeA)
	var waitIPv6 *time.Timer
	if r != nil && r.ipv6Timeout > 0 {
		waitIPv6 = time.NewTimer(r.ipv6Timeout)
	} else {
		waitIPv6 = time.NewTimer(100 * time.Millisecond)
	}
	defer waitIPv6.Stop()
	select {
	case ipv6s, open := <-ch:
		if !open && err != nil {
			return nil, resolver.ErrIPNotFound
		}
		ips = append(ips, ipv6s...)
	case <-waitIPv6.C:
		// wait ipv6 result
	}

	return ips, nil
}

// LookupIPv4 request with TypeA
func (r *Resolver) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.lookupIP(ctx, host, D.TypeA)
}

// LookupIPv6 request with TypeAAAA
func (r *Resolver) LookupIPv6(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.lookupIP(ctx, host, D.TypeAAAA)
}

func (r *Resolver) shouldIPFallback(ip netip.Addr) bool {
	for _, filter := range r.fallbackIPFilters {
		if filter.MatchIp(ip) {
			return true
		}
	}
	return false
}

func (r *Resolver) ResolveECH(ctx context.Context, host string) ([]byte, error) {
	query := &D.Msg{}
	query.SetQuestion(D.Fqdn(host), D.TypeHTTPS)

	msg, err := r.ExchangeContext(ctx, query)
	if err != nil {
		return nil, err
	}

	for _, rr := range msg.Answer {
		switch resource := rr.(type) {
		case *D.HTTPS:
			for _, value := range resource.Value {
				if echConfig, ok := value.(*D.SVCBECHConfig); ok {
					return echConfig.ECH, nil
				}
			}
		}
	}
	return nil, errors.New("no ECH config found in DNS records")
}

// ExchangeContext a batch of dns request with context.Context, and it use cache
func (r *Resolver) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	start := time.Now()
	defer func() {
		r.stats.recordQuery(time.Since(start))
	}()

	if len(m.Question) == 0 {
		return nil, errors.New("should have one question at least")
	}
	cacheFailure := true
	defer func() {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), resolver.DefaultDNSTimeout)
				defer cancel()
				_, _ = r.exchangeWithoutCache(ctx, m, cacheFailure) // ignore result, just for putMsgToCache
			}()
		}
	}()

	q := m.Question[0]
	domain := msgToDomain(m)
	msg, expireTime, hit := getMsgFromCache(r.cache, q)
	if hit {
		log.Debugln("[DNS] cache hit %s --> %s, expire at %s", domain, msgToLogString(msg), expireTime.Format("2006-01-02 15:04:05"))
		now := time.Now()
		if expireTime.Before(now) {
			if !r.optimisticCacheAlive(msg, expireTime, now) {
				r.stats.recordCacheMiss()
				msg, err = r.exchangeWithoutCache(ctx, m, true)
				if msg != nil {
					clampMsgTTL(msg, r.minTTL, r.maxTTL)
				}
				return
			}
			r.stats.recordCacheHit(true)
			setMsgTTL(msg, r.optimisticCacheAnswerTTL) // Continue fetch
			cacheFailure = false
			r.markPrefetchClientRefresh(q.String())
			if done := r.tryStartRefresh(q.String()); done != nil {
				go func() {
					defer done()
					ctx, cancel := context.WithTimeout(context.Background(), resolver.DefaultDNSTimeout)
					defer cancel()
					_, _ = r.exchangeWithoutCache(ctx, m, cacheFailure)
				}()
			}
		} else {
			r.stats.recordCacheHit(false)
			r.markPrefetchNearExpiryHit(q.String(), expireTime, now)
			// updating TTL by subtracting common delta time from each DNS record
			updateMsgTTL(msg, uint32(time.Until(expireTime).Seconds()))
			clampMsgTTL(msg, r.minTTL, r.maxTTL)
		}
		return
	}
	r.stats.recordCacheMiss()
	msg, err = r.exchangeWithoutCache(ctx, m, true)
	if msg != nil {
		clampMsgTTL(msg, r.minTTL, r.maxTTL)
	}
	return
}

func (r *Resolver) optimisticCacheAlive(msg *D.Msg, expireTime time.Time, now time.Time) bool {
	return r.optimisticCache && r.optimisticCacheTTL > 0 && msg != nil && msg.Rcode != D.RcodeServerFailure && now.Before(expireTime.Add(r.optimisticCacheTTL))
}

// ExchangeWithoutCache a batch of dns request, and it do NOT GET from cache
func (r *Resolver) exchangeWithoutCache(ctx context.Context, m *D.Msg, cacheFailure bool) (msg *D.Msg, err error) {
	q := m.Question[0]

	retryNum := 0
	retryMax := 3
	fn := func() (result *D.Msg, err error) {
		ctx, cancel := context.WithTimeout(context.Background(), resolver.DefaultDNSTimeout) // reset timeout in singleflight
		defer cancel()
		cache := false

		defer func() {
			if err != nil {
				result = &D.Msg{}
				result.Opcode = retryNum
				retryNum++
				return
			}

			if cache {
				meta := putMsgToCache(r.cache, q, result, r.minTTL, r.maxTTL, cacheFailure)
				r.updatePrefetchMeta(meta)
			}
		}()

		isIPReq := isIPRequest(q)
		if isIPReq {
			cache = true
			return r.ipExchange(ctx, m)
		}

		if matched := r.matchPolicy(m); len(matched) != 0 {
			result, cache, err = batchExchange(ctx, matched, m, r.stats)
			return
		}
		result, cache, err = batchExchange(ctx, r.main, m, r.stats)
		return
	}

	ch := r.group.DoChan(q.String(), fn)

	var result singleflight.Result[*D.Msg]

	select {
	case result = <-ch:
		break
	case <-ctx.Done():
		select {
		case result = <-ch: // maybe ctxDone and chFinish in same time, get DoChan's result as much as possible
			break
		default:
			go func() { // start a retrying monitor in background
				result := <-ch
				ret, err, shared := result.Val, result.Err, result.Shared
				if err != nil && !shared && ret.Opcode < retryMax { // retry
					r.group.DoChan(q.String(), fn)
				}
			}()
			return nil, ctx.Err()
		}
	}

	ret, err, shared := result.Val, result.Err, result.Shared
	if err != nil && !shared && ret.Opcode < retryMax { // retry
		r.group.DoChan(q.String(), fn)
	}

	if err == nil {
		msg = ret
		if shared {
			msg = msg.Copy()
		}
	}

	return
}

func (r *Resolver) matchPolicy(m *D.Msg) []dnsClient {
	if r.policy == nil {
		return nil
	}

	domain := msgToDomain(m)
	if domain == "" {
		return nil
	}

	for _, policy := range r.policy {
		if dnsClients := policy.Match(domain); len(dnsClients) > 0 {
			return dnsClients
		}
	}
	return nil
}

func (r *Resolver) shouldOnlyQueryFallback(m *D.Msg) bool {
	if r.fallback == nil || len(r.fallbackDomainFilters) == 0 {
		return false
	}

	domain := msgToDomain(m)

	if domain == "" {
		return false
	}

	for _, df := range r.fallbackDomainFilters {
		if df.MatchDomain(domain) {
			return true
		}
	}

	return false
}

func (r *Resolver) ipExchange(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	if matched := r.matchPolicy(m); len(matched) != 0 {
		res := <-r.asyncExchange(ctx, matched, m)
		return res.Msg, res.Error
	}

	onlyFallback := r.shouldOnlyQueryFallback(m)

	if onlyFallback {
		res := <-r.asyncExchange(ctx, r.fallback, m)
		return res.Msg, res.Error
	}

	msgCh := r.asyncExchange(ctx, r.main, m)

	if r.fallback == nil || len(r.fallback) == 0 { // directly return if no fallback servers are available
		res := <-msgCh
		msg, err = res.Msg, res.Error
		return
	}

	res := <-msgCh
	if res.Error == nil {
		if ips := msgToIP(res.Msg); len(ips) != 0 {
			shouldNotFallback := lo.EveryBy(ips, func(ip netip.Addr) bool {
				return !r.shouldIPFallback(ip)
			})
			if shouldNotFallback {
				msg, err = res.Msg, res.Error // no need to wait for fallback result
				return
			}
		}
	}

	res = <-r.asyncExchange(ctx, r.fallback, m)
	msg, err = res.Msg, res.Error
	return
}

func (r *Resolver) lookupIP(ctx context.Context, host string, dnsType uint16) (ips []netip.Addr, err error) {
	ip, err := netip.ParseAddr(host)
	if err == nil {
		ip = ip.Unmap()
		isIPv4 := ip.Is4()
		if dnsType == D.TypeAAAA && !isIPv4 {
			return []netip.Addr{ip}, nil
		} else if dnsType == D.TypeA && isIPv4 {
			return []netip.Addr{ip}, nil
		} else {
			return []netip.Addr{}, resolver.ErrIPVersion
		}
	}

	query := &D.Msg{}
	query.SetQuestion(D.Fqdn(host), dnsType)

	msg, err := r.ExchangeContext(ctx, query)
	if err != nil {
		return []netip.Addr{}, err
	}

	ips = msgToIP(msg)
	ipLength := len(ips)
	if ipLength == 0 {
		return []netip.Addr{}, resolver.ErrIPNotFound
	}

	return
}

func (r *Resolver) asyncExchange(ctx context.Context, client []dnsClient, msg *D.Msg) <-chan *result {
	ch := make(chan *result, 1)
	go func() {
		res, _, err := batchExchange(ctx, client, msg, r.stats)
		ch <- &result{Msg: res, Error: err}
	}()
	return ch
}

// Invalid return this resolver can or can't be used
func (r *Resolver) Invalid() bool {
	if r == nil {
		return false
	}
	return len(r.main) > 0
}

func (r *Resolver) ClearCache() {
	if r != nil && r.cache != nil {
		r.cache.Clear()
		if r.prefetch != nil {
			r.prefetch.clear()
		}
	}
}

func (r *Resolver) StoreDNSCache() {
	if r == nil {
		return
	}
	if r.prefetch != nil {
		r.prefetch.syncRefreshCounts()
	}
	if cache, ok := r.cache.(interface{ Store() }); ok {
		cache.Store()
	}
	if dr := r.defaultResolver; dr != nil {
		dr.StoreDNSCache()
	}
}

func (r *Resolver) CloseDNSCache() {
	if r == nil {
		return
	}
	if r.prefetch != nil {
		r.prefetch.stopLoop()
	}
	if cache, ok := r.cache.(interface{ Close() }); ok {
		cache.Close()
	}
	if dr := r.defaultResolver; dr != nil {
		dr.CloseDNSCache()
	}
}

func (r *Resolver) ResetConnection() {
	if r != nil {
		for _, c := range r.main {
			c.ResetConnection()
		}
		for _, c := range r.fallback {
			c.ResetConnection()
		}
		if dr := r.defaultResolver; dr != nil {
			dr.ResetConnection()
		}
	}
}

func (r *Resolver) DNSStats() DNSStatsSnapshot {
	if r == nil {
		return DNSStatsSnapshot{}
	}
	return r.stats.snapshot()
}

func (r *Resolver) ResetDNSStats() {
	if r == nil {
		return
	}
	r.stats.reset()
}

type NameServer struct {
	Net          string
	Addr         string
	ProxyAdapter C.ProxyAdapter
	ProxyName    string
	Params       map[string]string
	PreferH3     bool
}

func (ns NameServer) Equal(ns2 NameServer) bool {
	defer func() {
		// C.ProxyAdapter compare maybe panic, just ignore
		recover()
	}()
	if ns.Net == ns2.Net &&
		ns.Addr == ns2.Addr &&
		ns.ProxyAdapter == ns2.ProxyAdapter &&
		ns.ProxyName == ns2.ProxyName &&
		maps.Equal(ns.Params, ns2.Params) &&
		ns.PreferH3 == ns2.PreferH3 {
		return true
	}
	return false
}

type Policy struct {
	Domain      string
	Matcher     C.DomainMatcher
	NameServers []NameServer
}

type Config struct {
	Main, Fallback           []NameServer
	Default                  []NameServer
	ProxyServer              []NameServer
	DirectServer             []NameServer
	DirectFollowPolicy       bool
	IPv6                     bool
	IPv6Timeout              uint
	FallbackIPFilter         []C.IpMatcher
	FallbackDomainFilter     []C.DomainMatcher
	Policy                   []Policy
	ProxyServerPolicy        []Policy
	CacheAlgorithm           string
	CacheMaxSize             int
	CacheSaveInterval        int
	OptimisticCache          bool
	OptimisticCacheTTL       int
	OptimisticCacheAnswerTTL int
	MinTTL                   uint32
	MaxTTL                   uint32
	Prefetch                 bool
	PrefetchScanInterval     int
	PrefetchThreshold        int
	PrefetchMinRefreshes     int
	PersistCache             bool
}

func (config Config) newCache(namespace string) dnsCache {
	if config.CacheMaxSize == 0 {
		config.CacheMaxSize = 4096
	}
	var cache dnsCache
	switch config.CacheAlgorithm {
	case "arc":
		cache = arc.New(arc.WithSize[string, *D.Msg](config.CacheMaxSize))
	default:
		cache = lru.New(lru.WithSize[string, *D.Msg](config.CacheMaxSize), lru.WithStale[string, *D.Msg](true))
	}
	if config.PersistCache {
		cache = newPersistentDNSCache(namespace, cache, config.CacheMaxSize, time.Duration(config.CacheSaveInterval)*time.Second, config.optimisticCacheTTL())
	}
	return cache
}

func (config Config) optimisticCacheTTL() time.Duration {
	if !config.OptimisticCache {
		return 0
	}
	if config.OptimisticCacheTTL == 0 {
		return defaultOptimisticCacheTTL
	}
	return time.Duration(config.OptimisticCacheTTL) * time.Second
}

func (config Config) optimisticCacheAnswerTTL() uint32 {
	if !config.OptimisticCache {
		return 0
	}
	if config.OptimisticCacheAnswerTTL <= 0 {
		return defaultOptimisticCacheAnswerTTL
	}
	return uint32(config.OptimisticCacheAnswerTTL)
}

func (config Config) effectiveMinTTL() uint32 {
	if config.MinTTL > 0 {
		return config.MinTTL
	}
	if config.Prefetch {
		return defaultPrefetchMinTTL
	}
	return 0
}

type Resolvers struct {
	*Resolver
	ProxyResolver  *Resolver
	DirectResolver *Resolver
}

func (rs Resolvers) ClearCache() {
	rs.Resolver.ClearCache()
	rs.ProxyResolver.ClearCache()
	rs.DirectResolver.ClearCache()
}

func (rs Resolvers) ResetConnection() {
	rs.Resolver.ResetConnection()
	rs.ProxyResolver.ResetConnection()
	rs.DirectResolver.ResetConnection()
}

func (rs Resolvers) StoreDNSCache() {
	rs.Resolver.StoreDNSCache()
	rs.ProxyResolver.StoreDNSCache()
	rs.DirectResolver.StoreDNSCache()
}

func (rs Resolvers) CloseDNSCache() {
	rs.Resolver.CloseDNSCache()
	rs.ProxyResolver.CloseDNSCache()
	rs.DirectResolver.CloseDNSCache()
}

func (rs Resolvers) DNSStats() DNSStatsSnapshot {
	snapshots := []DNSStatsSnapshot{rs.Resolver.DNSStats()}
	if rs.Resolver != nil {
		snapshots = append(snapshots, rs.Resolver.defaultResolver.DNSStats())
	}
	snapshots = append(snapshots, rs.ProxyResolver.DNSStats(), rs.DirectResolver.DNSStats())
	return combineDNSStatsSnapshots(snapshots...)
}

func (rs Resolvers) ResetDNSStats() {
	rs.Resolver.ResetDNSStats()
	if rs.Resolver != nil {
		rs.Resolver.defaultResolver.ResetDNSStats()
	}
	rs.ProxyResolver.ResetDNSStats()
	rs.DirectResolver.ResetDNSStats()
}

func NewResolver(config Config) (rs Resolvers) {
	optimisticCacheTTL := config.optimisticCacheTTL()
	optimisticCacheAnswerTTL := config.optimisticCacheAnswerTTL()
	minTTL := config.effectiveMinTTL()
	defaultResolver := &Resolver{
		main:        transform(config.Default, nil),
		cache:       config.newCache("default"),
		stats:       newDNSStats(),
		ipv6Timeout: time.Duration(config.IPv6Timeout) * time.Millisecond,
		minTTL:      minTTL,
		maxTTL:      config.MaxTTL,
	}
	defaultResolver.optimisticCache = config.OptimisticCache
	defaultResolver.optimisticCacheTTL = optimisticCacheTTL
	defaultResolver.optimisticCacheAnswerTTL = optimisticCacheAnswerTTL
	defaultResolver.initPrefetch(config)

	var nameServerCache []struct {
		NameServer
		dnsClient
	}
	cacheTransform := func(nameserver []NameServer) (result []dnsClient) {
	LOOP:
		for _, ns := range nameserver {
			for _, nsc := range nameServerCache {
				if nsc.NameServer.Equal(ns) {
					result = append(result, nsc.dnsClient)
					continue LOOP
				}
			}
			// not in cache
			dc := transform([]NameServer{ns}, defaultResolver)
			if len(dc) > 0 {
				dc := dc[0]
				nameServerCache = append(nameServerCache, struct {
					NameServer
					dnsClient
				}{NameServer: ns, dnsClient: dc})
				result = append(result, dc)
			}
		}
		return
	}

	makePolicy := func(policies []Policy) (dnsPolicies []dnsPolicy) {
		var triePolicy *trie.DomainTrie[[]dnsClient]
		insertPolicy := func(policy dnsPolicy) {
			if triePolicy != nil {
				triePolicy.Optimize()
				dnsPolicies = append(dnsPolicies, domainTriePolicy{triePolicy})
				triePolicy = nil
			}
			if policy != nil {
				dnsPolicies = append(dnsPolicies, policy)
			}
		}

		for _, policy := range policies {
			if policy.Matcher != nil {
				insertPolicy(domainMatcherPolicy{matcher: policy.Matcher, dnsClients: cacheTransform(policy.NameServers)})
			} else {
				if triePolicy == nil {
					triePolicy = trie.New[[]dnsClient]()
				}
				_ = triePolicy.Insert(policy.Domain, cacheTransform(policy.NameServers))
			}
		}
		insertPolicy(nil)
		return
	}

	r := &Resolver{
		ipv6:        config.IPv6,
		main:        cacheTransform(config.Main),
		cache:       config.newCache("main"),
		stats:       newDNSStats(),
		ipv6Timeout: time.Duration(config.IPv6Timeout) * time.Millisecond,
		policy:      makePolicy(config.Policy),
		minTTL:      minTTL,
		maxTTL:      config.MaxTTL,
	}
	r.optimisticCache = config.OptimisticCache
	r.optimisticCacheTTL = optimisticCacheTTL
	r.optimisticCacheAnswerTTL = optimisticCacheAnswerTTL
	r.defaultResolver = defaultResolver
	r.initPrefetch(config)
	rs.Resolver = r

	if len(config.ProxyServer) != 0 {
		rs.ProxyResolver = &Resolver{
			ipv6:        config.IPv6,
			main:        cacheTransform(config.ProxyServer),
			cache:       config.newCache("proxy"),
			stats:       newDNSStats(),
			ipv6Timeout: time.Duration(config.IPv6Timeout) * time.Millisecond,
			policy:      makePolicy(config.ProxyServerPolicy),
			minTTL:      minTTL,
			maxTTL:      config.MaxTTL,
		}
		rs.ProxyResolver.optimisticCache = config.OptimisticCache
		rs.ProxyResolver.optimisticCacheTTL = optimisticCacheTTL
		rs.ProxyResolver.optimisticCacheAnswerTTL = optimisticCacheAnswerTTL
		rs.ProxyResolver.initPrefetch(config)
	}

	if len(config.DirectServer) != 0 {
		rs.DirectResolver = &Resolver{
			ipv6:        config.IPv6,
			main:        cacheTransform(config.DirectServer),
			cache:       config.newCache("direct"),
			stats:       newDNSStats(),
			ipv6Timeout: time.Duration(config.IPv6Timeout) * time.Millisecond,
			minTTL:      minTTL,
			maxTTL:      config.MaxTTL,
		}
		rs.DirectResolver.optimisticCache = config.OptimisticCache
		rs.DirectResolver.optimisticCacheTTL = optimisticCacheTTL
		rs.DirectResolver.optimisticCacheAnswerTTL = optimisticCacheAnswerTTL
		rs.DirectResolver.initPrefetch(config)
		if config.DirectFollowPolicy {
			rs.DirectResolver.policy = r.policy
		}
	}

	if len(config.Fallback) != 0 {
		r.fallback = cacheTransform(config.Fallback)
		r.fallbackIPFilters = config.FallbackIPFilter
		r.fallbackDomainFilters = config.FallbackDomainFilter
	}

	return
}

var ParseNameServer func(servers []string) ([]NameServer, error) // define in config/config.go
