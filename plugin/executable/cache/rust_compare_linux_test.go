//go:build linux && cgo && mosdns_rust_cache

package cache

import (
	"context"
	"fmt"
	gocache "github.com/IrineSistiana/mosdns/v5/pkg/cache"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"testing"
	"time"
)

func makeQueryAndResponse(ttl uint32) (*dns.Msg, *dns.Msg, []byte, []byte, string, error) {
	q := new(dns.Msg)
	q.SetQuestion("bench.example.org.", dns.TypeA)

	resp := new(dns.Msg)
	resp.SetReply(q)
	rr, err := dns.NewRR("bench.example.org. 60 IN A 1.2.3.4")
	if err != nil {
		return nil, nil, nil, nil, "", fmt.Errorf("new rr: %w", err)
	}
	rr.Header().Ttl = ttl
	resp.Answer = []dns.RR{rr}

	qBytes, err := q.Pack()
	if err != nil {
		return nil, nil, nil, nil, "", fmt.Errorf("pack query: %w", err)
	}
	respBytes, err := copyNoOpt(resp).Pack()
	if err != nil {
		return nil, nil, nil, nil, "", fmt.Errorf("pack response: %w", err)
	}

	qCtx := query_context.NewContext(q.Copy())
	msgKeyBuf, bufPtr := getMsgKeyBytes(qCtx.Q(), qCtx, false)
	if msgKeyBuf == nil {
		return nil, nil, nil, nil, "", fmt.Errorf("failed to build cache key")
	}
	msgKey := string(msgKeyBuf)
	keyBufferPool.Put(bufPtr)

	return q, resp, qBytes, respBytes, msgKey, nil
}

func mustMakeQueryAndResponseT(t *testing.T, ttl uint32) (*dns.Msg, *dns.Msg, []byte, []byte, string) {
	t.Helper()
	q, resp, qBytes, respBytes, msgKey, err := makeQueryAndResponse(ttl)
	if err != nil {
		t.Fatal(err)
	}
	return q, resp, qBytes, respBytes, msgKey
}

func mustMakeQueryAndResponseB(b *testing.B, ttl uint32) (*dns.Msg, *dns.Msg, []byte, []byte, string) {
	b.Helper()
	q, resp, qBytes, respBytes, msgKey, err := makeQueryAndResponse(ttl)
	if err != nil {
		b.Fatal(err)
	}
	return q, resp, qBytes, respBytes, msgKey
}

func mustStoreGo(t *testing.T, backend *gocache.Cache[key, *item], msgKey string, resp *dns.Msg, lazyTTL int, domainSet string) {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion("bench.example.org.", dns.TypeA)
	qCtx := query_context.NewContext(q)
	qCtx.SetResponse(resp.Copy())
	if domainSet != "" {
		qCtx.StoreValue(query_context.KeyDomainSet, domainSet)
	}
	if !saveRespToCache(msgKey, qCtx, backend, lazyTTL) {
		t.Fatal("saveRespToCache returned false")
	}
}

func parseFirstAnswerTTL(t *testing.T, msg *dns.Msg) uint32 {
	t.Helper()
	if msg == nil || len(msg.Answer) == 0 {
		t.Fatal("missing answer")
	}
	return msg.Answer[0].Header().Ttl
}

func TestRustAndGoCacheBehaviorParity(t *testing.T) {
	args := &Args{Size: 1024, LazyCacheTTL: 30}
	bridge, err := newRustBridge(args, zap.NewNop())
	if err != nil {
		t.Fatalf("newRustBridge: %v", err)
	}
	defer bridge.Close()

	backend := gocache.New[key, *item](gocache.Opts{Size: 1024})
	_, resp, _, respBytes, msgKey := mustMakeQueryAndResponseT(t, 2)
	queryKey := []byte(msgKey)

	domainSet := "bench"
	now := time.Now()

	stored, err := bridge.StoreByKey(queryKey, respBytes, domainSet, now)
	if err != nil {
		t.Fatalf("rust store: %v", err)
	}
	if !stored {
		t.Fatal("rust store rejected cacheable response")
	}
	mustStoreGo(t, backend, msgKey, resp, args.LazyCacheTTL, domainSet)

	// Fresh stage parity.
	goResp, goLazy, goDomain := getRespFromCache(msgKey, backend, true, expiredMsgTtl)
	if goResp == nil || goLazy {
		t.Fatalf("unexpected go fresh result, resp nil=%v lazy=%v", goResp == nil, goLazy)
	}
	if goDomain != domainSet {
		t.Fatalf("go domain_set mismatch, got %q want %q", goDomain, domainSet)
	}
	rustLookupFresh, err := bridge.LookupByKey(queryKey, now)
	if err != nil {
		t.Fatalf("rust lookup fresh: %v", err)
	}
	if rustLookupFresh.State != bridgeLookupFresh {
		t.Fatalf("unexpected rust fresh state: %v", rustLookupFresh.State)
	}
	rustFreshMsg := new(dns.Msg)
	if err := rustFreshMsg.Unpack(rustLookupFresh.Response); err != nil {
		t.Fatalf("unpack rust fresh response: %v", err)
	}
	if rustLookupFresh.DomainSet != domainSet {
		t.Fatalf("rust domain_set mismatch, got %q want %q", rustLookupFresh.DomainSet, domainSet)
	}
	if parseFirstAnswerTTL(t, rustFreshMsg) == 0 || parseFirstAnswerTTL(t, goResp) == 0 {
		t.Fatal("fresh ttl should be positive")
	}

	// Lazy stage parity (wait until message ttl expires but lazy ttl is still valid).
	time.Sleep(3 * time.Second)

	goRespLazy, goLazy, _ := getRespFromCache(msgKey, backend, true, expiredMsgTtl)
	if goRespLazy == nil || !goLazy {
		t.Fatalf("unexpected go lazy result, resp nil=%v lazy=%v", goRespLazy == nil, goLazy)
	}
	goLazyTTL := parseFirstAnswerTTL(t, goRespLazy)
	if goLazyTTL != expiredMsgTtl {
		t.Fatalf("go lazy ttl mismatch, got %d want %d", goLazyTTL, expiredMsgTtl)
	}

	rustLookupLazy, err := bridge.LookupByKey(queryKey, time.Now())
	if err != nil {
		t.Fatalf("rust lookup lazy: %v", err)
	}
	if rustLookupLazy.State != bridgeLookupLazy {
		t.Fatalf("unexpected rust lazy state: %v", rustLookupLazy.State)
	}
	rustLazyMsg := new(dns.Msg)
	if err := rustLazyMsg.Unpack(rustLookupLazy.Response); err != nil {
		t.Fatalf("unpack rust lazy response: %v", err)
	}
	rustLazyTTL := parseFirstAnswerTTL(t, rustLazyMsg)
	if rustLazyTTL != expiredMsgTtl {
		t.Fatalf("rust lazy ttl mismatch, got %d want %d", rustLazyTTL, expiredMsgTtl)
	}
}

func BenchmarkCacheLookupGoHit(b *testing.B) {
	backend := gocache.New[key, *item](gocache.Opts{Size: 1024})
	_, resp, _, _, msgKey := mustMakeQueryAndResponseB(b, 600)
	q := new(dns.Msg)
	q.SetQuestion("bench.example.org.", dns.TypeA)
	qCtx := query_context.NewContext(q)
	qCtx.SetResponse(resp.Copy())
	if !saveRespToCache(msgKey, qCtx, backend, 600) {
		b.Fatal("saveRespToCache returned false")
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r, _, _ := getRespFromCache(msgKey, backend, true, expiredMsgTtl)
		if r == nil {
			b.Fatal("go lookup miss on benchmark hot path")
		}
	}
}

func BenchmarkCacheLookupRustHit(b *testing.B) {
	args := &Args{Size: 1024, LazyCacheTTL: 600}
	bridge, err := newRustBridge(args, zap.NewNop())
	if err != nil {
		b.Fatalf("newRustBridge: %v", err)
	}
	defer bridge.Close()

	_, _, _, respBytes, msgKey := mustMakeQueryAndResponseB(b, 600)
	queryKey := []byte(msgKey)
	stored, err := bridge.StoreByKey(queryKey, respBytes, "", time.Now())
	if err != nil {
		b.Fatalf("rust store: %v", err)
	}
	if !stored {
		b.Fatal("rust store rejected cacheable response")
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res, err := bridge.LookupByKey(queryKey, time.Now())
		if err != nil {
			b.Fatal(err)
		}
		if res.State == bridgeLookupMiss {
			b.Fatal("rust lookup miss on benchmark hot path")
		}
	}
}

func BenchmarkCacheStoreGo(b *testing.B) {
	backend := gocache.New[key, *item](gocache.Opts{Size: 1024})
	q, resp, _, _, _ := mustMakeQueryAndResponseB(b, 120)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		qCtx := query_context.NewContext(q.Copy())
		qCtx.SetResponse(resp.Copy())
		msgKeyBuf, bufPtr := getMsgKeyBytes(qCtx.Q(), qCtx, false)
		msgKey := string(msgKeyBuf)
		keyBufferPool.Put(bufPtr)
		if !saveRespToCache(msgKey, qCtx, backend, 120) {
			b.Fatal("saveRespToCache returned false")
		}
	}
}

func BenchmarkCacheStoreRust(b *testing.B) {
	args := &Args{Size: 1024, LazyCacheTTL: 120}
	bridge, err := newRustBridge(args, zap.NewNop())
	if err != nil {
		b.Fatalf("newRustBridge: %v", err)
	}
	defer bridge.Close()

	_, _, _, respBytes, msgKey := mustMakeQueryAndResponseB(b, 120)
	queryKey := []byte(msgKey)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stored, err := bridge.StoreByKey(queryKey, respBytes, "", time.Now())
		if err != nil {
			b.Fatal(err)
		}
		if !stored {
			b.Fatal("rust store returned false")
		}
	}
}

func BenchmarkCacheExecGoHotHit(b *testing.B) {
	b.Setenv(cacheBackendEnv, "")
	b.Setenv(rustGoMirrorEnv, "")

	c := NewCache(&Args{Size: 1024, LazyCacheTTL: 600}, Opts{})
	defer c.Close()

	q, resp, _, _, msgKey := mustMakeQueryAndResponseB(b, 600)
	qStore := query_context.NewContext(q.Copy())
	qStore.SetResponse(resp.Copy())
	if !saveRespToCache(msgKey, qStore, c.backend, 600) {
		b.Fatal("saveRespToCache returned false")
	}

	// Warmup once to promote the record to Go L1.
	qWarm := query_context.NewContext(q.Copy())
	if err := c.Exec(context.Background(), qWarm, sequence.ChainWalker{}); err != nil {
		b.Fatal(err)
	}
	if qWarm.R() == nil && len(qWarm.RawResponse()) == 0 {
		b.Fatal("warmup miss")
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		qCtx := query_context.NewContext(q.Copy())
		if err := c.Exec(context.Background(), qCtx, sequence.ChainWalker{}); err != nil {
			b.Fatal(err)
		}
		if qCtx.R() == nil && len(qCtx.RawResponse()) == 0 {
			b.Fatal("cache miss on go hot hit benchmark")
		}
	}
}

func BenchmarkCacheExecRustHotHit(b *testing.B) {
	b.Setenv(cacheBackendEnv, "rust")
	b.Setenv(rustGoMirrorEnv, "")

	c := NewCache(&Args{Size: 1024, LazyCacheTTL: 600}, Opts{})
	defer c.Close()
	if c.rustBridge == nil {
		b.Fatal("rust bridge is nil in rust benchmark")
	}

	q, _, _, respBytes, msgKey := mustMakeQueryAndResponseB(b, 600)
	queryKey := []byte(msgKey)
	stored, err := c.rustBridge.StoreByKey(queryKey, respBytes, "", time.Now())
	if err != nil {
		b.Fatal(err)
	}
	if !stored {
		b.Fatal("rust pre-store returned false")
	}

	// Warmup once to populate Rust-mode Go L1.
	qWarm := query_context.NewContext(q.Copy())
	if err := c.Exec(context.Background(), qWarm, sequence.ChainWalker{}); err != nil {
		b.Fatal(err)
	}
	if qWarm.R() == nil && len(qWarm.RawResponse()) == 0 {
		b.Fatal("warmup miss")
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		qCtx := query_context.NewContext(q.Copy())
		if err := c.Exec(context.Background(), qCtx, sequence.ChainWalker{}); err != nil {
			b.Fatal(err)
		}
		if qCtx.R() == nil && len(qCtx.RawResponse()) == 0 {
			b.Fatal("cache miss on rust hot hit benchmark")
		}
	}
}
