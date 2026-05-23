package server_handler

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/server"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

func mustBuildRawResp(t *testing.T, id uint16, ra bool, ttl uint32) []byte {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion("raw.example.org.", dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(q)
	resp.Id = id
	resp.RecursionAvailable = ra
	rr, err := dns.NewRR("raw.example.org. 60 IN A 1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	rr.Header().Ttl = ttl
	resp.Answer = []dns.RR{rr}
	wire, err := resp.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestEntryHandler_RawResponse_UDPFastPath(t *testing.T) {
	entry := sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
		qCtx.SetRawResponse(mustBuildRawResp(t, 0x1111, false, 42))
		return nil
	})
	h := NewEntryHandler(EntryHandlerOpts{Entry: entry})

	req := new(dns.Msg)
	req.SetQuestion("raw.example.org.", dns.TypeA)
	req.Id = 0xCAFE

	payload := h.Handle(context.Background(), req, server.QueryMeta{FromUDP: true}, pool.PackBuffer)
	if payload == nil {
		t.Fatal("nil payload")
	}
	defer pool.ReleaseBuf(payload)

	resp := new(dns.Msg)
	if err := resp.Unpack(*payload); err != nil {
		t.Fatal(err)
	}
	if resp.Id != req.Id {
		t.Fatalf("id mismatch, got=%d want=%d", resp.Id, req.Id)
	}
	if !resp.RecursionAvailable {
		t.Fatal("RA flag should be set")
	}
	if len(resp.Answer) == 0 {
		t.Fatal("missing answer")
	}
}

func TestEntryHandler_RawResponse_TCPFastPath(t *testing.T) {
	entry := sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
		qCtx.SetRawResponse(mustBuildRawResp(t, 0x2222, false, 30))
		return nil
	})
	h := NewEntryHandler(EntryHandlerOpts{Entry: entry})

	req := new(dns.Msg)
	req.SetQuestion("raw.example.org.", dns.TypeA)
	req.Id = 0xBEEF

	payload := h.Handle(context.Background(), req, server.QueryMeta{FromUDP: false}, pool.PackTCPBuffer)
	if payload == nil {
		t.Fatal("nil payload")
	}
	defer pool.ReleaseBuf(payload)

	if len(*payload) < 14 {
		t.Fatalf("payload too short: %d", len(*payload))
	}
	l := int(binary.BigEndian.Uint16((*payload)[:2]))
	if l != len(*payload)-2 {
		t.Fatalf("tcp length mismatch: %d vs %d", l, len(*payload)-2)
	}

	resp := new(dns.Msg)
	if err := resp.Unpack((*payload)[2:]); err != nil {
		t.Fatal(err)
	}
	if resp.Id != req.Id {
		t.Fatalf("id mismatch, got=%d want=%d", resp.Id, req.Id)
	}
	if !resp.RecursionAvailable {
		t.Fatal("RA flag should be set")
	}
}

func TestEntryHandler_RawResponse_FallbackWithRespOpt(t *testing.T) {
	entry := sequence.ExecutableFunc(func(_ context.Context, qCtx *query_context.Context) error {
		qCtx.SetRawResponse(mustBuildRawResp(t, 0x3333, false, 20))
		return nil
	})
	h := NewEntryHandler(EntryHandlerOpts{Entry: entry})

	req := new(dns.Msg)
	req.SetQuestion("raw.example.org.", dns.TypeA)
	req.Id = 0xD00D
	req.SetEdns0(1232, true)

	payload := h.Handle(context.Background(), req, server.QueryMeta{FromUDP: true}, pool.PackBuffer)
	if payload == nil {
		t.Fatal("nil payload")
	}
	defer pool.ReleaseBuf(payload)

	resp := new(dns.Msg)
	if err := resp.Unpack(*payload); err != nil {
		t.Fatal(err)
	}
	if resp.Id != req.Id {
		t.Fatalf("id mismatch, got=%d want=%d", resp.Id, req.Id)
	}
	opt := resp.IsEdns0()
	if opt == nil {
		t.Fatal("expected EDNS0 OPT in response")
	}
	if !opt.Do() {
		t.Fatal("expected DO bit copied to response opt")
	}
}
