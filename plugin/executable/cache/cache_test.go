/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package cache

import (
	"bytes"
	"github.com/miekg/dns"
	"strconv"
	"strings"
	"testing"
	"time"
)

func Test_cachePlugin_Dump(t *testing.T) {
	c := NewCache(&Args{Size: 16 * dumpBlockSize}, Opts{}) // Big enough to create dump fragments.

	resp := new(dns.Msg)
	resp.SetQuestion("test.", dns.TypeA)

	// Fix: Pack the dns.Msg to []byte because item.resp is now []byte
	packedResp, err := resp.Pack()
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	hourLater := now.Add(time.Hour)
	v := &item{
		resp:           packedResp,
		storedTime:     now,
		expirationTime: hourLater,
	}

	// Fill the cache
	for i := 0; i < 32*dumpBlockSize; i++ {
		c.backend.Store(key(strconv.Itoa(i)), v, hourLater)
	}

	buf := new(bytes.Buffer)
	enw, err := c.writeDump(buf)
	if err != nil {
		t.Fatal(err)
	}
	enr, err := c.readDump(buf)
	if err != nil {
		t.Fatal(err)
	}

	if enw != enr {
		t.Fatalf("read err, wrote %d entries, read %d", enw, enr)
	}
}

func Test_cachePlugin_RenderShowFromDump(t *testing.T) {
	c := NewCache(&Args{Size: 32}, Opts{})

	q := new(dns.Msg)
	q.SetQuestion("example.org.", dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(q)
	rr, err := dns.NewRR("example.org. 60 IN A 1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	resp.Answer = []dns.RR{rr}

	packedResp, err := resp.Pack()
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	c.backend.Store(key("test-key"), &item{
		resp:           packedResp,
		storedTime:     now,
		expirationTime: now.Add(time.Minute),
		domainSet:      "cn",
	}, now.Add(time.Minute))

	dumpBuf := new(bytes.Buffer)
	if _, err := c.writeDump(dumpBuf); err != nil {
		t.Fatal(err)
	}

	showBuf := new(bytes.Buffer)
	if err := c.renderShowFromDump(showBuf, dumpBuf.Bytes(), "1.2.3.4", 10, 0); err != nil {
		t.Fatal(err)
	}

	out := showBuf.String()
	if !strings.Contains(out, "----- Cache Entry -----") {
		t.Fatalf("show output missing cache entry header, got: %s", out)
	}
	if !strings.Contains(out, "1.2.3.4") {
		t.Fatalf("show output missing deep-matched answer ip, got: %s", out)
	}
}
