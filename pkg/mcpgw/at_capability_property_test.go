package mcpgw

// AT (Test Wrangler) property-based tests over the bridge's tools/list
// aggregation + namespace-prefix logic. The bridge's bridge.go
// handleToolsList walks every upstream, prefixes each tool name with
// the namespace, and skips tool names that already contain ':' (which
// would collide with the prefix scheme). The combinatorial input
// space (N upstreams * M tools each * possible name collisions and
// `_meta` carry-over) is large enough that a hand-table can miss
// edge cases. These tests use testing/quick to drive random shapes
// through the same in-process bridge harness the worker tests use.
//
// Properties pinned:
//   1. The merged tools/list returns exactly the set of expected
//      prefixed names (sum of upstream-side counts minus skipped
//      name-with-colon entries).
//   2. No two output tool names collide (every output is unique).
//   3. A downstream tool name containing ':' is silently dropped at
//      the gateway with a log warning — the design choice A17 made
//      in handleToolsList. Future versions may escape instead; this
//      test pins the v0.5 behaviour.
//   4. If any upstream returns an error from tools/list, the bridge
//      surfaces an error log but does NOT poison subsequent calls
//      (the cache, if any, retries cleanly).
//
// All upstreams used here are the in-process fakeUpstream from
// bridge_test.go, NOT mocks of the bridge itself — the SUT is the
// real Bridge.handleToolsList.

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"sync/atomic"
	"testing"
	"testing/quick"
)

// TestAT_CapabilityMerge_Property_NameUniquenessAndCount runs
// quick.Check on a generator that produces 1..5 namespaces, each with
// 0..6 tools whose names are random alphanumerics. The properties
// asserted: the merged result count equals the sum of input counts
// (no colon-bearing names in this generator), and every output name is
// unique.
func TestAT_CapabilityMerge_Property_NameUniquenessAndCount(t *testing.T) {
	property := func(seed int64) bool {
		r := rand.New(rand.NewSource(seed))
		nNs := 1 + r.Intn(5)

		fakes := make([]*fakeUpstream, 0, nNs)
		seenNs := map[string]bool{}
		expectedTotal := 0
		for i := 0; i < nNs; i++ {
			var ns string
			for {
				ns = randomToken(r, 1+r.Intn(6))
				if !seenNs[ns] {
					break
				}
			}
			seenNs[ns] = true

			nTools := r.Intn(7)
			tools := make([]ToolDescriptor, 0, nTools)
			seenTool := map[string]bool{}
			for j := 0; j < nTools; j++ {
				var name string
				for attempt := 0; attempt < 8; attempt++ {
					name = randomToken(r, 1+r.Intn(8))
					if !seenTool[name] {
						break
					}
				}
				if seenTool[name] {
					continue // give up on this slot if we can't pick a unique name in 8 tries
				}
				seenTool[name] = true
				tools = append(tools, ToolDescriptor{Name: name})
			}
			expectedTotal += len(tools)

			f := newFakeUpstream(ns)
			f.handleSend = makeListSender(t, tools)
			fakes = append(fakes, f)
		}

		b := newTestBridge(t, fakes...)
		h := newBridgeHarness(t, b)
		h.send(map[string]interface{}{
			"jsonrpc": "2.0", "id": 1, "method": "tools/list",
			"params": map[string]interface{}{},
		})
		resp := h.readResponse()
		if resp.Error != nil {
			t.Logf("seed=%d unexpected error: %+v", seed, resp.Error)
			return false
		}
		var list ToolsListResult
		if err := json.Unmarshal(resp.Result, &list); err != nil {
			t.Logf("seed=%d decode failed: %v", seed, err)
			return false
		}
		if len(list.Tools) != expectedTotal {
			t.Logf("seed=%d: tool count = %d, expected %d (per-ns counts)", seed, len(list.Tools), expectedTotal)
			return false
		}
		seenNames := map[string]bool{}
		for _, tool := range list.Tools {
			if seenNames[tool.Name] {
				t.Logf("seed=%d: duplicate tool name %q", seed, tool.Name)
				return false
			}
			seenNames[tool.Name] = true
			// Every output name must contain exactly one ':' (the
			// namespace-tool separator) — the input generator never
			// emits colons.
			if strings.Count(tool.Name, ":") != 1 {
				t.Logf("seed=%d: name %q has wrong colon count", seed, tool.Name)
				return false
			}
		}
		return true
	}

	if err := quick.Check(property, &quick.Config{MaxCount: 50, Rand: rand.New(rand.NewSource(0xA17AC42))}); err != nil {
		t.Errorf("property failed: %v", err)
	}
}

// TestAT_CapabilityMerge_NameWithColonDropped pins the v0.5 design
// choice: a downstream advertising a tool name containing `:`
// is dropped (skipped) by handleToolsList rather than crashing or
// silently producing an ambiguous prefix. This is documented in
// bridge.go:447-451.
func TestAT_CapabilityMerge_NameWithColonDropped(t *testing.T) {
	up := newFakeUpstream("fs")
	up.handleSend = makeListSender(t, []ToolDescriptor{
		{Name: "good_tool"},
		{Name: "bad:name:tool"},
		{Name: "another_good"},
	})

	b := newTestBridge(t, up)
	h := newBridgeHarness(t, b)
	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "tools/list",
		"params": map[string]interface{}{},
	})
	resp := h.readResponse()
	if resp.Error != nil {
		t.Fatalf("error: %+v", resp.Error)
	}
	var list ToolsListResult
	if err := json.Unmarshal(resp.Result, &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	gotNames := map[string]bool{}
	for _, tool := range list.Tools {
		gotNames[tool.Name] = true
	}
	if !gotNames["fs:good_tool"] {
		t.Errorf("missing fs:good_tool: %+v", list.Tools)
	}
	if !gotNames["fs:another_good"] {
		t.Errorf("missing fs:another_good: %+v", list.Tools)
	}
	for name := range gotNames {
		if strings.Contains(strings.TrimPrefix(name, "fs:"), ":") {
			t.Errorf("colon-bearing tool was emitted: %q", name)
		}
	}
}

// TestAT_CapabilityMerge_UpstreamErrorDoesNotPoisonCache asserts
// that a tools/list returning an error from one upstream causes the
// bridge to log + skip that upstream, but the next call retries and
// can succeed. This protects against a regression where a cached
// negative result would leak across calls.
func TestAT_CapabilityMerge_UpstreamErrorDoesNotPoisonCache(t *testing.T) {
	upBad := newFakeUpstream("bad")
	var badCalls atomic.Int32
	var failFirst atomic.Bool
	failFirst.Store(true)

	upBad.handleSend = func(req *Request) *Response {
		if req.Method != MethodToolsList {
			return &Response{Result: json.RawMessage(`{}`)}
		}
		c := badCalls.Add(1)
		_ = c
		if failFirst.Load() {
			return &Response{
				Error: &Error{Code: -32603, Message: "synthetic upstream failure"},
			}
		}
		raw, err := json.Marshal(ToolsListResult{
			Tools: []ToolDescriptor{{Name: "recovered_tool"}},
		})
		if err != nil {
			panic(err)
		}
		return &Response{Result: raw}
	}

	upGood := newFakeUpstream("good")
	upGood.handleSend = makeListSender(t, []ToolDescriptor{{Name: "always_works"}})

	b := newTestBridge(t, upBad, upGood)
	h := newBridgeHarness(t, b)

	// Call 1: upBad errors, upGood succeeds — bridge should return
	// only good's tools.
	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "tools/list",
		"params": map[string]interface{}{},
	})
	r1 := h.readResponse()
	if r1.Error != nil {
		t.Fatalf("call 1 should not be an outer JSON-RPC error (one upstream errored, the other succeeded): %+v", r1.Error)
	}
	var list1 ToolsListResult
	if err := json.Unmarshal(r1.Result, &list1); err != nil {
		t.Fatalf("decode 1: %v", err)
	}
	if len(list1.Tools) != 1 || list1.Tools[0].Name != "good:always_works" {
		t.Errorf("call 1: expected only good:always_works, got %+v", list1.Tools)
	}

	// Now flip upBad to succeed and retry — the bridge MUST surface
	// the recovered tool (i.e., no negative cache).
	failFirst.Store(false)
	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 2, "method": "tools/list",
		"params": map[string]interface{}{},
	})
	r2 := h.readResponse()
	if r2.Error != nil {
		t.Fatalf("call 2 error: %+v", r2.Error)
	}
	var list2 ToolsListResult
	if err := json.Unmarshal(r2.Result, &list2); err != nil {
		t.Fatalf("decode 2: %v", err)
	}
	got := map[string]bool{}
	for _, tool := range list2.Tools {
		got[tool.Name] = true
	}
	if !got["bad:recovered_tool"] {
		t.Errorf("call 2: expected bad:recovered_tool after upstream recovered, got %+v", list2.Tools)
	}
	if !got["good:always_works"] {
		t.Errorf("call 2: expected good:always_works, got %+v", list2.Tools)
	}
}

// TestAT_CapabilityMerge_PropertyTwoUpstreamsCorrectRouting walks
// two stub upstreams advertising the same RAW tool name (e.g., both
// "search") and asserts both end up in the merged list with distinct
// prefixes and that a tools/call routes to the right upstream.
func TestAT_CapabilityMerge_PropertyTwoUpstreamsCorrectRouting(t *testing.T) {
	upA := newFakeUpstream("alpha")
	upB := newFakeUpstream("beta")

	var aCalls, bCalls atomic.Int32
	upA.handleSend = func(req *Request) *Response {
		switch req.Method {
		case MethodToolsList:
			raw, _ := json.Marshal(ToolsListResult{
				Tools: []ToolDescriptor{{Name: "search"}},
			})
			return &Response{Result: raw}
		case MethodToolsCall:
			aCalls.Add(1)
			raw, _ := json.Marshal(ToolsCallResult{
				Content: []ContentBlock{{Type: "text", Text: "alpha-result"}},
			})
			return &Response{Result: raw}
		}
		return &Response{Result: json.RawMessage(`{}`)}
	}
	upB.handleSend = func(req *Request) *Response {
		switch req.Method {
		case MethodToolsList:
			raw, _ := json.Marshal(ToolsListResult{
				Tools: []ToolDescriptor{{Name: "search"}},
			})
			return &Response{Result: raw}
		case MethodToolsCall:
			bCalls.Add(1)
			raw, _ := json.Marshal(ToolsCallResult{
				Content: []ContentBlock{{Type: "text", Text: "beta-result"}},
			})
			return &Response{Result: raw}
		}
		return &Response{Result: json.RawMessage(`{}`)}
	}

	b := newTestBridge(t, upA, upB)
	h := newBridgeHarness(t, b)

	// tools/list — both prefixed entries present.
	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": map[string]interface{}{},
	})
	resp := h.readResponse()
	var list ToolsListResult
	if err := json.Unmarshal(resp.Result, &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	gotNames := map[string]bool{}
	for _, tool := range list.Tools {
		gotNames[tool.Name] = true
	}
	if !gotNames["alpha:search"] || !gotNames["beta:search"] {
		t.Fatalf("namespace prefix did not de-collide same-named tools: got %+v", list.Tools)
	}

	// tools/call alpha:search → only upA fires.
	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]interface{}{
			"name":      "alpha:search",
			"arguments": map[string]interface{}{"q": "x"},
		},
	})
	r2 := h.readResponse()
	if r2.Error != nil {
		t.Fatalf("alpha call: %+v", r2.Error)
	}
	if aCalls.Load() != 1 || bCalls.Load() != 0 {
		t.Errorf("alpha:search routing: aCalls=%d bCalls=%d (want 1/0)", aCalls.Load(), bCalls.Load())
	}

	// tools/call beta:search → only upB fires.
	h.send(map[string]interface{}{
		"jsonrpc": "2.0", "id": 3, "method": "tools/call",
		"params": map[string]interface{}{
			"name":      "beta:search",
			"arguments": map[string]interface{}{"q": "y"},
		},
	})
	_ = h.readResponse()
	if aCalls.Load() != 1 || bCalls.Load() != 1 {
		t.Errorf("beta:search routing: aCalls=%d bCalls=%d (want 1/1)", aCalls.Load(), bCalls.Load())
	}
}

// makeListSender returns a handleSend function that echoes a fixed
// tools list back on tools/list and an empty result for everything
// else. Used by the property tests to seed each upstream with a
// generated catalogue.
func makeListSender(t *testing.T, tools []ToolDescriptor) func(req *Request) *Response {
	t.Helper()
	raw, err := json.Marshal(ToolsListResult{Tools: tools})
	if err != nil {
		t.Fatalf("marshal seed tools: %v", err)
	}
	return func(req *Request) *Response {
		if req.Method == MethodToolsList {
			return &Response{Result: raw}
		}
		return &Response{Result: json.RawMessage(`{}`)}
	}
}

// randomToken builds a lowercase alphanumeric token of exactly n bytes
// from r. Used by the property generator. Never contains a `:` (the
// colon-collision scenario is exercised separately).
func randomToken(r *rand.Rand, n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789_"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[r.Intn(len(letters))]
	}
	return string(b)
}

// reflectErrorString avoids importing reflect just for a tiny utility.
// errors.New produces a fixed string per call site so we keep an
// explicit constant for the colon-test panic — but we never actually
// need it; left here as a helper sentinel for future extensions.
var _ = errors.New
var _ = fmt.Sprintf
