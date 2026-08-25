package mcpgw

import (
	"bufio"
	"errors"
	"strings"
	"testing"
)

// The property that bufio.Scanner could not provide: an oversized frame is a
// per-frame failure, and the reader keeps working afterwards.
func TestReadFrame_ResyncsAfterOversizedFrame(t *testing.T) {
	const max = 1024
	in := strings.Join([]string{
		`{"id":1,"method":"a"}`,
		`{"id":2,"method":"b","pad":"` + strings.Repeat("X", max*2) + `"}`,
		`{"id":3,"method":"c"}`,
	}, "\n") + "\n"

	r := bufio.NewReaderSize(strings.NewReader(in), 64)

	f, _, err := readFrame(r, max)
	if err != nil || string(f) != `{"id":1,"method":"a"}` {
		t.Fatalf("frame 1: got (%q, %v)", f, err)
	}

	_, prefix, err := readFrame(r, max)
	if !errors.Is(err, errFrameTooLong) {
		t.Fatalf("frame 2: err = %v, want errFrameTooLong", err)
	}
	if id := peekFrameID(prefix); id != float64(2) {
		t.Errorf("recovered id = %v (%T), want 2 — an oversized request that cannot be "+
			"identified cannot be answered, leaving the caller waiting forever", id, id)
	}

	f, _, err = readFrame(r, max)
	if err != nil || string(f) != `{"id":3,"method":"c"}` {
		t.Fatalf("frame 3 after resync: got (%q, %v) — the reader did not recover", f, err)
	}
}

// An oversized frame must not be buffered in full just to be discarded.
func TestReadFrame_DoesNotBufferOversizedFrame(t *testing.T) {
	const max = 1024
	huge := `{"id":7,"pad":"` + strings.Repeat("Y", 4*1024*1024) + `"}`
	r := bufio.NewReaderSize(strings.NewReader(huge+"\n"+`{"id":8}`+"\n"), 64)

	_, prefix, err := readFrame(r, max)
	if !errors.Is(err, errFrameTooLong) {
		t.Fatalf("err = %v, want errFrameTooLong", err)
	}
	if len(prefix) > framePrefixBytes {
		t.Errorf("retained %d bytes of a %d-byte frame; cap is %d — a hostile frame "+
			"would be buffered in full", len(prefix), len(huge), framePrefixBytes)
	}
	f, _, err := readFrame(r, max)
	if err != nil || string(f) != `{"id":8}` {
		t.Fatalf("next frame: got (%q, %v)", f, err)
	}
}

func TestReadFrame_BoundaryAndTrailing(t *testing.T) {
	const max = 32
	t.Run("exactly at cap is accepted", func(t *testing.T) {
		body := `{"id":1,"p":"` + strings.Repeat("z", max-15) + `"}`
		if len(body) != max {
			t.Fatalf("test setup: frame is %d bytes, want %d", len(body), max)
		}
		r := bufio.NewReaderSize(strings.NewReader(body+"\n"), 16)
		f, _, err := readFrame(r, max)
		if err != nil {
			t.Fatalf("a frame exactly at the cap must be accepted, got %v", err)
		}
		if string(f) != body {
			t.Errorf("frame = %q, want %q", f, body)
		}
	})
	t.Run("unterminated final frame is not dropped", func(t *testing.T) {
		r := bufio.NewReaderSize(strings.NewReader(`{"id":9}`), 16)
		f, _, err := readFrame(r, max)
		if err != nil {
			t.Fatalf("err = %v, want the trailing frame", err)
		}
		if string(f) != `{"id":9}` {
			t.Errorf("frame = %q; a final frame without a newline was dropped", f)
		}
	})
	t.Run("CRLF is stripped", func(t *testing.T) {
		r := bufio.NewReaderSize(strings.NewReader("{\"id\":1}\r\n"), 16)
		f, _, err := readFrame(r, max)
		if err != nil || string(f) != `{"id":1}` {
			t.Errorf("got (%q, %v), want the frame with CRLF stripped", f, err)
		}
	})
}

func TestPeekFrameID_Shapes(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want interface{}
	}{
		{"int id", `{"jsonrpc":"2.0","id":42,"method":"x"}`, float64(42)},
		{"string id", `{"id":"abc","method":"x"}`, "abc"},
		{"id after method", `{"method":"x","id":7}`, float64(7)},
		{"explicit null is not an id", `{"id":null,"method":"x"}`, nil},
		{"absent id", `{"method":"x"}`, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := peekFrameID([]byte(c.in)); got != c.want {
				t.Errorf("peekFrameID(%s) = %v (%T), want %v", c.in, got, got, c.want)
			}
		})
	}
}
