package mcpgw

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// errFrameTooLong reports a newline-delimited frame larger than the configured
// cap. The frame is discarded; the reader stays usable.
//
// This exists because bufio.Scanner cannot do it. Once Scan returns
// bufio.ErrTooLong the Scanner is permanently dead -- it recovers zero
// subsequent tokens and offers no way to resynchronize. Both read loops used a
// Scanner, so one oversized frame ended the loop: on the host side that
// returned from Bridge.Run, which main turns into os.Exit(1) (audit B10); on
// the upstream side it killed readLoop while the subprocess kept running
// (audit B12).
var errFrameTooLong = errors.New("mcpgw: frame exceeds maximum size")

// framePrefixBytes is how much of an oversized frame is retained so a request
// id can be recovered for an error reply. A JSON-RPC frame carries its id in
// the first handful of fields in practice; this is best-effort, and a frame
// whose id is not in the prefix simply gets no reply, which is no worse than
// the silence that preceded this.
const framePrefixBytes = 8 * 1024

// readFrame returns the next newline-delimited frame from r.
//
// On a frame longer than max it discards the remainder through the next
// newline and returns errFrameTooLong along with the retained prefix, leaving r
// positioned at the start of the following frame. The returned frame is only
// valid until the next call.
func readFrame(r *bufio.Reader, max int) (frame []byte, prefix []byte, err error) {
	var buf []byte
	var over bool
	for {
		chunk, e := r.ReadSlice('\n')

		if e == nil || errors.Is(e, io.EOF) {
			if len(chunk) == 0 && len(buf) == 0 {
				return nil, nil, e // clean EOF between frames
			}
			if !over {
				buf = append(buf, chunk...)
			}
			// The delimiter is framing, not payload, so it must not count
			// toward the cap -- a frame of exactly max bytes is legal.
			trimmed := bytes.TrimRight(buf, "\r\n")
			if over || len(trimmed) > max {
				return nil, capPrefix(buf), errFrameTooLong
			}
			return trimmed, nil, nil
		}

		if errors.Is(e, bufio.ErrBufferFull) {
			// Partial read: no delimiter yet. Once past the cap we stop
			// accumulating and keep only the prefix, so a hostile multi-GiB
			// line is discarded as it streams rather than buffered in full.
			if !over {
				buf = append(buf, chunk...)
				if len(buf) > max {
					over = true
					buf = capPrefix(buf)
				}
			}
			continue
		}

		return nil, nil, e
	}
}

func capPrefix(b []byte) []byte {
	if len(b) > framePrefixBytes {
		return b[:framePrefixBytes]
	}
	return b
}

// peekFrameID makes a best-effort recovery of the JSON-RPC id from the prefix
// of a frame that was never fully parsed, so an oversized request can be
// answered instead of ignored. Returns nil when no id can be recovered, in
// which case the frame is indistinguishable from a notification and silence is
// the correct handling.
func peekFrameID(prefix []byte) RequestID {
	idx := bytes.Index(prefix, []byte(`"id"`))
	if idx < 0 {
		return nil
	}
	rest := prefix[idx+4:]
	colon := bytes.IndexByte(rest, ':')
	if colon < 0 {
		return nil
	}
	rest = bytes.TrimLeft(rest[colon+1:], " \t\r\n")
	if len(rest) == 0 {
		return nil
	}
	// Bound the candidate at the next structural delimiter.
	end := bytes.IndexAny(rest, ",}")
	if end < 0 {
		end = len(rest)
	}
	candidate := bytes.TrimSpace(rest[:end])
	if len(candidate) == 0 || bytes.Equal(candidate, []byte("null")) {
		return nil
	}
	var id RequestID
	if err := json.Unmarshal(candidate, &id); err != nil {
		return nil
	}
	return id
}
