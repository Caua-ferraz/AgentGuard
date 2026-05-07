// Command stub_server is a tiny MCP-stdio server used by the
// pkg/mcpgw transport and bridge tests. It speaks the minimum
// subset of MCP needed to drive the bridge:
//
//   - initialize → returns a fixed protocolVersion + serverInfo +
//     capabilities map.
//   - tools/list → returns a single fake tool descriptor.
//   - tools/call → echoes the arguments back as text content.
//   - notifications/initialized → no-op.
//
// Behaviour is configurable via flags so tests can probe edge
// conditions:
//
//   --name           name advertised in serverInfo (default "stub")
//   --tool           name of the single tool advertised (default "echo")
//   --proto-version  protocol version returned on initialize (default
//                    matches the test's negotiated version)
//   --crash-after-n  exit non-zero after handling N requests
//                    (default 0 = never crash)
//
// The stub reads newline-delimited JSON from stdin; writes
// newline-delimited JSON to stdout; logs to stderr. Per MCP spec.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"
)

func main() {
	name := flag.String("name", "stub", "serverInfo name")
	tool := flag.String("tool", "echo", "single tool advertised")
	protoVersion := flag.String("proto-version", "2025-11-25", "protocolVersion to return on initialize")
	crashAfterN := flag.Int("crash-after-n", 0, "exit non-zero after handling N requests; 0 = never")
	flag.Parse()

	logf := func(format string, args ...interface{}) {
		fmt.Fprintf(os.Stderr, "[stub] "+format+"\n", args...)
	}
	logf("starting name=%s tool=%s", *name, *tool)

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	out := bufio.NewWriter(os.Stdout)

	var handled atomic.Int64

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var probe struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal(line, &probe); err != nil {
			logf("malformed: %v", err)
			continue
		}

		isNotification := len(probe.ID) == 0 || string(probe.ID) == "null"

		if !isNotification {
			n := handled.Add(1)
			if *crashAfterN > 0 && int(n) > *crashAfterN {
				logf("crash-after-n triggered, exiting non-zero")
				os.Exit(2)
			}
		}

		switch probe.Method {
		case "initialize":
			if isNotification {
				continue
			}
			result := map[string]interface{}{
				"protocolVersion": *protoVersion,
				"serverInfo": map[string]string{
					"name":    *name,
					"version": "0.0.0-stub",
				},
				"capabilities": map[string]interface{}{
					"tools":   map[string]interface{}{"listChanged": false},
					"logging": map[string]interface{}{},
				},
			}
			writeResponse(out, probe.ID, result, nil, logf)

		case "notifications/initialized":
			// no-op
			continue

		case "tools/list":
			if isNotification {
				continue
			}
			result := map[string]interface{}{
				"tools": []map[string]interface{}{
					{
						"name":        *tool,
						"description": "Stub tool: echoes its arguments",
						"inputSchema": map[string]interface{}{
							"type": "object",
							"properties": map[string]interface{}{
								"text": map[string]interface{}{"type": "string"},
							},
						},
					},
				},
			}
			writeResponse(out, probe.ID, result, nil, logf)

		case "tools/call":
			if isNotification {
				continue
			}
			var p struct {
				Name      string                 `json:"name"`
				Arguments map[string]interface{} `json:"arguments"`
			}
			_ = json.Unmarshal(probe.Params, &p)
			text := fmt.Sprintf("called tool %q with args %s", p.Name, mustJSON(p.Arguments))
			result := map[string]interface{}{
				"content": []map[string]interface{}{
					{"type": "text", "text": text},
				},
				"isError": false,
			}
			writeResponse(out, probe.ID, result, nil, logf)

		case "ping":
			if !isNotification {
				writeResponse(out, probe.ID, map[string]interface{}{}, nil, logf)
			}

		default:
			if !isNotification {
				writeResponse(out, probe.ID, nil, &errorObj{
					Code:    -32601,
					Message: fmt.Sprintf("method not found: %s", probe.Method),
				}, logf)
			}
		}
	}

	if err := scanner.Err(); err != nil && !strings.Contains(err.Error(), "closed") {
		logf("scanner error: %v", err)
	}
	logf("exiting cleanly")
}

type errorObj struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func writeResponse(out *bufio.Writer, id json.RawMessage, result interface{}, errObj *errorObj, logf func(string, ...interface{})) {
	resp := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
	}
	if errObj != nil {
		resp["error"] = errObj
	} else {
		resp["result"] = result
	}
	data, err := json.Marshal(resp)
	if err != nil {
		logf("marshal: %v", err)
		return
	}
	if _, err := out.Write(append(data, '\n')); err != nil {
		logf("write: %v", err)
		return
	}
	if err := out.Flush(); err != nil {
		logf("flush: %v", err)
	}
}

func mustJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "<unmarshalable>"
	}
	return string(b)
}

// _ = io.Discard keeps the io import live across refactors; the
// stub server has no interactive use for it but keeping the import
// avoids churn when tests want to silence the stub's own stderr.
var _ = io.Discard
