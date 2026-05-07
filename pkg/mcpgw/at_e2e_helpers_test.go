package mcpgw_test

// AT (Test Wrangler) — helpers shared across the external-package
// E2E tests in pkg/mcpgw. These tests must run in package
// `mcpgw_test` so they can `import "github.com/.../pkg/proxy"` without
// creating an internal-package import cycle. That means we cannot
// reuse the unexported `stubFactory` and `bridgeHarness` from the
// internal-package tests; we re-implement the minimum needed here.
//
// What's here:
//   - e2eStubFactory: builds a CommandFactory that runs the
//     pre-built testdata/stub_server binary with the supplied flags.
//   - e2eHarness: drives Bridge.Run via in-memory pipes and
//     marshals/unmarshals JSON-RPC frames.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/Caua-ferraz/AgentGuard/pkg/mcpgw"
)

var (
	e2eStubBinOnce sync.Once
	e2eStubBinPath string
	e2eStubBinErr  error
)

// e2eBuildStubBinary builds the testdata/stub_server binary once per
// test process. Uses runtime.Caller to locate the package's testdata
// directory regardless of where the test is invoked from.
func e2eBuildStubBinary(t *testing.T) string {
	t.Helper()
	e2eStubBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "mcpgw-stub-e2e-*")
		if err != nil {
			e2eStubBinErr = err
			return
		}
		// Find the package's testdata dir using runtime.Caller (the
		// caller's file is in pkg/mcpgw/, so testdata/stub_server is a
		// relative subpath of its dir).
		_, thisFile, _, ok := runtime.Caller(0)
		if !ok {
			e2eStubBinErr = fmt.Errorf("runtime.Caller failed")
			return
		}
		pkgDir := filepath.Dir(thisFile)
		stubSrc := filepath.Join(pkgDir, "testdata", "stub_server")

		out := filepath.Join(dir, "stub_server")
		if runtime.GOOS == "windows" {
			out += ".exe"
		}
		cmd := exec.Command("go", "build", "-o", out, ".")
		cmd.Dir = stubSrc
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			e2eStubBinErr = fmt.Errorf("build stub server: %w", err)
			return
		}
		e2eStubBinPath = out
	})
	if e2eStubBinErr != nil {
		t.Fatalf("e2e stub binary unavailable: %v", e2eStubBinErr)
	}
	return e2eStubBinPath
}

// stubFactoryForE2E returns a mcpgw.CommandFactory that runs the
// pre-built stub binary with the supplied flags.
func stubFactoryForE2E(t *testing.T, stubFlags ...string) mcpgw.CommandFactory {
	bin := e2eBuildStubBinary(t)
	return func(ctx context.Context, _ []string) (*exec.Cmd, error) {
		args := append([]string{}, stubFlags...)
		return exec.CommandContext(ctx, bin, args...), nil
	}
}

// e2eHarness drives a mcpgw.Bridge through in-memory pipes.
type e2eHarness struct {
	t       *testing.T
	bridge  *mcpgw.Bridge
	stdinW  *io.PipeWriter
	stdoutR *io.PipeReader
	cancel  context.CancelFunc
	done    chan error
}

// newE2EHarness spawns Bridge.Run on a background goroutine and
// returns a harness with stdin writer / stdout reader.
func newE2EHarness(t *testing.T, b *mcpgw.Bridge) *e2eHarness {
	t.Helper()
	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- b.Run(ctx, stdinR, stdoutW, io.Discard)
		_ = stdoutW.Close()
	}()

	t.Cleanup(func() {
		cancel()
		_ = stdinW.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Logf("bridge.Run did not exit cleanly")
		}
	})

	return &e2eHarness{
		t:       t,
		bridge:  b,
		stdinW:  stdinW,
		stdoutR: stdoutR,
		cancel:  cancel,
		done:    done,
	}
}

func (h *e2eHarness) send(v interface{}) {
	h.t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		h.t.Fatalf("marshal frame: %v", err)
	}
	data = append(data, '\n')
	if _, err := h.stdinW.Write(data); err != nil {
		h.t.Fatalf("write stdin: %v", err)
	}
}

// readResponse reads one newline-terminated JSON-RPC response from
// the bridge's stdout, returning the unmarshalled Response. Times
// out at 10 seconds (these E2E tests touch a real subprocess + a
// real httptest.Server).
func (h *e2eHarness) readResponse() *mcpgw.Response {
	h.t.Helper()
	type result struct {
		resp *mcpgw.Response
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		var buf bytes.Buffer
		one := make([]byte, 1)
		for {
			n, err := h.stdoutR.Read(one)
			if n > 0 {
				if one[0] == '\n' {
					var resp mcpgw.Response
					if uerr := json.Unmarshal(buf.Bytes(), &resp); uerr != nil {
						ch <- result{nil, fmt.Errorf("decode response %q: %w", buf.String(), uerr)}
						return
					}
					ch <- result{&resp, nil}
					return
				}
				buf.Write(one[:n])
				continue
			}
			if err != nil {
				ch <- result{nil, err}
				return
			}
		}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			h.t.Fatalf("read response: %v", r.err)
		}
		return r.resp
	case <-time.After(10 * time.Second):
		h.t.Fatalf("timed out waiting for response")
		return nil
	}
}
