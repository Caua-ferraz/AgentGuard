package main

// claude_settings.go: connecting Claude Code — AgentGuard's PreToolUse
// entry in Claude Code's user settings (~/.claude/settings.json), and the
// Claude Code rules in the policy. Both edits touch only what AgentGuard
// adds, keep everything else as it was (key order included), leave a
// backup, and can be undone.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Caua-ferraz/AgentGuard/configs"
	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// claudeConfigDir is Claude Code's user folder: $CLAUDE_CONFIG_DIR, else
// ~/.claude (on Windows too).
func claudeConfigDir() string {
	if d := os.Getenv("CLAUDE_CONFIG_DIR"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".claude")
}

func claudeSettingsPath() string {
	if d := claudeConfigDir(); d != "" {
		return filepath.Join(d, "settings.json")
	}
	return ""
}

// claudeCodeDetected reports whether Claude Code looks installed: its user
// folder exists or `claude` is on PATH.
func claudeCodeDetected() bool {
	if d := claudeConfigDir(); d != "" {
		if info, err := os.Stat(d); err == nil && info.IsDir() {
			return true
		}
	}
	_, err := exec.LookPath("claude")
	return err == nil
}

// claudeHookCommand is the command line the settings entry runs: this
// binary by absolute path (hooks may not see the user's PATH), with
// forward slashes so bash, cmd and PowerShell all accept it.
func claudeHookCommand(exe string) string {
	return `"` + filepath.ToSlash(exe) + `" hook claude-code`
}

// isAgentGuardHook reports whether a PreToolUse entry is the one AgentGuard
// wrote: any of its commands runs "agentguard… hook claude-code".
func isAgentGuardHook(entry json.RawMessage) bool {
	var e struct {
		Hooks []struct {
			Command string `json:"command"`
		} `json:"hooks"`
	}
	if json.Unmarshal(entry, &e) != nil {
		return false
	}
	for _, h := range e.Hooks {
		if strings.Contains(h.Command, "agentguard") && strings.Contains(h.Command, "hook claude-code") {
			return true
		}
	}
	return false
}

// claudeConnected reports whether the settings file has AgentGuard's entry.
func claudeConnected(path string) bool {
	root, err := readJSONObject(path)
	if err != nil {
		return false
	}
	entries, _ := preToolUseEntries(root)
	for _, e := range entries {
		if isAgentGuardHook(e) {
			return true
		}
	}
	return false
}

// connectClaudeCode adds (or refreshes) AgentGuard's PreToolUse entry.
func connectClaudeCode(path, exe string) error {
	entry, err := json.Marshal(struct {
		Matcher string `json:"matcher"`
		Hooks   []any  `json:"hooks"`
	}{
		Matcher: claudeHookMatcher,
		Hooks: []any{struct {
			Type    string `json:"type"`
			Command string `json:"command"`
			Timeout int    `json:"timeout"`
		}{"command", claudeHookCommand(exe), claudeHookTimeout}},
	})
	if err != nil {
		return err
	}
	return editPreToolUse(path, func(entries []json.RawMessage) []json.RawMessage {
		return append(withoutAgentGuard(entries), entry)
	})
}

// disconnectClaudeCode removes AgentGuard's entry; it reports whether there
// was one.
func disconnectClaudeCode(path string) (bool, error) {
	if !claudeConnected(path) {
		return false, nil
	}
	return true, editPreToolUse(path, withoutAgentGuard)
}

func withoutAgentGuard(entries []json.RawMessage) []json.RawMessage {
	var kept []json.RawMessage
	for _, e := range entries {
		if !isAgentGuardHook(e) {
			kept = append(kept, e)
		}
	}
	return kept
}

// editPreToolUse rewrites hooks.PreToolUse through edit, keeping every
// other key where it was. An empty PreToolUse (and then an empty hooks)
// is removed rather than left behind. The old file is kept as
// <file>.agentguard-backup.
func editPreToolUse(path string, edit func([]json.RawMessage) []json.RawMessage) error {
	root, err := readJSONObject(path)
	if err != nil {
		return err
	}
	hooks := &orderedObject{vals: map[string]json.RawMessage{}}
	if raw, ok := root.vals["hooks"]; ok {
		if hooks, err = parseObject(raw); err != nil {
			return fmt.Errorf("%s: \"hooks\" is not an object: %w", path, err)
		}
	}
	entries, err := preToolUseEntries(root)
	if err != nil {
		return err
	}
	entries = edit(entries)
	if len(entries) == 0 {
		hooks.del("PreToolUse")
	} else {
		b, err := json.Marshal(entries)
		if err != nil {
			return err
		}
		hooks.set("PreToolUse", b)
	}
	if len(hooks.keys) == 0 {
		root.del("hooks")
	} else {
		root.set("hooks", hooks.marshal())
	}

	if old, err := os.ReadFile(path); err == nil {
		if err := os.WriteFile(path+".agentguard-backup", old, 0o600); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	var out bytes.Buffer
	if err := json.Indent(&out, root.marshal(), "", "  "); err != nil {
		return err
	}
	out.WriteByte('\n')
	return os.WriteFile(path, out.Bytes(), 0o600)
}

func preToolUseEntries(root *orderedObject) ([]json.RawMessage, error) {
	raw, ok := root.vals["hooks"]
	if !ok {
		return nil, nil
	}
	hooks, err := parseObject(raw)
	if err != nil {
		return nil, err
	}
	var entries []json.RawMessage
	if list, ok := hooks.vals["PreToolUse"]; ok {
		if err := json.Unmarshal(list, &entries); err != nil {
			return nil, fmt.Errorf("\"hooks.PreToolUse\" is not a list: %w", err)
		}
	}
	return entries, nil
}

// readJSONObject reads a JSON object file; a missing or empty file is an
// empty object. A file that isn't a JSON object is an error: setup never
// overwrites what it can't read.
func readJSONObject(path string) (*orderedObject, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) || (err == nil && len(bytes.TrimSpace(b)) == 0) {
		return &orderedObject{vals: map[string]json.RawMessage{}}, nil
	}
	if err != nil {
		return nil, err
	}
	o, err := parseObject(b)
	if err != nil {
		return nil, fmt.Errorf("%s isn't valid JSON (%v); fix it, then try again", path, err)
	}
	return o, nil
}

// orderedObject is a JSON object that remembers its key order, so a file
// written back reads like the one that was read.
type orderedObject struct {
	keys []string
	vals map[string]json.RawMessage
}

func parseObject(b []byte) (*orderedObject, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	o := &orderedObject{vals: map[string]json.RawMessage{}}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := tok.(string)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		o.set(key, raw)
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("extra data after the object")
	}
	return o, nil
}

func (o *orderedObject) set(key string, v json.RawMessage) {
	if _, ok := o.vals[key]; !ok {
		o.keys = append(o.keys, key)
	}
	o.vals[key] = v
}

func (o *orderedObject) del(key string) {
	if _, ok := o.vals[key]; !ok {
		return
	}
	delete(o.vals, key)
	for i, k := range o.keys {
		if k == key {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			break
		}
	}
}

func (o *orderedObject) marshal() []byte {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		b.Write(kb)
		b.WriteByte(':')
		b.Write(o.vals[k])
	}
	b.WriteByte('}')
	return b.Bytes()
}

// ── The Claude Code rules in the policy ─────────────────────────────────

// policyHasClaudeRules reports whether the policy has rules for agent
// "claude-code".
func policyHasClaudeRules(path string) (bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	var doc struct {
		Agents map[string]any `yaml:"agents"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return false, err
	}
	_, ok := doc.Agents[claudeAgentID]
	return ok, nil
}

// agentsLine matches a top-level `agents:` key with its entries below it.
var agentsLine = regexp.MustCompile(`(?m)^agents:[ \t]*(#.*)?\r?$`)

// addClaudeRules adds the Claude Code block to the policy as text, so the
// operator's comments and layout stay: after an existing top-level
// `agents:` line, or at the end under a new one. The result must load, or
// the file is put back; the old file is kept as <file>.agentguard-backup.
// A running server picks the change up by itself (it reloads the policy).
func addClaudeRules(path string) error {
	old, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// The block takes the policy's line endings, whatever the checkout
	// gave the embedded copy.
	block := strings.ReplaceAll(string(configs.ClaudeCode), "\r\n", "\n")
	text := string(old)
	nl := "\n"
	if strings.Contains(text, "\r\n") {
		nl = "\r\n"
		block = strings.ReplaceAll(block, "\n", "\r\n")
	}
	var updated string
	if loc := agentsLine.FindStringIndex(text); loc != nil {
		end := loc[1]
		updated = text[:end] + strings.TrimSuffix(block, nl) + text[end:]
	} else {
		updated = strings.TrimRight(text, "\r\n") + nl + nl + "# --- Per-agent rules ---" + nl + "agents:" + block
	}
	if err := os.WriteFile(path+".agentguard-backup", old, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		return err
	}
	if reason := checkClaudeRulesAdded(old, []byte(updated), path); reason != "" {
		_ = os.WriteFile(path, old, 0o644)
		return fmt.Errorf("adding the Claude Code rules would have changed the policy in other ways (%s), so it was left as it was", reason)
	}
	return nil
}

// checkClaudeRulesAdded compares the policy before and after the text
// insertion: the new one must load, have the claude-code agent, and parse
// to exactly the old document otherwise. The last check catches a layout
// the block doesn't fit, e.g. agents indented by four spaces, where an
// existing agent would silently become a field of claude-code. Returns ""
// when all is well.
func checkClaudeRulesAdded(before, after []byte, path string) string {
	if _, err := policy.LoadFromFile(path); err != nil {
		return err.Error()
	}
	var was, now map[string]any
	if yaml.Unmarshal(before, &was) != nil || yaml.Unmarshal(after, &now) != nil {
		return "it isn't valid YAML"
	}
	agents, _ := now["agents"].(map[string]any)
	if _, ok := agents[claudeAgentID]; !ok {
		return "the rules didn't end up under agents"
	}
	delete(agents, claudeAgentID)
	if len(agents) == 0 {
		delete(now, "agents")
	}
	if !reflect.DeepEqual(was, now) {
		return "the agents section is laid out differently from the block"
	}
	return ""
}
