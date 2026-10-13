package main

// agent_settings.go: what connecting any coding agent shares — editing the
// agent's JSON settings file by key path, recognising AgentGuard's own hook
// entries, and adding the agent's rules to the policy. Every edit touches
// only what AgentGuard adds, keeps everything else as it was (key order
// included), leaves a backup, and can be undone. claude_settings.go and
// agent_integrations.go use these for each agent.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Caua-ferraz/AgentGuard/pkg/policy"
)

// hookCommand is the command line a settings entry runs: this binary by
// absolute path (hooks may not see the user's PATH), with forward slashes so
// bash, cmd and PowerShell all accept it. --fail-closed goes after the
// agent, so the entry still reads "hook <agent>".
func hookCommand(exe, agent string, failClosed bool) string {
	cmd := `"` + filepath.ToSlash(exe) + `" hook ` + agent
	if failClosed {
		cmd += " --fail-closed"
	}
	return cmd
}

// agentGuardEntry reports whether a hook entry is one AgentGuard wrote for
// agent — its command, or one of its hooks' commands, runs "agentguard…
// hook <agent>" — and whether that command fails closed. It reads both the
// grouped shape ({"matcher", "hooks": [{"command"}]}) and Cursor's flat one
// ({"command"}).
func agentGuardEntry(entry json.RawMessage, agent string) (ours, failClosed bool) {
	var e struct {
		Command string `json:"command"`
		Hooks   []struct {
			Command string `json:"command"`
		} `json:"hooks"`
	}
	if json.Unmarshal(entry, &e) != nil {
		return false, false
	}
	commands := []string{e.Command}
	for _, h := range e.Hooks {
		commands = append(commands, h.Command)
	}
	for _, c := range commands {
		if strings.Contains(c, "agentguard") && strings.Contains(c, "hook "+agent) {
			ours = true
			failClosed = failClosed || strings.Contains(c, "--fail-closed")
		}
	}
	return ours, failClosed
}

// hookList is a list in an agent's settings file that AgentGuard adds a
// hook entry to: its key path ({"hooks", "PreToolUse"}) and the entry.
type hookList struct {
	keys  []string
	entry any
}

// hooksConnected reports whether the settings file at path has
// AgentGuard's entry for agent in any of lists, and whether it fails
// closed. A file that can't be read isn't connected.
func hooksConnected(path, agent string, lists [][]string) (connected, failClosed bool) {
	root, err := readJSONObject(path)
	if err != nil {
		return false, false
	}
	for _, keys := range lists {
		entries, _ := listAt(root, keys)
		for _, e := range entries {
			if ours, fc := agentGuardEntry(e, agent); ours {
				connected, failClosed = true, failClosed || fc
			}
		}
	}
	return connected, failClosed
}

// connectHooks adds (or refreshes) AgentGuard's entry for agent in each
// list. prepare, when set, runs first, for keys the file needs (Cursor's
// "version").
func connectHooks(path, agent string, lists []hookList, prepare func(root *orderedObject)) error {
	return editJSONFile(path, func(root *orderedObject) error {
		if prepare != nil {
			prepare(root)
		}
		for _, l := range lists {
			b, err := json.Marshal(l.entry)
			if err != nil {
				return err
			}
			if err := editListAt(root, l.keys, func(entries []json.RawMessage) []json.RawMessage {
				return append(withoutAgentGuardEntries(entries, agent), b)
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

// disconnectHooks removes AgentGuard's entries for agent; it reports
// whether there were any.
func disconnectHooks(path, agent string, lists [][]string) (bool, error) {
	if connected, _ := hooksConnected(path, agent, lists); !connected {
		return false, nil
	}
	return true, editJSONFile(path, func(root *orderedObject) error {
		for _, keys := range lists {
			if err := editListAt(root, keys, func(entries []json.RawMessage) []json.RawMessage {
				return withoutAgentGuardEntries(entries, agent)
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

func withoutAgentGuardEntries(entries []json.RawMessage, agent string) []json.RawMessage {
	var kept []json.RawMessage
	for _, e := range entries {
		if ours, _ := agentGuardEntry(e, agent); !ours {
			kept = append(kept, e)
		}
	}
	return kept
}

// editJSONFile rewrites the JSON object file at path through edit. A
// missing file starts empty; one that isn't a JSON object (including one
// with comments) is an error and stays as it was. The old file is kept as
// <file>.agentguard-backup.
func editJSONFile(path string, edit func(root *orderedObject) error) error {
	root, err := readJSONObject(path)
	if err != nil {
		return err
	}
	if err := edit(root); err != nil {
		return fmt.Errorf("%s: %w", path, err)
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

// editListAt rewrites the list at keys (e.g. hooks → PreToolUse) through
// edit, creating the objects on the way. An emptied list, and then each
// emptied object above it, is removed rather than left behind.
func editListAt(o *orderedObject, keys []string, edit func([]json.RawMessage) []json.RawMessage) error {
	return editListUnder(o, keys, keys, edit)
}

func editListUnder(o *orderedObject, keys, full []string, edit func([]json.RawMessage) []json.RawMessage) error {
	key := keys[0]
	name := strings.Join(full[:len(full)-len(keys)+1], ".")
	if len(keys) == 1 {
		var entries []json.RawMessage
		if raw, ok := o.vals[key]; ok {
			if err := json.Unmarshal(raw, &entries); err != nil {
				return fmt.Errorf("%q is not a list: %w", name, err)
			}
		}
		entries = edit(entries)
		if len(entries) == 0 {
			o.del(key)
			return nil
		}
		b, err := json.Marshal(entries)
		if err != nil {
			return err
		}
		o.set(key, b)
		return nil
	}
	child := &orderedObject{vals: map[string]json.RawMessage{}}
	if raw, ok := o.vals[key]; ok {
		var err error
		if child, err = parseObject(raw); err != nil {
			return fmt.Errorf("%q is not an object: %w", name, err)
		}
	}
	if err := editListUnder(child, keys[1:], full, edit); err != nil {
		return err
	}
	if len(child.keys) == 0 {
		o.del(key)
	} else {
		o.set(key, child.marshal())
	}
	return nil
}

// listAt returns the list at keys, or nil when any key is missing.
func listAt(o *orderedObject, keys []string) ([]json.RawMessage, error) {
	for i, key := range keys {
		raw, ok := o.vals[key]
		if !ok {
			return nil, nil
		}
		name := strings.Join(keys[:i+1], ".")
		if i == len(keys)-1 {
			var entries []json.RawMessage
			if err := json.Unmarshal(raw, &entries); err != nil {
				return nil, fmt.Errorf("%q is not a list: %w", name, err)
			}
			return entries, nil
		}
		var err error
		if o, err = parseObject(raw); err != nil {
			return nil, fmt.Errorf("%q is not an object: %w", name, err)
		}
	}
	return nil, nil
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

// ── An agent's rules in the policy ──────────────────────────────────────

// policyHasAgentRules reports whether the policy has rules for agentID.
func policyHasAgentRules(path, agentID string) (bool, error) {
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
	_, ok := doc.Agents[agentID]
	return ok, nil
}

// agentsLine matches a top-level `agents:` key with its entries below it.
var agentsLine = regexp.MustCompile(`(?m)^agents:[ \t]*(#.*)?\r?$`)

// addAgentRules adds an agent's policy block (one entry for agentID under
// `agents:`, from configs/) to the policy as text, so the operator's
// comments and layout stay: after an existing top-level `agents:` line, or
// at the end under a new one. The result must load, or the file is put
// back; the old file is kept as <file>.agentguard-backup. A running server
// picks the change up by itself (it reloads the policy). name is the agent
// in the error message.
func addAgentRules(path, agentID, name string, block []byte) error {
	old, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// The block takes the policy's line endings, whatever the checkout
	// gave the embedded copy.
	text := string(old)
	b := strings.ReplaceAll(string(block), "\r\n", "\n")
	nl := "\n"
	if strings.Contains(text, "\r\n") {
		nl = "\r\n"
		b = strings.ReplaceAll(b, "\n", "\r\n")
	}
	var updated string
	if loc := agentsLine.FindStringIndex(text); loc != nil {
		end := loc[1]
		updated = text[:end] + strings.TrimSuffix(b, nl) + text[end:]
	} else {
		updated = strings.TrimRight(text, "\r\n") + nl + nl + "# --- Per-agent rules ---" + nl + "agents:" + b
	}
	if err := os.WriteFile(path+".agentguard-backup", old, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		return err
	}
	if reason := checkAgentRulesAdded(old, []byte(updated), path, agentID); reason != "" {
		_ = os.WriteFile(path, old, 0o644)
		return fmt.Errorf("adding the %s rules would have changed the policy in other ways (%s), so it was left as it was", name, reason)
	}
	return nil
}

// checkAgentRulesAdded compares the policy before and after the text
// insertion: the new one must load, have the agent, and parse to exactly
// the old document otherwise. The last check catches a layout the block
// doesn't fit, e.g. agents indented by four spaces, where an existing
// agent would silently become a field of the new one. Returns "" when all
// is well.
func checkAgentRulesAdded(before, after []byte, path, agentID string) string {
	if _, err := policy.LoadFromFile(path); err != nil {
		return err.Error()
	}
	var was, now map[string]any
	if yaml.Unmarshal(before, &was) != nil || yaml.Unmarshal(after, &now) != nil {
		return "it isn't valid YAML"
	}
	agents, _ := now["agents"].(map[string]any)
	if _, ok := agents[agentID]; !ok {
		return "the rules didn't end up under agents"
	}
	delete(agents, agentID)
	if len(agents) == 0 {
		delete(now, "agents")
	}
	if !reflect.DeepEqual(was, now) {
		return "the agents section is laid out differently from the block"
	}
	return ""
}
