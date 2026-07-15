package llmproxy

// argcheck.go holds the duplicate-JSON-key detector that closes audit
// finding H3 (parser-differential bypass).
//
// The LLM API proxy gates a tool call by projecting fields from the parsed
// arguments object (a Go map[string]interface{}). Go's encoding/json keeps the
// LAST value for a duplicate key. But on the ALLOW path the proxy replays the
// upstream's RAW argument bytes byte-identically, and a downstream tool
// executor whose JSON parser resolves duplicate keys FIRST-wins would then act
// on a different value than the one AgentGuard gated. That gap — the gated view
// differing from what the executor runs — is exactly what this product exists
// to prevent. We therefore reject any tool-call arguments containing a
// duplicate key, fail-closed, before evaluating policy.

import (
	"bytes"
	"encoding/json"
	"errors"
)

// errDuplicateJSONKey is the sentinel returned by the token walker when an
// object with a repeated key is found.
var errDuplicateJSONKey = errors.New("duplicate json key")

// hasDuplicateJSONKeys reports whether the JSON value in raw contains any
// object (at any nesting depth) with a duplicate key.
//
// Empty input returns false. Syntactically invalid JSON also returns false:
// malformed arguments are already handled by the gate's nil-Arguments path,
// and we do not want a truncated-but-harmless body to be treated as a
// duplicate-key attack. Only a successfully parsed object with a genuinely
// repeated key trips the detector.
func hasDuplicateJSONKeys(raw []byte) bool {
	if len(bytes.TrimSpace(raw)) == 0 {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	return errors.Is(walkForDuplicateKeys(dec), errDuplicateJSONKey)
}

// walkForDuplicateKeys consumes exactly one JSON value from dec, recursing into
// objects and arrays. It returns errDuplicateJSONKey if any object has a
// repeated key, or the decoder's error on malformed/truncated input (which the
// caller treats as "not proven duplicate").
func walkForDuplicateKeys(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		// Scalar (string/number/bool/null) — nothing nested to inspect.
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyTok.(string)
			if !ok {
				// Object keys are always strings in valid JSON; bail safe.
				return errors.New("non-string object key")
			}
			if _, dup := seen[key]; dup {
				return errDuplicateJSONKey
			}
			seen[key] = struct{}{}
			if err := walkForDuplicateKeys(dec); err != nil {
				return err
			}
		}
		// Consume the closing '}'.
		if _, err := dec.Token(); err != nil {
			return err
		}
	case '[':
		for dec.More() {
			if err := walkForDuplicateKeys(dec); err != nil {
				return err
			}
		}
		// Consume the closing ']'.
		if _, err := dec.Token(); err != nil {
			return err
		}
	}
	return nil
}
