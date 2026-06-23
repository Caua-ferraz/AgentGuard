package depaudit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// osvFinding is one vulnerability OSV.dev reports for a queried version.
type osvFinding struct {
	ID        string
	Summary   string
	Fixed     string // lowest fixed version across the entry's ranges; "" = no fix yet
	Reference string
}

// osvEcosystem maps our ecosystem tag to OSV's canonical name.
func osvEcosystem(e string) string {
	switch e {
	case "go":
		return "Go"
	case "python":
		return "PyPI"
	case "npm":
		return "npm"
	default:
		return ""
	}
}

// queryOSV asks the live OSV.dev database whether a dependency's *exact* current
// version has any known vulnerability. It returns nil (no error) for the cases
// where a precise query is not meaningful — constraint specs (Python ranges)
// and Go pseudo-versions / pre-releases — so those degrade to registry + (for
// Go) govulncheck coverage rather than producing misleading matches.
//
// OSV's query-by-version does the affected-range matching server-side: every
// vuln it returns already affects the queried version. We then surface whether
// a fixed release exists, because the gate only fails when an upgrade resolves
// the issue.
// The returned queried bool reports whether an authoritative answer was
// actually obtained: it is true only on a successful HTTP 200 from OSV. It is
// false for skipped inputs (constraints, pseudo-versions) AND for any network
// or status error — so the caller never claims "OSV-verified" unless OSV really
// answered, and a network blip degrades to registry-only instead of flaking.
func queryOSV(client *http.Client, d Dependency) (findings []osvFinding, queried bool, err error) {
	eco := osvEcosystem(d.Ecosystem)
	if eco == "" || d.Constraint {
		return nil, false, nil // range spec — not a point query
	}
	v, ok := parseVersion(d.Current)
	if !ok || v.pre != "" {
		return nil, false, nil // pseudo-version / pre-release: not a clean point query
	}

	body, err := json.Marshal(map[string]any{
		"version": strings.TrimPrefix(d.Current, "v"),
		"package": map[string]string{"name": d.Name, "ecosystem": eco},
	})
	if err != nil {
		return nil, false, err
	}
	req, err := http.NewRequest(http.MethodPost, "https://api.osv.dev/v1/query", bytes.NewReader(body))
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("osv.dev returned status %d", resp.StatusCode)
	}
	f, perr := parseOSVResponse(resp.Body)
	if perr != nil {
		return nil, false, perr
	}
	return f, true, nil
}

// parseOSVResponse extracts findings from an OSV /v1/query response body. Split
// out so the JSON handling is unit-testable without the network.
func parseOSVResponse(r io.Reader) ([]osvFinding, error) {
	var payload struct {
		Vulns []struct {
			ID        string `json:"id"`
			Summary   string `json:"summary"`
			Withdrawn string `json:"withdrawn"`
			Affected  []struct {
				Ranges []struct {
					Events []map[string]string `json:"events"`
				} `json:"ranges"`
			} `json:"affected"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"vulns"`
	}
	if err := json.NewDecoder(r).Decode(&payload); err != nil {
		return nil, err
	}

	var out []osvFinding
	for _, v := range payload.Vulns {
		if v.Withdrawn != "" {
			continue // withdrawn advisory — ignore
		}
		fixed := ""
		for _, a := range v.Affected {
			for _, rg := range a.Ranges {
				for _, ev := range rg.Events {
					fx := ev["fixed"]
					if fx == "" {
						continue
					}
					if fixed == "" || lessSemver(fx, fixed) {
						fixed = fx
					}
				}
			}
		}
		ref := "https://osv.dev/vulnerability/" + v.ID
		if len(v.References) > 0 && v.References[0].URL != "" {
			ref = v.References[0].URL
		}
		out = append(out, osvFinding{ID: v.ID, Summary: v.Summary, Fixed: fixed, Reference: ref})
	}
	return out, nil
}

// lessSemver reports whether version a sorts strictly below b; uncomparable
// inputs fall back to a stable string comparison so "lowest fix" stays
// deterministic.
func lessSemver(a, b string) bool {
	av, aok := parseVersion(a)
	bv, bok := parseVersion(b)
	if aok && bok {
		return cmpVersion(av, bv) < 0
	}
	return a < b
}
