package main

// wiring_test.go guards the single most consequential line in this binary:
// `bridge.PolicyCheck = gate.Check`.
//
// A Bridge with no PolicyCheck wired ALLOWS every tools/call (pkg/mcpgw's
// nil-safe default, pinned in policy_hook_contract_test.go). That default is
// fine for library ergonomics and catastrophic in a shipped firewall: the
// gateway would forward every tool call unevaluated, and the only trace would
// be an `allow:policy_hook_unwired` rule string on decisions nobody is reading.
//
// There is no startup guard that refuses to serve unwired (audit B5), so the
// binary's correctness rests entirely on every code path assigning the hook.
// Until now nothing enforced that — this package had no tests at all.
//
// Deliberately a STRUCTURAL test, not a behavioural one: main() is not
// callable, and extracting it would be a refactor this task has no mandate for.
// It is written to be permissive about everything that does not matter —
// variable names, ordering, formatting, added flags, extra branches — and
// strict about the one thing that does: no path may construct a policy gate
// without wiring it in.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"testing"
)

// gateConstructor is the call that builds the policy gate. If it is ever
// renamed, these tests fail loudly rather than silently passing on a
// no-longer-matching name — a rename is a deliberate act and should update
// this constant with it.
const gateConstructor = "NewHTTPPolicyClient"

// hookField is the Server/Bridge field that must receive the gate.
const hookField = "PolicyCheck"

func parseMain(t *testing.T) (*token.FileSet, *ast.File) {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(thisFile), "main.go")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return fset, f
}

// containsGateConstruction reports whether n contains a call to the gate
// constructor anywhere beneath it.
func containsGateConstruction(n ast.Node) bool {
	found := false
	ast.Inspect(n, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == gateConstructor {
			found = true
			return false
		}
		return true
	})
	return found
}

// countHookAssignments counts assignments whose left-hand side is a selector
// ending in the hook field (e.g. `bridge.PolicyCheck = ...`).
func countHookAssignments(f *ast.File) int {
	n := 0
	ast.Inspect(f, func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, lhs := range assign.Lhs {
			if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == hookField {
				n++
			}
		}
		return true
	})
	return n
}

// TestMain_WiresPolicyCheck is the blunt one: the hook must be assigned at all.
// Catches outright deletion during a refactor.
func TestMain_WiresPolicyCheck(t *testing.T) {
	_, f := parseMain(t)

	if got := countHookAssignments(f); got == 0 {
		t.Fatalf("main.go never assigns .%s — a Bridge with no policy hook ALLOWS every "+
			"tools/call, and nothing at startup refuses to serve in that state (audit B5)", hookField)
	}
	if !containsGateConstruction(f) {
		t.Fatalf("main.go never calls %s; if the gate constructor was renamed, update the "+
			"gateConstructor constant in this test so the wiring invariant keeps being checked",
			gateConstructor)
	}
}

// TestMain_EveryBranchConstructingAGateHasASibling is the invariant that
// actually catches the realistic regression: someone adds a new mode (a third
// policy-source branch, a fast-path shortcut) and wires the gate on the path
// they were thinking about, but not the other.
//
// Rule: if any arm of an if/else constructs a policy gate, EVERY arm must —
// including the final else. An `if` that builds a gate with no `else` at all
// means the else-path runs gate-less.
//
// Permissive by design: it says nothing about which variable holds the gate,
// what order things happen in, or how many branches exist.
func TestMain_EveryBranchConstructingAGateHasASibling(t *testing.T) {
	fset, f := parseMain(t)

	checked := 0
	ast.Inspect(f, func(node ast.Node) bool {
		ifStmt, ok := node.(*ast.IfStmt)
		if !ok {
			return true
		}
		bodyHasGate := containsGateConstruction(ifStmt.Body)
		if !bodyHasGate && (ifStmt.Else == nil || !containsGateConstruction(ifStmt.Else)) {
			return true // this if/else has nothing to do with the gate
		}
		checked++
		pos := fset.Position(ifStmt.Pos())

		if ifStmt.Else == nil {
			t.Errorf("%s: an if-branch constructs the policy gate but has no else — "+
				"the else-path reaches Run() with no gate, so every tool call is allowed unevaluated (B5)", pos)
			return true
		}
		elseHasGate := containsGateConstruction(ifStmt.Else)
		if bodyHasGate != elseHasGate {
			which := "else"
			if !bodyHasGate {
				which = "if"
			}
			t.Errorf("%s: the %s branch constructs no policy gate while its sibling does — "+
				"requests taking that path would be forwarded with no policy evaluation (B5)", pos, which)
		}
		return true
	})

	if checked == 0 {
		t.Fatalf("found no if/else that constructs the policy gate; the wiring shape changed and "+
			"this invariant is no longer being checked — re-derive it against main.go (%s)",
			fset.Position(f.Pos()).Filename)
	}
}

// countHookAssignmentsIn counts hook assignments beneath a single node.
func countHookAssignmentsIn(n ast.Node) int {
	count := 0
	ast.Inspect(n, func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, lhs := range assign.Lhs {
			if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == hookField {
				count++
			}
		}
		return true
	})
	return count
}

// TestMain_HookWiringIsUniformAcrossGateBranches closes the hole that branch
// parity alone leaves open.
//
// Constructing a gate in every branch is not the invariant — WIRING it is. A
// branch can build a gate and simply forget to assign it, which is the precise
// regression this file exists to catch, and construction-parity sails right
// past it.
//
// Two wiring shapes are legitimate and this test permits both:
//
//	per-branch  — each arm assigns the hook itself (this binary)
//	post-branch — arms only build the gate; one assignment follows the if/else
//	              (agentguard-llm-proxy)
//
// What is NOT legitimate is a mixture: if some gate-building arms wire and
// others do not, the un-wired arm reaches Run() with a nil hook and silently
// allows everything. So the rule is all-or-nothing, which stays agnostic about
// which shape the binary uses while making a half-migration fail loudly.
func TestMain_HookWiringIsUniformAcrossGateBranches(t *testing.T) {
	fset, f := parseMain(t)

	type arm struct {
		node ast.Node
		pos  token.Pos
	}
	var arms []arm
	ast.Inspect(f, func(node ast.Node) bool {
		ifStmt, ok := node.(*ast.IfStmt)
		if !ok {
			return true
		}
		if containsGateConstruction(ifStmt.Body) {
			arms = append(arms, arm{ifStmt.Body, ifStmt.Body.Pos()})
		}
		if ifStmt.Else != nil && containsGateConstruction(ifStmt.Else) {
			arms = append(arms, arm{ifStmt.Else, ifStmt.Else.Pos()})
		}
		return true
	})

	if len(arms) == 0 {
		t.Fatal("no branch constructs the policy gate; the wiring shape changed and this " +
			"invariant is no longer being checked — re-derive it against main.go")
	}

	var wired, bare []string
	for _, a := range arms {
		if countHookAssignmentsIn(a.node) > 0 {
			wired = append(wired, fset.Position(a.pos).String())
		} else {
			bare = append(bare, fset.Position(a.pos).String())
		}
	}

	// All-or-nothing. A mixture means at least one path runs unwired.
	if len(wired) > 0 && len(bare) > 0 {
		t.Errorf("policy-hook wiring is inconsistent across gate-constructing branches: "+
			"wired at %v but NOT at %v. The un-wired path reaches Run() with a nil hook, "+
			"which ALLOWS every request unevaluated (audit B5). Either wire every branch, "+
			"or wire once after the if/else — not a mixture.", wired, bare)
	}

	// The post-branch shape is only safe if the assignment actually exists.
	if len(wired) == 0 && countHookAssignments(f) == 0 {
		t.Error("no branch wires the policy hook and there is no assignment after the " +
			"if/else either — nothing ever wires it (audit B5)")
	}
}
