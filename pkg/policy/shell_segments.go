package policy

// Compound shell commands.
//
// A shell rule's pattern is a glob over the whole command string, and a
// single `*` matches every character, including shell operators. Before this
// file, `allow: "ls *"` therefore also allowed `ls /tmp; rm -rf /`,
// `ls $(rm -rf ~)` and `echo x > /etc/passwd`, and a newline-separated second
// command was hidden by stripControl before matching.
//
// For a command that contains any shell syntax, the engine now splits it into
// the simple commands a POSIX shell would run and evaluates each one (see
// Engine.checkCompoundShell). This file is the tokenizer. It is deliberately
// conservative: anything it cannot split with confidence (heredocs, unbalanced
// quotes or parentheses, arithmetic expansion, deep nesting) is reported as
// unparseable, and the engine denies it.

import (
	"errors"
	"strings"
)

// shellSyntaxChars are the bytes that can change how a shell splits or
// expands a command: operators, grouping, quotes, escapes, substitutions,
// redirections and line breaks. A command containing none of them is one
// simple command made of literal words, so it keeps the original
// whole-string matching (the hot path).
const shellSyntaxChars = ";&|<>()$`'\"\\\n\r"

// shellSyntaxByte marks the bytes of shellSyntaxChars. A table lookup per
// byte is about twice as fast as strings.ContainsAny, which rebuilds its
// character set on every call, and isCompoundShell runs on every shell check.
var shellSyntaxByte = func() (t [256]bool) {
	for i := 0; i < len(shellSyntaxChars); i++ {
		t[shellSyntaxChars[i]] = true
	}
	return t
}()

// isCompoundShell reports whether cmd needs the segment-by-segment path.
func isCompoundShell(cmd string) bool {
	for i := 0; i < len(cmd); i++ {
		if shellSyntaxByte[cmd[i]] {
			return true
		}
	}
	return false
}

// errShellUnparseable means the tokenizer could not split the command with
// confidence. The engine turns it into a DENY.
var errShellUnparseable = errors.New("shell command could not be parsed safely")

const (
	// maxShellSegments bounds the number of simple commands in one request.
	maxShellSegments = 64
	// maxShellDepth bounds nesting of $( … ), backticks and ( … ) subshells.
	maxShellDepth = 8
)

// shellRedirect is a file redirection found in a command.
type shellRedirect struct {
	Target string // file path, unquoted as the shell would pass it
	Write  bool   // >, >>, >|, &>, &>>, <> ; false for <
}

// shellParse is the tokenizer's output.
type shellParse struct {
	// Segments are the simple commands, in order, each rebuilt from its
	// unquoted words joined by single spaces. Commands inside $( … ),
	// backticks, <( … ) and ( … ) are separate segments.
	Segments  []string
	Redirects []shellRedirect
}

// parseShell splits cmd into simple commands and file redirections.
func parseShell(cmd string) (*shellParse, error) {
	out := &shellParse{}
	p := &shellParser{s: cmd, out: out}
	if err := p.parseList(0); err != nil {
		return nil, err
	}
	return out, nil
}

type shellParser struct {
	s     string
	i     int
	depth int
	out   *shellParse
}

func (p *shellParser) peek(off int) byte {
	if p.i+off < len(p.s) {
		return p.s[p.i+off]
	}
	return 0
}

func (p *shellParser) hasPrefix(prefix string) bool {
	return strings.HasPrefix(p.s[p.i:], prefix)
}

// isWordEnd reports whether c ends an unquoted word.
func isWordEnd(c byte) bool {
	switch c {
	case ' ', '\t', ';', '&', '|', '<', '>', '(', ')', '\n', '\r':
		return true
	}
	return false
}

// parseList reads simple commands separated by operators until the end of
// input or, when closer is ')', until the matching ')' (consumed).
func (p *shellParser) parseList(closer byte) error {
	var words []string
	flush := func() error {
		seg := joinSegment(words)
		words = words[:0]
		if seg == "" {
			return nil
		}
		if len(p.out.Segments) >= maxShellSegments {
			return errShellUnparseable
		}
		p.out.Segments = append(p.out.Segments, seg)
		return nil
	}
	for p.i < len(p.s) {
		c := p.s[p.i]
		switch {
		case c == ' ' || c == '\t':
			p.i++
		case c == ')':
			if closer != ')' {
				return errShellUnparseable
			}
			p.i++
			return flush()
		case c == '&' && p.peek(1) == '>':
			if err := p.parseRedirect(); err != nil {
				return err
			}
		case c == ';' || c == '&' || c == '|' || c == '\n' || c == '\r':
			// ; ;; & && | || |& and line breaks all end the simple command.
			p.i++
			if n := p.peek(0); (c == ';' && n == ';') || (c == '&' && n == '&') || (c == '|' && (n == '|' || n == '&')) {
				p.i++
			}
			if err := flush(); err != nil {
				return err
			}
		case c == '(':
			// A subshell: its commands are segments of their own.
			if err := flush(); err != nil {
				return err
			}
			p.i++
			if err := p.nested(); err != nil {
				return err
			}
		case (c == '<' || c == '>') && p.peek(1) == '(':
			// Process substitution <( … ) / >( … ): runs a command.
			start := p.i
			p.i += 2
			if err := p.nested(); err != nil {
				return err
			}
			words = append(words, p.s[start:p.i])
		case c == '<' || c == '>':
			if err := p.parseRedirect(); err != nil {
				return err
			}
		case isDigit(c) && p.fdRedirectAhead():
			for isDigit(p.s[p.i]) {
				p.i++
			}
			if err := p.parseRedirect(); err != nil {
				return err
			}
		default:
			w, err := p.readWord()
			if err != nil {
				return err
			}
			words = append(words, w)
		}
	}
	if closer != 0 {
		return errShellUnparseable // missing ')'
	}
	return flush()
}

// nested parses a parenthesised command list whose '(' was just consumed.
func (p *shellParser) nested() error {
	p.depth++
	if p.depth > maxShellDepth {
		return errShellUnparseable
	}
	err := p.parseList(')')
	p.depth--
	return err
}

// fdRedirectAhead reports whether the digits at p.i are a file-descriptor
// prefix such as the 2 in 2>/dev/null.
func (p *shellParser) fdRedirectAhead() bool {
	j := p.i
	for j < len(p.s) && isDigit(p.s[j]) {
		j++
	}
	return j < len(p.s) && (p.s[j] == '<' || p.s[j] == '>')
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// parseRedirect reads one redirection operator and its target.
func (p *shellParser) parseRedirect() error {
	write := true
	switch {
	case p.hasPrefix("<<<"):
		// Here-string: the word is input, not a file. Still read it, since it
		// can hold a command substitution.
		p.i += 3
		p.skipBlanks()
		_, err := p.readWord()
		return err
	case p.hasPrefix("<<"):
		return errShellUnparseable // heredoc bodies span lines; not supported
	case p.hasPrefix("&>>"):
		p.i += 3
	case p.hasPrefix("&>"), p.hasPrefix(">>"), p.hasPrefix(">|"), p.hasPrefix("<>"):
		p.i += 2
	case p.hasPrefix(">"):
		p.i++
	case p.hasPrefix("<"):
		p.i++
		write = false
	}
	// File-descriptor duplication (>&2, <&0, >&-) opens no file.
	if p.peek(0) == '&' {
		p.i++
		for p.i < len(p.s) && (isDigit(p.s[p.i]) || p.s[p.i] == '-') {
			p.i++
		}
		return nil
	}
	p.skipBlanks()
	if p.i >= len(p.s) || isWordEnd(p.s[p.i]) {
		return errShellUnparseable // redirection without a target
	}
	target, err := p.readWord()
	if err != nil {
		return err
	}
	if isHarmlessRedirectTarget(target) {
		return nil
	}
	p.out.Redirects = append(p.out.Redirects, shellRedirect{Target: target, Write: write})
	return nil
}

// isHarmlessRedirectTarget lists targets that are not files an agent could
// damage: the null device and the process's own standard streams.
func isHarmlessRedirectTarget(t string) bool {
	switch t {
	case "/dev/null", "/dev/stdout", "/dev/stderr", "/dev/stdin", "/dev/tty":
		return true
	}
	return strings.HasPrefix(t, "/dev/fd/")
}

func (p *shellParser) skipBlanks() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t') {
		p.i++
	}
}

// readWord reads one word and returns it unquoted the way the shell would
// pass it to the command. Command substitutions inside it are parsed as
// segments of their own and kept in the word as their original text.
func (p *shellParser) readWord() (string, error) {
	var b strings.Builder
	for p.i < len(p.s) {
		c := p.s[p.i]
		if isWordEnd(c) {
			break
		}
		switch c {
		case '\'':
			end := strings.IndexByte(p.s[p.i+1:], '\'')
			if end < 0 {
				return "", errShellUnparseable
			}
			b.WriteString(p.s[p.i+1 : p.i+1+end])
			p.i += end + 2
		case '"':
			if err := p.readDoubleQuoted(&b); err != nil {
				return "", err
			}
		case '\\':
			if p.i+1 >= len(p.s) {
				p.i++ // a trailing backslash escapes nothing
				continue
			}
			next := p.s[p.i+1]
			p.i += 2
			if next == '\n' {
				continue // line continuation
			}
			b.WriteByte(next)
		case '$':
			if err := p.readDollar(&b); err != nil {
				return "", err
			}
		case '`':
			if err := p.readBackticks(&b); err != nil {
				return "", err
			}
		default:
			b.WriteByte(c)
			p.i++
		}
	}
	return b.String(), nil
}

// readDoubleQuoted reads a "…" string whose opening quote is at p.i.
func (p *shellParser) readDoubleQuoted(b *strings.Builder) error {
	p.i++ // opening quote
	for p.i < len(p.s) {
		c := p.s[p.i]
		switch c {
		case '"':
			p.i++
			return nil
		case '\\':
			if p.i+1 >= len(p.s) {
				return errShellUnparseable
			}
			next := p.s[p.i+1]
			p.i += 2
			switch next {
			case '$', '`', '"', '\\':
				b.WriteByte(next)
			case '\n':
				// line continuation
			default:
				b.WriteByte('\\')
				b.WriteByte(next)
			}
		case '$':
			if err := p.readDollar(b); err != nil {
				return err
			}
		case '`':
			if err := p.readBackticks(b); err != nil {
				return err
			}
		default:
			b.WriteByte(c)
			p.i++
		}
	}
	return errShellUnparseable // unterminated "
}

// readDollar handles $( … ), $(( … )), ${ … } and plain $ at p.i.
func (p *shellParser) readDollar(b *strings.Builder) error {
	switch {
	case p.hasPrefix("$(("):
		// Arithmetic expansion can nest command substitutions; not supported.
		return errShellUnparseable
	case p.hasPrefix("$("):
		start := p.i
		p.i += 2
		if err := p.nested(); err != nil {
			return err
		}
		b.WriteString(p.s[start:p.i])
		return nil
	case p.hasPrefix("${"):
		end := strings.IndexByte(p.s[p.i:], '}')
		if end < 0 {
			return errShellUnparseable
		}
		body := p.s[p.i : p.i+end+1]
		// ${x:-$(cmd)} and friends run commands; keep it simple and refuse.
		if strings.ContainsAny(body[2:], "$`{") {
			return errShellUnparseable
		}
		b.WriteString(body)
		p.i += end + 1
		return nil
	default:
		b.WriteByte('$')
		p.i++
		return nil
	}
}

// readBackticks parses a `…` command substitution at p.i.
func (p *shellParser) readBackticks(b *strings.Builder) error {
	start := p.i
	var inner strings.Builder
	p.i++
	for p.i < len(p.s) {
		c := p.s[p.i]
		if c == '\\' && p.i+1 < len(p.s) {
			next := p.s[p.i+1]
			if next == '`' || next == '\\' || next == '$' {
				inner.WriteByte(next)
			} else {
				inner.WriteByte('\\')
				inner.WriteByte(next)
			}
			p.i += 2
			continue
		}
		if c == '`' {
			p.i++
			if p.depth+1 > maxShellDepth {
				return errShellUnparseable
			}
			sub := &shellParser{s: inner.String(), depth: p.depth + 1, out: p.out}
			if err := sub.parseList(0); err != nil {
				return err
			}
			b.WriteString(p.s[start:p.i])
			return nil
		}
		inner.WriteByte(c)
		p.i++
	}
	return errShellUnparseable // unterminated `
}

// shellLeadingKeywords are reserved words that can open a simple command
// without being the command itself.
var shellLeadingKeywords = map[string]struct{}{
	"!": {}, "if": {}, "then": {}, "else": {}, "elif": {}, "do": {},
	"while": {}, "until": {}, "time": {}, "{": {},
}

// joinSegment rebuilds a simple command from its words, dropping grouping
// braces and leading reserved words, so `if true; then rm -rf /; fi` is
// evaluated as `true` and `rm -rf /`.
func joinSegment(words []string) string {
	for len(words) > 0 {
		if _, ok := shellLeadingKeywords[words[0]]; !ok {
			break
		}
		words = words[1:]
	}
	for len(words) > 0 && words[len(words)-1] == "}" {
		words = words[:len(words)-1]
	}
	if len(words) == 1 {
		switch words[0] {
		case "fi", "done", "esac", "}":
			return ""
		}
	}
	return strings.Join(words, " ")
}
