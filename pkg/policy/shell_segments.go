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
	"unicode"
	"unicode/utf8"
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

// isCompoundShell reports whether cmd needs the segment-by-segment path:
// it has shell syntax, or it runs a command its plain text hides (`sh -c
// rm`, `eval rm -rf /`, `env rm -rf /`; see shell_nested.go), which the
// whole-string match would see as one harmless-looking command.
func isCompoundShell(cmd string) bool {
	if hasShellSyntax(cmd) {
		return true
	}
	// The full check splits the command into words, which allocates; only
	// a command that starts with an assignment, a shell, eval or a wrapper
	// can need it.
	if !startsWithLauncher(cmd) {
		return false
	}
	words, complete := firstWords(cmd, maxLauncherWords)
	if !complete {
		// Too long to inspect on the hot path; the segment path reads it
		// in full, and gives the same verdict for a plain command.
		return true
	}
	return runsOtherCommand(words)
}

// maxLauncherWords bounds the words isCompoundShell splits a command that
// starts with a launcher into.
const maxLauncherWords = 64

// firstWords splits cmd at spaces and tabs into at most n words. complete
// is false when there are more.
func firstWords(cmd string, n int) (words []string, complete bool) {
	i := 0
	for {
		for i < len(cmd) && (cmd[i] == ' ' || cmd[i] == '\t') {
			i++
		}
		if i == len(cmd) {
			return words, true
		}
		if len(words) == n {
			return nil, false
		}
		j := i
		for j < len(cmd) && cmd[j] != ' ' && cmd[j] != '\t' {
			j++
		}
		words = append(words, cmd[i:j])
		i = j
	}
}

// hasShellSyntax reports whether s contains any byte of shellSyntaxChars.
func hasShellSyntax(s string) bool {
	for i := 0; i < len(s); i++ {
		if shellSyntaxByte[s[i]] {
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
	// Scripts are the command strings run as shell code by a command of
	// their own (the script of `sh -c` or `eval`), unquoted, in order. The
	// engine matches whole-string rules against each one, as it does
	// against the full command line.
	Scripts []string
	// Wrapped are the commands run by a wrapper, an assignment or `!`,
	// without that prefix: `rm -rf /` for `timeout 5 rm -rf /`. The engine
	// matches deny and require_approval rules against each one; whether
	// the command may run at all stays with its full segment, so
	// `sudo reboot` still asks for approval under `sudo *` rather than
	// needing an allow rule for `reboot` as well.
	Wrapped []string
	// Unparsed are the command strings in Scripts that couldn't be split
	// (arithmetic, a heredoc, case … esac, nesting too deep). The engine
	// asks a person about them rather than denying the command outright:
	// a script inside `bash -c` is often harmless and only uses syntax the
	// splitter doesn't read.
	Unparsed []string
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
	// script is set while parsing a command string run by another shell
	// (see parseScript).
	script bool
	// nsubst and substBytes count the command substitutions written into
	// the word being read, and their length, so readWord can tell a word
	// that is nothing but one substitution.
	nsubst, substBytes int
	// wordIsSubst reports whether the last word readWord returned was
	// exactly one command substitution, such as "$(ssh-agent -s)".
	wordIsSubst bool
}

// addSegment appends one simple command to the output, within the segment
// limit. In a nested command string, a segment already found is skipped:
// the text of `eval "$(cmd)"` still holds the substitution, which was
// split when the outer word was read, and parsing it again would only
// repeat its commands (and double them at every level of nesting).
func (p *shellParser) addSegment(seg string) error {
	if p.script {
		for _, s := range p.out.Segments {
			if s == seg {
				return nil
			}
		}
	}
	if len(p.out.Segments) >= maxShellSegments {
		return errShellUnparseable
	}
	p.out.Segments = append(p.out.Segments, seg)
	return nil
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
	// firstIsSubst is set when the command's first word is exactly one
	// command substitution.
	firstIsSubst := false
	// heres are the command's here-strings (<<< word), unquoted.
	var heres []string
	flush := func() error {
		seg := joinSegment(words)
		// The command a wrapper, an assignment or `!` runs is matched on
		// its own too: `timeout 5 rm -rf /` as `rm -rf /`.
		var unwrapped []string
		inner, err := unwrapCommand(words, func(cmd []string) {
			if u := joinSegment(cmd); u != seg {
				unwrapped = append(unwrapped, u)
			}
		})
		if err != nil {
			return err
		}
		scripts, readsStdin := innerScripts(inner)
		if readsStdin {
			// `bash <<< 'rm -rf /'`: a shell reading its script from
			// standard input runs the here-string. Fed to any other
			// command, a here-string is data.
			scripts = append(scripts, heres...)
		}
		onlySubst := firstIsSubst && len(words) == 1
		words, firstIsSubst, heres = words[:0], false, heres[:0]
		if seg == "" {
			return nil
		}
		// In a nested command string, a command that is only a
		// substitution (the script of `eval "$(ssh-agent -s)"`) runs
		// whatever the substitution prints. That output can't be known
		// here; the substitution's own commands are already segments. As
		// a segment, the bare "$(ssh-agent -s)" would only fail every
		// allow rule.
		if p.script && onlySubst {
			return nil
		}
		if err := p.addSegment(seg); err != nil {
			return err
		}
		if len(p.out.Wrapped)+len(unwrapped) > maxShellSegments {
			return errShellUnparseable
		}
		p.out.Wrapped = append(p.out.Wrapped, unwrapped...)
		// `bash -c '<script>'` and `eval <script>` run the script as shell
		// code: its commands are segments of their own, as a $( … )
		// substitution's are.
		for _, script := range scripts {
			if err := p.parseScript(script); err != nil {
				return err
			}
		}
		return nil
	}
	// redirect reads one redirection, keeping a here-string's word.
	redirect := func() error {
		here, isHere, err := p.parseRedirect()
		if isHere {
			heres = append(heres, here)
		}
		return err
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
			if err := redirect(); err != nil {
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
			if err := redirect(); err != nil {
				return err
			}
		case isDigit(c) && p.fdRedirectAhead():
			for isDigit(p.s[p.i]) {
				p.i++
			}
			if err := redirect(); err != nil {
				return err
			}
		default:
			w, err := p.readWord()
			if err != nil {
				return err
			}
			if len(words) == 0 {
				firstIsSubst = p.wordIsSubst
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

// parseScript splits a command string another shell will run (the script
// of `sh -c` or `eval`) into segments of its own, counted against the same
// segment and nesting limits. A script that can't be split is recorded in
// Unparsed, and the rest of the command is still read.
func (p *shellParser) parseScript(script string) error {
	if len(p.out.Scripts) >= maxShellSegments {
		return errShellUnparseable
	}
	p.out.Scripts = append(p.out.Scripts, script)
	if p.depth+1 > maxShellDepth {
		p.out.Unparsed = append(p.out.Unparsed, script)
		return nil
	}
	sub := &shellParser{s: script, depth: p.depth + 1, out: p.out, script: true}
	if err := sub.parseList(0); err != nil {
		p.out.Unparsed = append(p.out.Unparsed, script)
	}
	return nil
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

// parseRedirect reads one redirection operator and its target. For a
// here-string (<<< word) it returns the word, unquoted, with isHere set:
// the caller decides whether a shell runs it as a script.
func (p *shellParser) parseRedirect() (here string, isHere bool, err error) {
	write := true
	switch {
	case p.hasPrefix("<<<"):
		// Here-string: the word is input, not a file. Still read it, since it
		// can hold a command substitution.
		p.i += 3
		p.skipBlanks()
		w, err := p.readWord()
		return w, err == nil, err
	case p.hasPrefix("<<"):
		return "", false, errShellUnparseable // heredoc bodies span lines; not supported
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
		return "", false, nil
	}
	p.skipBlanks()
	if p.i >= len(p.s) || isWordEnd(p.s[p.i]) {
		return "", false, errShellUnparseable // redirection without a target
	}
	target, err := p.readWord()
	if err != nil {
		return "", false, err
	}
	if isHarmlessRedirectTarget(target) {
		return "", false, nil
	}
	p.out.Redirects = append(p.out.Redirects, shellRedirect{Target: target, Write: write})
	return "", false, nil
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
	n, size := p.nsubst, p.substBytes
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
			switch p.peek(1) {
			case '\'':
				// $'…' (ANSI-C quoting): decoded as bash does, so
				// $'rm' -rf is checked as rm -rf.
				if err := p.readANSIC(&b); err != nil {
					return "", err
				}
			case '"':
				// $"…" (a translated string) is quoted like "…".
				p.i++
			default:
				if err := p.readDollar(&b); err != nil {
					return "", err
				}
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
	// One substitution and nothing else: "$(cmd)", `cmd`, $(cmd).
	p.wordIsSubst = p.nsubst == n+1 && b.Len() > 0 && b.Len() == p.substBytes-size
	return b.String(), nil
}

// readANSIC decodes a $'…' string whose $ is at p.i, with bash's escapes:
// \n \t \r \a \b \e \E \f \v \\ \' \" \?, \xHH, \NNN (octal), \uHHHH,
// \UHHHHHHHH and \cX. Any other escape keeps its backslash, as in bash. A
// NUL (\0, \x00, \u0000, \c@) ends the string, as in bash: `$'abc\0def'`
// is abc, and `read -d $'\0'` reads up to a NUL byte. An escape that can't
// be decoded safely (a missing digit, a value that isn't a byte or a code
// point) makes the command unparseable.
func (p *shellParser) readANSIC(b *strings.Builder) error {
	p.i += 2 // $'
	var out []byte
	ended := false // a NUL was decoded; the rest is read but dropped
	put := func(c byte) {
		if c == 0 {
			ended = true
		}
		if !ended {
			out = append(out, c)
		}
	}
	for p.i < len(p.s) {
		c := p.s[p.i]
		if c == '\'' {
			p.i++
			b.Write(out)
			return nil
		}
		if c != '\\' {
			put(c)
			p.i++
			continue
		}
		if p.i+1 >= len(p.s) {
			return errShellUnparseable
		}
		e := p.s[p.i+1]
		p.i += 2
		switch e {
		case 'n':
			put('\n')
		case 't':
			put('\t')
		case 'r':
			put('\r')
		case 'a':
			put(0x07)
		case 'b':
			put(0x08)
		case 'e', 'E':
			put(0x1b)
		case 'f':
			put(0x0c)
		case 'v':
			put(0x0b)
		case '\\', '\'', '"', '?':
			put(e)
		case 'x', 'u', 'U':
			digits := 2
			switch e {
			case 'u':
				digits = 4
			case 'U':
				digits = 8
			}
			v, n := p.readDigits(16, digits)
			switch {
			case n == 0:
				return errShellUnparseable
			case e == 'x' || v == 0:
				put(byte(v))
			case v > unicode.MaxRune || (v >= 0xd800 && v <= 0xdfff):
				return errShellUnparseable
			case !ended:
				out = utf8.AppendRune(out, rune(v))
			}
		case '0', '1', '2', '3', '4', '5', '6', '7':
			p.i-- // the first digit is part of the value
			v, _ := p.readDigits(8, 3)
			if v > 0xff {
				return errShellUnparseable
			}
			put(byte(v))
		case 'c':
			// \cX is control-X; \c? is DEL.
			if p.i >= len(p.s) {
				return errShellUnparseable
			}
			x := p.s[p.i]
			p.i++
			if x == '\\' && p.peek(0) == '\\' {
				p.i++
			}
			v := byte(0x7f)
			if x != '?' {
				if x >= 'a' && x <= 'z' {
					x -= 'a' - 'A'
				}
				v = x & 0x1f
			}
			put(v)
		default:
			put('\\')
			put(e)
		}
	}
	return errShellUnparseable // unterminated $'
}

// readDigits reads up to most digits in base (8 or 16) at p.i and returns
// their value and how many it read.
func (p *shellParser) readDigits(base, most int) (v uint32, n int) {
	for n < most && p.i < len(p.s) {
		d := digitValue(p.s[p.i])
		if d < 0 || d >= base {
			break
		}
		v = v*uint32(base) + uint32(d)
		p.i++
		n++
	}
	return v, n
}

func digitValue(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
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
		n, size := p.nsubst, p.substBytes
		if err := p.nested(); err != nil {
			return err
		}
		b.WriteString(p.s[start:p.i])
		p.nsubst, p.substBytes = n+1, size+p.i-start
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
			sub := &shellParser{s: inner.String(), depth: p.depth + 1, out: p.out, script: p.script}
			if err := sub.parseList(0); err != nil {
				return err
			}
			b.WriteString(p.s[start:p.i])
			p.nsubst++
			p.substBytes += p.i - start
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
		// `time -p cmd`: -p is the keyword's option, not the command.
		if words[0] == "time" && len(words) > 1 && words[1] == "-p" {
			words = words[1:]
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
