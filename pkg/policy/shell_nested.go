package policy

// Commands that run other commands.
//
// A simple command can run a second command that its own text only names
// as arguments: a wrapper runs the command that follows its options
// (`env rm -rf /`, `timeout 5 rm -rf /`), a shell runs the script of its -c
// option (`bash -c 'rm -rf /'`) and eval runs its arguments as shell code.
// Matched as one string, each of these reads as a harmless `env`, `timeout`,
// `bash` or `eval` command. The tokenizer (shell_segments.go) uses this file
// to check the inner command as a segment of its own, next to the outer
// one.

import "strings"

// shellNames are the shells whose -c option runs its argument as a script,
// and which read a script from standard input without one. A versioned
// name (bash5, ksh93) is looked up without its version.
var shellNames = map[string]struct{}{
	"sh": {}, "bash": {}, "rbash": {}, "zsh": {}, "dash": {}, "ksh": {},
	"rksh": {}, "mksh": {}, "pdksh": {}, "oksh": {}, "ash": {}, "yash": {},
	"posh": {}, "fish": {}, "csh": {}, "tcsh": {},
}

// wrapperSpec says how a command wrapper reads its own arguments before
// the command it runs.
type wrapperSpec struct {
	// valueShort are the short options (letters) that take a value: the
	// next word, or the rest of the word when more follows the letter
	// (-u root, -uroot, -Eu root).
	valueShort string
	// valueLong are the whole-word options that take the next word as a
	// value (--user root, arch's -arch arm64). --opt=value is one word.
	valueLong []string
	// stopShort and stopLong are options after which the wrapper runs no
	// command (command -v, sudo -l, chrt -p): what follows is not a
	// command to check.
	stopShort string
	stopLong  []string
	// operands is the number of words between the options and the command
	// (timeout's DURATION, flock's FILE, taskset's MASK, chrt's PRIORITY).
	operands int
	// wholeWords means options are never clusters of letters (arch -arm64).
	wholeWords bool
	// splitShort and splitLong take a string that the wrapper splits into
	// more arguments (env -S 'cmd args').
	splitShort string
	splitLong  string
	// shellCommand is the option, after the operands, that hands the next
	// word to `sh -c` (flock FILE -c 'cmd').
	shellCommand []string
}

// commandWrappers run the command that follows their own options and
// operands, so `env bash -c …` and `sudo sh -c …` hand a script to a shell
// just as `bash -c …` does, and `timeout 5 rm -rf /` runs `rm -rf /`.
var commandWrappers = map[string]*wrapperSpec{
	"builtin":    {},
	"busybox":    {},
	"caffeinate": {valueShort: "tw"},
	"chrt": {
		valueShort: "TPD", valueLong: []string{"--sched-runtime", "--sched-period", "--sched-deadline"},
		stopShort: "pm", stopLong: []string{"--pid", "--max"}, operands: 1,
	},
	"command": {stopShort: "vV"},
	"doas":    {valueShort: "u", stopShort: "CL"},
	"env": {
		valueShort: "uCP", valueLong: []string{"--unset", "--chdir"},
		splitShort: "S", splitLong: "--split-string",
	},
	"exec": {valueShort: "a"},
	"flock": {
		valueShort: "wE", valueLong: []string{"--wait", "--timeout", "--conflict-exit-code"},
		operands: 1, shellCommand: []string{"-c", "--command"},
	},
	"ionice": {
		valueShort: "cn", valueLong: []string{"--class", "--classdata"},
		stopShort: "pPu", stopLong: []string{"--pid", "--pgid", "--uid"},
	},
	"arch":   {wholeWords: true, valueLong: []string{"-arch", "-d", "-e"}},
	"nice":   {valueShort: "n", valueLong: []string{"--adjustment"}},
	"nohup":  {},
	"setsid": {},
	"stdbuf": {valueShort: "ioe", valueLong: []string{"--input", "--output", "--error"}},
	"sudo": {
		valueShort: "ugCDhprtUTR",
		valueLong: []string{"--user", "--group", "--close-from", "--chdir", "--host", "--prompt",
			"--role", "--type", "--other-user", "--command-timeout", "--chroot"},
		stopShort: "lvKVe", stopLong: []string{"--list", "--validate", "--remove-timestamp", "--version", "--edit", "--help"},
	},
	"taskset": {stopShort: "p", stopLong: []string{"--pid"}, operands: 1},
	"time":    {valueShort: "fo", valueLong: []string{"--format", "--output"}},
	"timeout": {valueShort: "sk", valueLong: []string{"--signal", "--kill-after"}, operands: 1},
	"unshare": {
		valueShort: "RwSGl",
		valueLong: []string{"--root", "--wd", "--setuid", "--setgid", "--propagation", "--setgroups",
			"--map-user", "--map-group", "--map-users", "--map-groups", "--monotonic", "--boottime", "--load-interp"},
	},
	"xargs": {
		valueShort: "adEILnPs",
		valueLong: []string{"--arg-file", "--delimiter", "--eof", "--replace", "--max-lines",
			"--max-args", "--max-procs", "--max-chars", "--process-slot-var"},
	},
}

// skip drops the wrapper's own options and operands from args, the words
// after the wrapper's name, and returns the command it runs. ok is false
// when the wrapper runs no command (an option such as command -v, or too
// few words).
func (s *wrapperSpec) skip(args []string) (rest []string, ok bool, err error) {
	for len(args) > 0 {
		a := args[0]
		if len(a) < 2 || a[0] != '-' {
			break
		}
		args = args[1:]
		if a == "--" {
			break
		}
		name, value, hasValue := a, "", false
		if strings.HasPrefix(a, "--") {
			if eq := strings.IndexByte(a, '='); eq > 0 {
				name, value, hasValue = a[:eq], a[eq+1:], true
			}
		}
		switch {
		case containsWord(s.stopLong, name):
			return nil, false, nil
		case s.splitLong != "" && name == s.splitLong:
			if !hasValue {
				if len(args) == 0 {
					return nil, false, nil
				}
				value, args = args[0], args[1:]
			}
			if args, err = splitInto(value, args); err != nil {
				return nil, false, err
			}
		case containsWord(s.valueLong, name):
			if !hasValue {
				if len(args) == 0 {
					return nil, false, nil
				}
				args = args[1:]
			}
		case strings.HasPrefix(a, "--") || s.wholeWords:
			// A flag, or an option with its value in the same word.
		default:
			// A cluster of short options, such as -Eu root or -n10.
			for k := 1; k < len(a); k++ {
				c := a[k]
				if strings.IndexByte(s.stopShort, c) >= 0 {
					return nil, false, nil
				}
				split := strings.IndexByte(s.splitShort, c) >= 0
				if !split && strings.IndexByte(s.valueShort, c) < 0 {
					continue
				}
				value := a[k+1:]
				if value == "" {
					if len(args) == 0 {
						return nil, false, nil
					}
					value, args = args[0], args[1:]
				}
				if split {
					if args, err = splitInto(value, args); err != nil {
						return nil, false, err
					}
				}
				break
			}
		}
	}
	if len(args) < s.operands {
		return nil, false, nil
	}
	args = args[s.operands:]
	if len(args) > 1 && containsWord(s.shellCommand, args[0]) {
		// flock FILE -c 'cmd' runs the command string with sh -c.
		return append([]string{"sh", "-c"}, args[1:]...), true, nil
	}
	return args, len(args) > 0, nil
}

// splitInto splits value into words the way env -S does, for the common
// quoting, and returns them followed by rest.
func splitInto(value string, rest []string) ([]string, error) {
	words, err := splitWords(value)
	if err != nil {
		return nil, err
	}
	return append(words, rest...), nil
}

// splitWords splits s at blanks, honouring single quotes, double quotes and
// backslash escapes. An unterminated quote is unparseable.
func splitWords(s string) ([]string, error) {
	var words []string
	var b strings.Builder
	inWord := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n':
			if inWord {
				words = append(words, b.String())
				b.Reset()
				inWord = false
			}
			continue
		case c == '\'':
			end := strings.IndexByte(s[i+1:], '\'')
			if end < 0 {
				return nil, errShellUnparseable
			}
			b.WriteString(s[i+1 : i+1+end])
			i += end + 1
		case c == '"':
			j := i + 1
			for ; j < len(s) && s[j] != '"'; j++ {
				if s[j] == '\\' && j+1 < len(s) {
					j++
				}
				b.WriteByte(s[j])
			}
			if j >= len(s) {
				return nil, errShellUnparseable
			}
			i = j
		case c == '\\' && i+1 < len(s):
			i++
			b.WriteByte(s[i])
		default:
			b.WriteByte(c)
		}
		inWord = true
	}
	if inWord {
		words = append(words, b.String())
	}
	return words, nil
}

func containsWord(list []string, w string) bool {
	for _, x := range list {
		if x == w {
			return true
		}
	}
	return false
}

// unwrapCommand drops what comes before the command a simple command
// really runs: leading reserved words (`!`), NAME=value assignments and
// command wrappers with their options and operands. It calls inner for
// each command found behind such a prefix, outermost first: for
// `env sudo ls`, `sudo ls` and then `ls`, since sudo has rules of its own.
// It returns the innermost command. A wrapper that runs no command
// (`command -v bash`, `sudo -l`) is itself the command.
func unwrapCommand(words []string, inner func([]string)) ([]string, error) {
	stripped := false
	for len(words) > 0 {
		spec, isWrapper := commandWrappers[commandName(words[0])]
		if !isWrapper {
			if _, ok := shellLeadingKeywords[words[0]]; ok || isAssignment(words[0]) {
				words, stripped = words[1:], true
				continue
			}
		}
		if stripped && inner != nil {
			inner(words)
		}
		if !isWrapper {
			break
		}
		next, runs, err := spec.skip(words[1:])
		if err != nil {
			return nil, err
		}
		if !runs {
			break
		}
		words, stripped = next, true
	}
	return words, nil
}

// innerScripts returns the command strings a simple command, as its
// unquoted words with any wrappers already dropped (see unwrapCommand),
// runs as shell code: the script of a shell's -c option (alone or in a
// cluster such as -lc or -ec) or --command, fish's -C / --init-command, or
// the arguments of eval joined by spaces. readsStdin reports whether the
// command is a shell that reads its script from standard input (no -c and
// no script file, or -s), so a here-string fed to it is a script too.
func innerScripts(words []string) (scripts []string, readsStdin bool) {
	if len(words) == 0 {
		return nil, false
	}
	if commandName(words[0]) == "eval" {
		args := words[1:]
		if len(args) > 0 && args[0] == "--" {
			args = args[1:]
		}
		if len(args) == 0 {
			return nil, false
		}
		return []string{strings.Join(args, " ")}, false
	}
	shell := shellName(words[0])
	if shell == "" {
		return nil, false
	}
	fish := shell == "fish"
	runsString, stdinFlag := false, false
	for i := 1; i < len(words); i++ {
		w := words[i]
		switch {
		case w == "--" || w == "-":
			if runsString {
				if i+1 < len(words) {
					scripts = append(scripts, words[i+1])
				}
				return scripts, false
			}
			// With -s, what follows are arguments; otherwise the next
			// word is a script file.
			return scripts, stdinFlag || i+1 == len(words)
		case w == "--command" || (fish && w == "--init-command"):
			if i+1 < len(words) {
				scripts = append(scripts, words[i+1])
				i++
			}
			if w == "--command" {
				return scripts, false
			}
		case strings.HasPrefix(w, "--command="):
			return append(scripts, w[len("--command="):]), false
		case fish && strings.HasPrefix(w, "--init-command="):
			scripts = append(scripts, w[len("--init-command="):])
		case strings.HasPrefix(w, "--"):
			// Long options (--login, --norc); these two take a value.
			if w == "--rcfile" || w == "--init-file" {
				i++
			}
		case len(w) > 1 && (w[0] == '-' || w[0] == '+'):
			opts := w[1:]
			if w[0] == '-' {
				runsString = runsString || strings.IndexByte(opts, 'c') >= 0
				stdinFlag = stdinFlag || strings.IndexByte(opts, 's') >= 0
				if fish && strings.IndexByte(opts, 'C') >= 0 && i+1 < len(words) {
					scripts = append(scripts, words[i+1])
					i++
					continue
				}
			}
			if strings.IndexByte(opts, 'o') >= 0 || strings.IndexByte(opts, 'O') >= 0 {
				i++ // -o option / -O shopt_option take a name
			}
		default:
			// The first operand: the script when -c was given; with -s,
			// an argument; else a script file the shell reads (not
			// something to parse here).
			if runsString {
				return append(scripts, w), false
			}
			return scripts, stdinFlag
		}
	}
	// No operand: a shell without -c reads its script from stdin.
	return scripts, !runsString
}

// runsOtherCommand reports whether a syntax-free command, as its words,
// runs a command its plain text hides: a wrapped command or a command
// string. It decides whether such a command takes the segment path.
func runsOtherCommand(words []string) bool {
	wrapped := false
	inner, err := unwrapCommand(words, func([]string) { wrapped = true })
	if err != nil {
		return true // the segment path denies it as unparseable
	}
	if wrapped {
		return true
	}
	scripts, _ := innerScripts(inner)
	return len(scripts) > 0
}

// shellName returns the shell a command word names, or "". A trailing
// version (bash5, ksh93, bash5.2) is dropped first.
func shellName(w string) string {
	name := commandName(w)
	if _, ok := shellNames[name]; ok {
		return name
	}
	if v := trimVersion(name); v != name {
		if _, ok := shellNames[v]; ok {
			return v
		}
	}
	return ""
}

// trimVersion drops trailing digits and dots from a command name.
func trimVersion(name string) string {
	end := len(name)
	for end > 0 && (isDigit(name[end-1]) || name[end-1] == '.') {
		end--
	}
	return name[:end]
}

// startsWithLauncher reports, without allocating, whether a syntax-free
// command starts with a NAME=value assignment, or its first word names a
// shell, eval, a command wrapper or `!`: the only commands that can run
// another command their text hides. It runs on every shell check, so
// ordinary commands (`git push --force`, `npm run test -- --watch`) cost a
// short scan and one map lookup.
func startsWithLauncher(cmd string) bool {
	i := 0
	for i < len(cmd) && (cmd[i] == ' ' || cmd[i] == '\t') {
		i++
	}
	j := i
	for j < len(cmd) && cmd[j] != ' ' && cmd[j] != '\t' {
		j++
	}
	if i == j {
		return false
	}
	w := cmd[i:j]
	if isAssignment(w) {
		return true
	}
	var buf [maxLauncherName]byte
	name, ok := lowerCommandName(&buf, w)
	if !ok {
		return false
	}
	// string(name) in a map index does not allocate.
	if _, ok := launcherNames[string(name)]; ok {
		return true
	}
	if v := trimVersionBytes(name); len(v) < len(name) {
		_, ok = shellNames[string(v)]
		return ok
	}
	return false
}

// maxLauncherName bounds the command names startsWithLauncher lowercases;
// every launcher name, with a version, is shorter.
const maxLauncherName = 24

// lowerCommandName writes the lowercased last path element of w into buf,
// without a .exe suffix, as commandName does but without allocating. ok is
// false when the name doesn't fit, so it can't be a launcher.
func lowerCommandName(buf *[maxLauncherName]byte, w string) ([]byte, bool) {
	w = baseName(w)
	if len(w) > 4 && strings.EqualFold(w[len(w)-4:], ".exe") {
		w = w[:len(w)-4]
	}
	if len(w) > len(buf) {
		return nil, false
	}
	for k := 0; k < len(w); k++ {
		c := w[k]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		buf[k] = c
	}
	return buf[:len(w)], true
}

// trimVersionBytes is trimVersion for a byte slice.
func trimVersionBytes(name []byte) []byte {
	end := len(name)
	for end > 0 && (isDigit(name[end-1]) || name[end-1] == '.') {
		end--
	}
	return name[:end]
}

// launcherNames are the command names startsWithLauncher looks for.
var launcherNames = func() map[string]struct{} {
	m := map[string]struct{}{"eval": {}, "!": {}}
	for name := range shellNames {
		m[name] = struct{}{}
	}
	for name := range commandWrappers {
		m[name] = struct{}{}
	}
	return m
}()

// commandName is the name a command word is looked up by: its last path
// element, lowercased and without a .exe suffix. File systems on macOS and
// Windows ignore case, so BASH and /BIN/SH run bash and sh there.
func commandName(w string) string {
	name := strings.ToLower(baseName(w))
	return strings.TrimSuffix(name, ".exe")
}

// isAssignment reports whether w is a NAME=value word.
func isAssignment(w string) bool {
	eq := strings.IndexByte(w, '=')
	if eq <= 0 {
		return false
	}
	for i := 0; i < eq; i++ {
		if !nameByte(w[i], i == 0) {
			return false
		}
	}
	return true
}

// nameByte reports whether c can appear in a shell variable name; a digit
// can't start one.
func nameByte(c byte, first bool) bool {
	switch {
	case c == '_', c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		return true
	}
	return !first && c >= '0' && c <= '9'
}

// baseName is the last path element of a command word, so /bin/sh and
// /usr/bin/bash name sh and bash. A backslash separates too, for a quoted
// Windows path.
func baseName(w string) string {
	for i := len(w) - 1; i >= 0; i-- {
		if w[i] == '/' || w[i] == '\\' {
			return w[i+1:]
		}
	}
	return w
}
