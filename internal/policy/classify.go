package policy

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Classify parses cmd and returns the highest risk level of everything in it.
// allow/deny are extra per-host patterns: deny raises a match to forbidden,
// allow lowers a rule-table match to read (never a forbidden one).
func (e *Engine) Classify(cmd string, allow, deny []string) Result {
	c := &classifier{e: e, allow: allow, deny: deny}
	c.script(cmd, 0, 0)
	if len(c.res.Reasons) == 0 {
		c.add(Read, "empty command", 0, len(cmd))
	}
	return c.res
}

type classifier struct {
	e           *Engine
	allow, deny []string
	res         Result
}

func (c *classifier) add(l Level, text string, start, end int) {
	for _, r := range c.res.Reasons {
		if r.Text == text && r.Start == start {
			return
		}
	}
	c.res.Reasons = append(c.res.Reasons, Reason{l, text, start, end})
	if l > c.res.Level {
		c.res.Level = l
	}
}

// word is a shell word evaluated statically. static=false means its value
// depends on runtime expansion ($x, $(...), globs in names, ...).
type word struct {
	s          string
	static     bool
	start, end int
}

const maxDepth = 5

func (c *classifier) script(src string, base, depth int) {
	if depth > maxDepth {
		c.add(Destructive, "nested shell too deep", base, base+len(src))
		return
	}
	f, err := syntax.NewParser().Parse(strings.NewReader(src), "")
	if err != nil {
		c.add(Destructive, "parse error: "+err.Error(), base, base+len(src))
		return
	}
	c.scan(src, base, base+len(src))
	syntax.Walk(f, func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.Stmt:
			if call, ok := x.Cmd.(*syntax.CallExpr); ok && len(call.Args) > 0 {
				ws := make([]word, len(call.Args))
				for i, w := range call.Args {
					ws[i] = evalWord(w, base)
				}
				c.argv(ws, extraText(x, src), src, base, depth)
			}
			for _, r := range x.Redirs {
				c.redirect(r, base)
			}
		case *syntax.BinaryCmd:
			if x.Op == syntax.Pipe || x.Op == syntax.PipeAll {
				c.pipe(x, base)
			}
		}
		return true
	})
}

// extraText returns heredoc bodies attached to a statement (for SQL checks).
func extraText(s *syntax.Stmt, src string) string {
	var b strings.Builder
	for _, r := range s.Redirs {
		if r.Hdoc != nil {
			b.WriteString(src[r.Hdoc.Pos().Offset():r.Hdoc.End().Offset()])
		}
		if r.Op == syntax.WordHdoc && r.Word != nil {
			b.WriteString(src[r.Word.Pos().Offset():r.Word.End().Offset()])
		}
	}
	return b.String()
}

var (
	sensitiveRe = regexp.MustCompile(`(^|[^\w])\.ssh([^\w]|$)|authorized_keys|(^|[^a-zA-Z0-9])id_(rsa|dsa|ecdsa|ed25519)|/etc/(shadow|gshadow|sudoers)|/dev/(tcp|udp)/`)
	sqlRe       = regexp.MustCompile(`(?i)\b(drop|truncate|delete|alter)\b`)
	// Sample sensitive paths that a glob argument must not be able to reach.
	sensitivePaths = []string{
		"~/.ssh", "~/.ssh/id_rsa", "~/.ssh/authorized_keys", ".ssh", ".ssh/id_rsa", ".ssh/authorized_keys",
		"/root/.ssh", "/root/.ssh/id_rsa", "/home/u/.ssh", "/home/u/.ssh/id_rsa", "/home/u/.ssh/authorized_keys",
		"/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d",
	}
)

// scan flags references to secrets and raw network devices anywhere in text.
func (c *classifier) scan(text string, start, end int) {
	if m := sensitiveRe.FindString(text); m != "" {
		c.add(Forbidden, "reference to sensitive path: "+strings.TrimSpace(m), start, end)
	}
}

func globReachesSensitive(pat string) bool {
	if !strings.ContainsAny(pat, "*?[") {
		return false
	}
	ps := strings.Split(pat, "/")
	for _, cand := range sensitivePaths {
		cs := strings.Split(cand, "/")
		if len(cs) != len(ps) {
			continue
		}
		ok := true
		for i := range cs {
			// Shell globs never match a leading dot implicitly.
			if strings.HasPrefix(cs[i], ".") && !strings.HasPrefix(ps[i], ".") {
				ok = false
				break
			}
			if m, _ := path.Match(ps[i], cs[i]); !m {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

var safeVars = map[string]bool{"USER": true, "LOGNAME": true, "PWD": true, "HOSTNAME": true, "SHELL": true}

func evalWord(w *syntax.Word, base int) word {
	var b strings.Builder
	static := true
	for _, p := range w.Parts {
		if !evalPart(p, &b, false) {
			static = false
		}
	}
	s := b.String()
	// Brace expansion ({a,b}) can assemble any string at runtime.
	if strings.Contains(s, "{") && strings.Contains(s, ",") && strings.Contains(s, "}") {
		static = false
	}
	return word{s, static, base + int(w.Pos().Offset()), base + int(w.End().Offset())}
}

func evalPart(p syntax.WordPart, b *strings.Builder, inDq bool) bool {
	switch x := p.(type) {
	case *syntax.Lit:
		b.WriteString(unescape(x.Value, inDq))
		return true
	case *syntax.SglQuoted:
		b.WriteString(x.Value)
		return !x.Dollar
	case *syntax.DblQuoted:
		ok := !x.Dollar
		for _, pp := range x.Parts {
			if !evalPart(pp, b, true) {
				ok = false
			}
		}
		return ok
	case *syntax.ParamExp:
		if x.Param != nil && !x.Excl && !x.Length && x.Index == nil && x.Slice == nil &&
			x.Repl == nil && x.Exp == nil && x.Names == 0 && len(x.Modifiers) == 0 {
			if x.Param.Value == "HOME" {
				b.WriteString("~")
				return true
			}
			if safeVars[x.Param.Value] {
				b.WriteString("$" + x.Param.Value)
				return true
			}
		}
	}
	b.WriteString("$?")
	return false
}

func unescape(s string, inDq bool) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			n := s[i+1]
			if !inDq || strings.IndexByte("$`\"\\\n", n) >= 0 {
				if n != '\n' {
					b.WriteByte(n)
				}
				i++
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

type wrapper struct {
	argFlags   string // space-separated flags that take a value
	positional int    // positional args before the wrapped command (timeout DURATION)
	assigns    bool   // allows NAME=value words before the command
}

var wrappers = map[string]wrapper{
	"sudo":    {argFlags: "-u -g -C -D -h -p -r -t -U -T --user --group --chdir --host --prompt --role --type --other-user --close-from --command-timeout", assigns: true},
	"doas":    {argFlags: "-u -C"},
	"env":     {argFlags: "-u -C --unset --chdir", assigns: true},
	"nohup":   {},
	"timeout": {argFlags: "-s -k --signal --kill-after", positional: 1},
	"nice":    {argFlags: "-n --adjustment"},
	"ionice":  {argFlags: "-c -n -p --class --classdata"},
	"xargs":   {argFlags: "-a -d -E -I -L -n -P -s --arg-file --delimiter --eof --replace --max-lines --max-args --max-procs --max-chars --process-slot-var"},
	"stdbuf":  {argFlags: "-i -o -e --input --output --error"},
	"command": {},
	"builtin": {},
	"exec":    {argFlags: "-a"},
	"time":    {argFlags: "-f -o --format --output"},
}

var assignRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

func skipFlags(ws []word, w wrapper) []word {
	args := strings.Fields(w.argFlags)
	takesArg := func(f string) bool {
		for _, a := range args {
			if a == f {
				return true
			}
		}
		return false
	}
	i := 0
	for i < len(ws) {
		a := ws[i].s
		if !ws[i].static {
			break
		}
		if a == "--" {
			i++
			break
		}
		if w.assigns && assignRe.MatchString(a) {
			i++
			continue
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			break
		}
		i++
		if takesArg(a) {
			i++
		}
	}
	i += w.positional
	if i > len(ws) {
		i = len(ws)
	}
	return ws[i:]
}

var (
	shells      = set("sh bash zsh dash ksh ash mksh fish busybox")
	interactive = map[string]string{
		"vim": "cat / sed -n", "vi": "cat / sed -n", "nano": "cat / sed -n", "emacs": "cat / sed -n",
		"top": "top -bn1", "htop": "top -bn1", "less": "cat / head / tail", "more": "cat / head / tail",
		"watch": "run the command once", "ssh": "ostiary run on the target host", "man": "<cmd> --help",
		"mosh": "ostiary run on the target host", "tmux": "ostiary job start", "screen": "ostiary job start",
	}
	sqlClients = set("psql mysql mariadb sqlite3")
	netcats    = set("nc ncat netcat")
)

func set(s string) map[string]bool {
	m := map[string]bool{}
	for _, f := range strings.Fields(s) {
		m[f] = true
	}
	return m
}

// normalize strips paths and wrapper commands (sudo, env, timeout, ...).
// ok=false means the command name is not static.
func normalize(ws []word) (out []word, wrappersOnly []word, ok bool) {
	for len(ws) > 0 {
		if !ws[0].static || strings.ContainsAny(ws[0].s, "*?[$") || ws[0].s == "" {
			return ws, nil, false
		}
		ws[0].s = path.Base(ws[0].s)
		w, isWrapper := wrappers[ws[0].s]
		if !isWrapper {
			return ws, nil, true
		}
		rest := skipFlags(ws[1:], w)
		if len(rest) == 0 {
			return nil, ws, true
		}
		ws = rest
	}
	return nil, nil, true
}

func joinWords(ws []word) string {
	s := make([]string, len(ws))
	for i, w := range ws {
		s[i] = w.s
	}
	return strings.Join(s, " ")
}

func (c *classifier) argv(ws []word, extra, src string, base, depth int) {
	start, end := ws[0].start, ws[len(ws)-1].end
	for _, w := range ws {
		if w.static {
			c.scan(w.s, w.start, w.end)
		}
		if globReachesSensitive(w.s) {
			c.add(Forbidden, "glob may match sensitive path: "+w.s, w.start, w.end)
		}
	}
	ws, wrapOnly, ok := normalize(ws)
	if !ok {
		c.add(Destructive, "command name is not static: "+ws[0].s, start, end)
		return
	}
	if ws == nil { // e.g. bare "env" or "sudo -l": classify the wrapper itself
		ws = wrapOnly
	}
	name := ws[0].s
	raw := ""
	if start >= base && end-base <= len(src) {
		raw = src[start-base : end-base]
	}
	fetches := strings.Contains(raw, "curl") || strings.Contains(raw, "wget")

	if hint, bad := interactive[name]; bad {
		c.add(Forbidden, fmt.Sprintf("interactive command %s is not supported (no PTY); use %s", name, hint), start, end)
		return
	}
	switch {
	case shells[name] || name == "su":
		for i := 1; i < len(ws); i++ {
			a := ws[i].s
			if a == "-o" || a == "+o" {
				i++
				continue
			}
			isC := (strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.Contains(a, "c")) || a == "--command"
			if isC && i+1 < len(ws) {
				s := ws[i+1]
				if s.static {
					c.add(Read, name+" -c: classified by its script", start, end)
					c.script(s.s, s.start+1, depth+1)
				} else if fetches {
					c.add(Forbidden, "downloaded code executed by "+name, start, end)
				} else {
					c.add(Destructive, name+" -c with a dynamic script", start, end)
				}
				return
			}
			if !strings.HasPrefix(a, "-") && name != "su" {
				break
			}
		}
		if fetches {
			c.add(Forbidden, "downloaded code executed by "+name, start, end)
			return
		}
		c.add(Destructive, name+" runs a script or stdin with unknown content", start, end)
		return
	case name == "eval" || name == "source" || name == ".":
		if fetches {
			c.add(Forbidden, "downloaded code executed by "+name, start, end)
			return
		}
		c.add(Destructive, name+" runs code with unknown content", start, end)
		return
	case netcats[name]:
		for _, w := range ws[1:] {
			if w.s == "--exec" || w.s == "--sh-exec" || w.s == "--lua-exec" ||
				(strings.HasPrefix(w.s, "-") && !strings.HasPrefix(w.s, "--") && strings.ContainsAny(w.s, "ec")) {
				c.add(Forbidden, "netcat executing a program (reverse shell)", start, end)
				return
			}
		}
	case sqlClients[name]:
		if m := sqlRe.FindString(joinWords(ws[1:]) + " " + extra); m != "" {
			c.add(Destructive, fmt.Sprintf("%s with SQL %s", name, strings.ToUpper(m)), start, end)
		}
	case name == "find":
		for i := 1; i < len(ws); i++ {
			switch ws[i].s {
			case "-exec", "-execdir", "-ok", "-okdir":
				j := i + 1
				for j < len(ws) && ws[j].s != ";" && ws[j].s != "+" {
					j++
				}
				if j > i+1 {
					c.argv(append([]word(nil), ws[i+1:j]...), "", src, base, depth)
				}
				k := min(j+1, len(ws))
				ws = append(ws[:i:i], ws[k:]...) // drop the -exec part from the find line
				i--
			}
		}
	case name == "tee":
		for _, w := range ws[1:] {
			if !strings.HasPrefix(w.s, "-") {
				c.writeTarget(w, "tee")
			}
		}
	}

	line := joinWords(ws)
	if Match(c.deny, line) {
		c.add(Forbidden, name+": matches host deny rule", start, end)
		return
	}
	lvl, rule, found := c.e.lookup(line)
	why := fmt.Sprintf("%s: %s (rule %q)", name, lvl, rule)
	if !found {
		why = fmt.Sprintf("%s: %s (no rule)", name, lvl)
	}
	if lvl != Forbidden && Match(c.allow, line) {
		lvl, why = Read, name+": read (host allow rule)"
	}
	for _, w := range ws[1:] {
		if !w.static && lvl < Mutate {
			lvl, why = Mutate, name+": mutate (dynamic argument "+w.s+")"
			break
		}
	}
	c.add(lvl, why, start, end)
}

var systemPrefixes = []string{"/etc", "/boot", "/usr", "/var/lib", "/dev", "/bin", "/sbin", "/lib"}

// SystemPath reports whether writing to p counts as destructive.
func SystemPath(p string) bool {
	if strings.Contains(p, "..") {
		return true
	}
	p = path.Clean(p)
	for _, pre := range systemPrefixes {
		if p == pre || strings.HasPrefix(p, pre+"/") {
			return true
		}
	}
	return false
}

func (c *classifier) writeTarget(w word, what string) {
	switch {
	case !w.static:
		c.add(Destructive, what+" writes to a dynamic path "+w.s, w.start, w.end)
	case w.s == "/dev/null" || w.s == "/dev/stdout" || w.s == "/dev/stderr" || strings.HasPrefix(w.s, "/dev/fd/"):
	case SystemPath(w.s):
		c.add(Destructive, what+" writes to system path "+w.s, w.start, w.end)
	default:
		c.add(Mutate, what+" writes file "+w.s, w.start, w.end)
	}
}

func (c *classifier) redirect(r *syntax.Redirect, base int) {
	if r.Word == nil {
		return
	}
	w := evalWord(r.Word, base)
	switch r.Op {
	case syntax.RdrOut, syntax.AppOut, syntax.RdrClob, syntax.AppClob, syntax.RdrAll,
		syntax.RdrAllClob, syntax.AppAll, syntax.AppAllClob, syntax.RdrInOut:
		c.writeTarget(w, "redirect")
	case syntax.DplOut:
		if w.s != "-" && strings.Trim(w.s, "0123456789") != "" {
			c.writeTarget(w, "redirect")
		}
	}
}

func flattenPipe(s *syntax.Stmt, out []*syntax.Stmt) []*syntax.Stmt {
	if b, ok := s.Cmd.(*syntax.BinaryCmd); ok && (b.Op == syntax.Pipe || b.Op == syntax.PipeAll) {
		return flattenPipe(b.Y, flattenPipe(b.X, out))
	}
	return append(out, s)
}

// pipe forbids download-and-execute: curl/wget/base64 -d piped into a shell.
func (c *classifier) pipe(b *syntax.BinaryCmd, base int) {
	stages := flattenPipe(b.Y, flattenPipe(b.X, nil))
	source := false
	for _, st := range stages {
		call, ok := st.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			continue
		}
		ws := make([]word, len(call.Args))
		for i, w := range call.Args {
			ws[i] = evalWord(w, base)
		}
		ws, _, ok = normalize(ws)
		if !ok || len(ws) == 0 {
			continue
		}
		name := ws[0].s
		if source && (shells[name] || name == "python" || name == "python3" || name == "perl") {
			c.add(Forbidden, "downloaded/decoded data piped into "+name,
				base+int(b.Pos().Offset()), base+int(b.End().Offset()))
			return
		}
		if name == "curl" || name == "wget" {
			source = true
		}
		if name == "base64" {
			for _, w := range ws[1:] {
				if w.s == "-d" || w.s == "--decode" || w.s == "-D" {
					source = true
				}
			}
		}
	}
}

// Calls returns the argv of every simple command in cmd, with paths and
// wrappers (sudo, env, ...) stripped and static "sh -c" scripts expanded.
// Words that are not static read as "$?". writes reports redirects into
// real files. Used by agent hooks to spot ssh and ostiary invocations.
func Calls(cmd string) (calls [][]string, writes bool, err error) {
	err = calls1(cmd, 0, &calls, &writes)
	return calls, writes, err
}

func calls1(src string, depth int, calls *[][]string, writes *bool) error {
	f, err := syntax.NewParser().Parse(strings.NewReader(src), "")
	if err != nil {
		return err
	}
	syntax.Walk(f, func(n syntax.Node) bool {
		st, ok := n.(*syntax.Stmt)
		if !ok {
			return true
		}
		for _, r := range st.Redirs {
			if r.Word == nil {
				continue
			}
			c := &classifier{}
			c.redirect(r, 0)
			*writes = *writes || len(c.res.Reasons) > 0
		}
		call, ok := st.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		ws := make([]word, len(call.Args))
		for i, w := range call.Args {
			ws[i] = evalWord(w, 0)
		}
		ws, wrapOnly, static := normalize(ws)
		if ws == nil {
			ws = wrapOnly
		}
		argv := make([]string, len(ws))
		for i, w := range ws {
			argv[i] = w.s
			if !w.static {
				argv[i] = "$?"
			}
		}
		if !static {
			argv[0] = "$?"
		}
		*calls = append(*calls, argv)
		if shells[argv[0]] && depth < maxDepth {
			for i := 1; i+1 < len(ws); i++ {
				if ws[i].s == "-c" && ws[i+1].static {
					calls1(ws[i+1].s, depth+1, calls, writes)
					break
				}
			}
		}
		return true
	})
	return nil
}
