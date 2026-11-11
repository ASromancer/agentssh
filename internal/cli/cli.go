// Package cli implements the ostiary subcommands. Agent-facing commands
// are thin clients of the daemon; human commands need a real terminal.
package cli

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/rpc"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/ASromancer/ostiary/internal/daemon"
)

const usage = `ostiary — SSH for AI agents with policy, approvals and audit.

For agents:
  ostiary hosts [--json]
  ostiary run <host> "<cmd>" [--timeout 60s] [--json]
  ostiary out <id> [--grep <regexp>] [--range a:b]
  ostiary get <host>:<remote-path> <local-path>
  ostiary put <local-path> <host>:<remote-path>
  ostiary job start <host> "<cmd>" | job tail <id> [--lines N] | job kill <id>
  ostiary explain "<cmd>" [--host <host>]
  ostiary mcp [--cwd <dir>]          stdio MCP server with the same tools

For the human user (need a real terminal; approvals and admin commands are confirmed
in an OS authentication dialog, or with a code from a desktop notification as a fallback):
  ostiary open                       open the Ostiary app (starts the daemon if needed)
  ostiary stop                       stop the daemon
  ostiary upgrade [--check] [--yes]  install the latest release (--check: exit 10 if one exists)
  ostiary init [--passphrase] | unlock | lock | approve | reload | doctor | ui | daemon | install-polkit | install-service | uninstall-service
  ostiary host add|edit|ls|rm|trust ...
  ostiary key gen|import|export|ls|rm ...
  ostiary log [--follow] [-n N]
  ostiary install-hooks claude|codex|gemini|antigravity|all

Exit codes: the remote command's own code, or
  100 blocked by policy, 101 denied / approval timed out, 102 daemon not running or vault locked.
Only errors produced by ostiary itself print a stderr line starting with "ostiary:".
`

// Version is set at release time with -ldflags "-X .../internal/cli.Version=x.y.z".
var Version = "dev"

func init() {
	// go install github.com/ASromancer/ostiary@vX stamps the module version.
	if bi, ok := debug.ReadBuildInfo(); ok && Version == "dev" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		Version = strings.TrimPrefix(bi.Main.Version, "v")
	}
}

var guidance = map[int]string{
	daemon.CodeBlocked:  "blocked by policy: do not retry another way; tell the user what you wanted to do",
	daemon.CodeDenied:   "stop and ask the user; do not retry another way",
	daemon.CodeNoDaemon: "if you run in a sandbox (e.g. Codex), it may block ostiary's local socket: re-run this ostiary command outside the sandbox first; otherwise ask the user to start or unlock ostiary",
}

// Main runs a subcommand and returns the process exit code.
func Main(args []string) int {
	if len(args) == 0 {
		if exe, err := os.Executable(); err == nil && appDefault(exe) {
			return cmdOpen(nil)
		}
		fmt.Print(usage)
		return 2
	}
	cleanOldBinaries()
	cmds := map[string]func([]string) int{
		"hosts": cmdHosts, "run": cmdRun, "out": cmdOut, "get": cmdGet, "put": cmdPut,
		"job": cmdJob, "explain": cmdExplain, "hook": cmdHook,
		"init": cmdInit, "unlock": cmdUnlock, "lock": cmdLock, "approve": cmdApprove,
		"reload": cmdReload, "host": cmdHost, "key": cmdKey, "log": cmdLog, "doctor": cmdDoctor, "ui": cmdUI,
		"install-hooks": cmdInstallHooks, "daemon": cmdDaemon, "install-polkit": cmdInstallPolkit, "install-service": cmdInstallService, "uninstall-service": cmdUninstallService, "mcp": cmdMCP, "open": cmdOpen, "stop": cmdStop, "upgrade": cmdUpgrade,
		"version": func([]string) int { fmt.Println("ostiary", Version); return 0 },
	}
	if f, ok := cmds[args[0]]; ok {
		return f(args[1:])
	}
	if args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Print(usage)
		return 0
	}
	return errf(2, "unknown command %q; see 'ostiary help'", args[0])
}

func errf(code int, format string, a ...any) int {
	fmt.Fprintf(os.Stderr, "ostiary: "+format+"\n", a...)
	return code
}

// agentFail prints an ostiary-specific error with guidance for the agent.
func agentFail(code int, msg string) int {
	fmt.Fprintf(os.Stderr, "ostiary: %s\nostiary: %s\n", msg, guidance[code])
	return code
}

func dial() (*rpc.Client, int) {
	// a short retry covers the window right after the daemon (re)starts
	c, err := dialRetry(2 * time.Second)
	if err != nil {
		return nil, agentFail(daemon.CodeNoDaemon, "daemon is not running (systemctl --user start ostiary, or 'ostiary daemon --detach')")
	}
	return c, 0
}

func callErr(err error) int {
	if errors.Is(err, rpc.ErrShutdown) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return agentFail(daemon.CodeNoDaemon, "lost connection to the daemon")
	}
	return errf(1, "%v", err)
}

func env() daemon.Env {
	cwd, _ := os.Getwd()
	e := daemon.Env{Cwd: cwd}
	if os.Getenv("CLAUDECODE") != "" {
		e.Agent = daemon.AgentClaude
	}
	for _, kv := range os.Environ() {
		switch {
		case strings.HasPrefix(kv, "CODEX_"):
			e.Agent = "codex"
		case strings.HasPrefix(kv, "GEMINI_CLI="):
			e.Agent = "gemini"
		case strings.HasPrefix(kv, "ANTIGRAVITY"):
			e.Agent = "antigravity"
		}
	}
	return e
}

// parse lets flags appear before, between or after positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet("ostiary "+name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

// term is the controlling terminal (/dev/tty, or CONIN$/CONOUT$ on
// Windows). Human-only commands insist on it so an agent driving a pipe
// cannot answer the prompts.
type term struct {
	in, out *os.File
	r       *bufio.Reader
}

func openTTY(what string) (*term, int) {
	in, out, err := openConsole()
	if err != nil {
		return nil, errf(2, "%s must be run by the user in a real terminal (%v)", what, err)
	}
	return &term{in, out, bufio.NewReader(in)}, 0
}

func (t *term) printf(format string, a ...any) { fmt.Fprintf(t.out, format, a...) }

func (t *term) prompt(p string) string {
	t.printf("%s", p)
	l, _ := t.r.ReadString('\n')
	return strings.TrimSpace(l)
}

func (t *term) secret(p string) string {
	restore := echoOff(t.in)
	defer func() {
		restore()
		t.printf("\n")
	}()
	return t.prompt(p)
}

func (t *term) yes(q string, def bool) bool {
	hint := " [y/N] "
	if def {
		hint = " [Y/n] "
	}
	a := strings.ToLower(t.prompt(q + hint))
	if a == "" {
		return def
	}
	return a == "y" || a == "yes"
}
