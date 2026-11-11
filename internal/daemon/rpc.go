package daemon

import (
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"time"

	"github.com/ASromancer/ostiary/internal/hosts"
	"github.com/ASromancer/ostiary/internal/paths"
	"github.com/ASromancer/ostiary/internal/policy"
)

// ostiary-specific exit codes (spec 6.1).
const (
	CodeBlocked  = 100 // forbidden, profile does not allow, host not allowed
	CodeDenied   = 101 // denied or approval timed out
	CodeNoDaemon = 102 // daemon not running or vault locked
)

// AgentClaude is the Env.Agent value for Claude Code, the only agent whose
// hook asks the user before state-changing commands (soft layer).
const AgentClaude = "claude-code"

// Env is what the CLI tells the daemon about its caller. It is
// self-declared, so it only scopes convenience features, never security.
type Env struct {
	Cwd   string
	Agent string
}

type Empty struct{}

type HostInfo struct {
	Name        string `json:"name"`
	Profile     string `json:"profile"`
	Description string `json:"description,omitempty"`
}

type HostsReply struct {
	Hosts []HostInfo
}

type ExecArgs struct {
	Env
	Kind       string // run|job|get|put
	Host       string
	Cmd        string // run, job
	Remote     string // get, put
	Local      string // get, put (absolute)
	Timeout    time.Duration
	ApprovalID int           // second call after the request was approved
	WaitMax    time.Duration // with ApprovalID: give up waiting after this (0 = until decided); Pending is set again
}

type ExecReply struct {
	Code    int    // CodeBlocked/CodeDenied/CodeNoDaemon, 0 otherwise
	Msg     string // shown on stderr with the "ostiary:" prefix
	Pending int    // approval needed: call again with ApprovalID = Pending
	ID      int
	Exit    int
	DurMs   int64
	Level   string
	Output  string
}

type ExplainArgs struct {
	Env
	Cmd, Host string
}

type ExplainReply struct {
	policy.Result
	Host    string
	HostOK  bool
	Profile string
	Action  string
	Msg     string
}

type JobArgs struct{ ID, Lines int }

type JobReply struct {
	Running bool
	Exit    int
	Output  string
}

type StatusReply struct {
	Locked, UserOnly, Passphrase, VaultMissing bool
	Pending                                    int
	Auth                                       string // "os" or "code"
	AuthNote                                   string // why OS authentication is unavailable
	UI                                         string // base URL of the web UI, "" when it is not running
}

type UILoginReply struct{ URL string }

type UnlockArgs struct{ Pass string }

type DecideArgs struct {
	ID                 int
	Code, Choice, Note string
}

type BeginArgs struct{ Op, Name string }

type BeginReply struct {
	Ticket int
	Info   string // e.g. host key fingerprint to compare
	Code   string // only when the desktop notification failed (code mode)
	OSAuth bool   // no code: Admin triggers an OS authentication dialog
}

type AdminArgs struct {
	Ticket   int
	Code     string
	Op, Name string
	Host     *hosts.Host
	PEM      []byte
	Password []byte
	Pass     []byte // vault passphrase for init (never logged)
}

type AdminReply struct{ Out string }

// AgentState is one agent's setup state, for the onboarding guide.
type AgentState struct {
	Name      string // claude | codex | gemini | antigravity
	Detected  bool   // the agent's config dir exists
	Installed bool   // our hook/plugin is configured
}

// SetupFuncs are the agent/service helpers that live in package cli.
type SetupFuncs struct {
	Agents       func() []AgentState
	InstallHook  func(agent string) error
	Autostart    func() bool
	SetAutostart func(on bool) error
}

type SetupReply struct {
	VaultReady    bool // vault file exists
	Locked        bool
	Hosts         int
	Keys          int // keys + passwords; -1 while locked
	Agents        []AgentState
	Autostart     bool
	PolkitMissing bool // linux only: the polkit policy file is absent
	Skipped       bool // the user hid the guide
}

type SetupSkipArgs struct{ Skip bool }

type KeysReply struct{ Keys []string }

// Dial connects to the running daemon.
func Dial() (*rpc.Client, error) {
	c, err := net.DialTimeout("unix", paths.Socket(), 2*time.Second)
	if err != nil {
		return nil, err
	}
	return jsonrpc.NewClient(c), nil
}

// HostListReply is every configured host (not only those visible to
// agents), for the human UI.
type HostListReply struct {
	Hosts   map[string]hosts.Host
	Trusted map[string]bool // host key pinned in known_hosts
}
