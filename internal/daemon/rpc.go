package daemon

import (
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"time"

	"github.com/ASromancer/agentssh/internal/hosts"
	"github.com/ASromancer/agentssh/internal/paths"
	"github.com/ASromancer/agentssh/internal/policy"
)

// agentssh-specific exit codes (spec 6.1).
const (
	CodeBlocked  = 100 // forbidden, profile does not allow, host not allowed
	CodeDenied   = 101 // denied or approval timed out
	CodeNoDaemon = 102 // daemon not running or vault locked
)

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
	Msg     string // shown on stderr with the "agentssh:" prefix
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
}

type UnlockArgs struct{ Pass string }

type DecideArgs struct {
	ID                 int
	Code, Choice, Note string
}

type BeginArgs struct{ Op, Name string }

type BeginReply struct {
	Ticket int
	Info   string // e.g. host key fingerprint to compare
	Code   string // only when the desktop notification failed
}

type AdminArgs struct {
	Ticket   int
	Code     string
	Op, Name string
	Host     *hosts.Host
	PEM      []byte
	Password []byte
}

type AdminReply struct{ Out string }

type KeysReply struct{ Keys []string }

// Dial connects to the running daemon.
func Dial() (*rpc.Client, error) {
	c, err := net.DialTimeout("unix", paths.Socket(), 2*time.Second)
	if err != nil {
		return nil, err
	}
	return jsonrpc.NewClient(c), nil
}
