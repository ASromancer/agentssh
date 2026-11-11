// Package daemon is the long-running agentssh process: it holds decrypted
// keys in memory, enforces policy, runs approvals and talks SSH.
package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ASromancer/agentssh/internal/approval"
	"github.com/ASromancer/agentssh/internal/audit"
	"github.com/ASromancer/agentssh/internal/hosts"
	"github.com/ASromancer/agentssh/internal/humanok"
	"github.com/ASromancer/agentssh/internal/paths"
	"github.com/ASromancer/agentssh/internal/policy"
	"github.com/ASromancer/agentssh/internal/sshconn"
	"github.com/ASromancer/agentssh/internal/vault"
)

const outRetention = 7 * 24 * time.Hour

type Daemon struct {
	mu       sync.Mutex
	engine   *policy.Engine
	cfg      *hosts.Config
	data     *vault.Data // nil while locked
	master   *[32]byte
	salt     []byte
	userOnly bool // config on disk differs from the approved hash
	jobs     map[int]*sshconn.Job

	q      *approval.Queue
	human  humanok.Confirmer
	dialog sync.Mutex            // one OS dialog at a time
	auth   atomic.Pointer[error] // why approvals use codes; nil error: OS authentication
	pool   *sshconn.Pool
	log    *audit.Log
}

func New(notify func(title, body string) error, approvalTimeout time.Duration) (*Daemon, error) {
	for _, d := range []string{paths.Config(), paths.State(), paths.Out(), filepath.Dir(paths.Socket())} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	d := &Daemon{
		jobs: map[int]*sshconn.Job{},
		q:    approval.NewQueue(notify, approvalTimeout),
		pool: sshconn.NewPool(paths.KnownHosts()),
		log:  &audit.Log{Path: paths.Audit()},
	}
	d.human = humanok.Default
	if why := osAuthOff(runtime.GOOS, os.Getenv("AGENTSSH_OS_AUTH")); why != "" {
		d.human = authOff(why)
	}
	d.pickAuth()
	d.q.UseCodes = func() bool { return !d.osAuth() }
	if err := d.loadConfig(); err != nil {
		return nil, err
	}
	d.autoUnlock()
	return d, nil
}

// osAuthOff returns why OS authentication is off, or "" when it is on.
// It is on by default only on Linux, the only backend verified on a real
// machine so far; AGENTSSH_OS_AUTH=1 turns it on, =0 off, everywhere.
func osAuthOff(goos, env string) string {
	switch {
	case env == "0":
		return "OS authentication is off (AGENTSSH_OS_AUTH=0)"
	case env == "1", goos == "linux":
		return ""
	}
	return "OS authentication is off on " + goos + " until verified; set AGENTSSH_OS_AUTH=1 to enable"
}

// authOff is the confirmer when OS authentication is turned off.
type authOff string

func (a authOff) Available() error                      { return fmt.Errorf("%w: %s", humanok.ErrUnavailable, string(a)) }
func (a authOff) Confirm(context.Context, string) error { return a.Available() }

// pickAuth decides how the human is authenticated, at start. Nothing an
// agent does to the session later (renaming the display socket, killing
// the polkit agent) can switch the daemon to codes.
func (d *Daemon) pickAuth() {
	err := d.human.Available()
	d.auth.Store(&err)
}

// reloadAuth runs on an approved reload. It may switch codes to OS
// authentication, never back: in OS mode it only returns why the dialog
// cannot be shown right now.
func (d *Daemon) reloadAuth() error {
	if d.osAuth() {
		return d.human.Available()
	}
	d.pickAuth()
	return nil
}

// authProblem returns why approvals use codes, or nil when they use OS
// authentication.
func (d *Daemon) authProblem() error { return *d.auth.Load() }

// osAuth reports whether the human is authenticated through the OS.
func (d *Daemon) osAuth() bool { return d.authProblem() == nil }

const (
	confirmTimeout = 2 * time.Minute
	maxDialogBytes = 1000
	dialogHead     = 500
	dialogTail     = 400
)

// dialogText makes any message safe and honest for every OS backend: valid
// UTF-8, no control or bidi/format characters, whitespace collapsed, never
// empty. An over-long message keeps its head and tail so that padding
// cannot hide the end of a command.
func dialogText(msg string) string {
	msg = strings.ToValidUTF8(msg, "\uFFFD")
	msg = strings.Map(func(r rune) rune {
		switch {
		case r == 0, unicode.Is(unicode.Cf, r), r == 0x3164, r == 0x2800: // invisible
			return -1
		case r < 0x20, r >= 0x7F && r <= 0x9F:
			return ' '
		}
		return r
	}, msg)
	msg = strings.Join(strings.Fields(msg), " ")
	if msg == "" {
		return "confirm an agentssh action"
	}
	if len(msg) > maxDialogBytes {
		h, t := dialogHead, len(msg)-dialogTail
		for !utf8.RuneStart(msg[h]) {
			h--
		}
		for !utf8.RuneStart(msg[t]) {
			t++
		}
		msg = fmt.Sprintf("%s … %d bytes hidden … %s", msg[:h], t-h, msg[t:])
	}
	return msg
}

var errBusy = errors.New("another confirmation is already in progress; finish it first")

// confirm shows one OS dialog at a time, so that the human never answers
// a dialog started by someone else while waiting for their own. If the OS
// cannot show it, the daemon stays in OS mode: switching to codes is the
// human's decision, made by restarting the daemon.
func (d *Daemon) confirm(msg string) error {
	if !d.dialog.TryLock() {
		return errBusy
	}
	defer d.dialog.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), confirmTimeout)
	defer cancel()
	err := d.human.Confirm(ctx, dialogText(msg))
	if !errors.Is(err, humanok.ErrUnavailable) {
		return err
	}
	return fmt.Errorf("OS authentication failed: %w. Run 'agentssh doctor'; to use approval codes instead, restart the daemon with AGENTSSH_OS_AUTH=0.", err)
}

func (d *Daemon) loadConfig() error {
	cfg, err := hosts.Load(paths.Hosts())
	if err != nil {
		return err
	}
	eng, err := policy.Load(paths.Rules())
	if err != nil {
		return err
	}
	d.mu.Lock()
	d.cfg, d.engine = cfg, eng
	d.mu.Unlock()
	return nil
}

// ConfigHash fingerprints hosts.toml and rules.toml.
func ConfigHash() string {
	h := sha256.New()
	for _, p := range []string{paths.Hosts(), paths.Rules()} {
		b, _ := os.ReadFile(p)
		fmt.Fprintf(h, "%s\x00%d\x00", filepath.Base(p), len(b))
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (d *Daemon) autoUnlock() {
	salt, err := vault.Salt(paths.Vault())
	if err != nil {
		log.Printf("vault not available (%v); run 'agentssh init'", err)
		return
	}
	if salt != nil {
		log.Print("vault uses a passphrase; waiting for 'agentssh unlock'")
		return
	}
	key, err := vault.KeyringGet()
	if err != nil {
		log.Printf("keyring: %v; waiting for 'agentssh unlock'", err)
		return
	}
	if err := d.unlock(key, nil); err != nil {
		log.Printf("unlock: %v", err)
	}
}

func (d *Daemon) unlock(key *[32]byte, salt []byte) error {
	data, err := vault.Open(paths.Vault(), key)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.data != nil {
		d.data.Wipe()
	}
	d.data, d.master, d.salt = data, key, salt
	d.userOnly = data.ConfigHash != ConfigHash()
	if d.userOnly {
		log.Print("hosts.toml/rules.toml changed since last approval: refusing agent requests until 'agentssh reload'")
	}
	return nil
}

func (d *Daemon) lock() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.data != nil {
		d.data.Wipe()
		clear(d.master[:])
	}
	d.data, d.master = nil, nil
}

// saveVault must be called with d.mu held.
func (d *Daemon) saveVault() error {
	return vault.Save(paths.Vault(), d.master, d.salt, d.data)
}

var idMu sync.Mutex

// newID returns a request id that stays unique across restarts.
func newID() int {
	idMu.Lock()
	defer idMu.Unlock()
	p := filepath.Join(paths.State(), "next_id")
	b, _ := os.ReadFile(p)
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	if n < 1 {
		n = 1
	}
	_ = os.WriteFile(p, []byte(strconv.Itoa(n+1)), 0o600)
	return n
}

func OutPath(id int) string { return filepath.Join(paths.Out(), strconv.Itoa(id)) }

func cleanOut() {
	ents, _ := os.ReadDir(paths.Out())
	for _, e := range ents {
		if fi, err := e.Info(); err == nil && time.Since(fi.ModTime()) > outRetention {
			os.Remove(filepath.Join(paths.Out(), e.Name()))
		}
	}
}

// Serve listens on the unix socket until SIGINT/SIGTERM.
func (d *Daemon) Serve() error {
	sock := paths.Socket()
	if c, err := net.DialTimeout("unix", sock, time.Second); err == nil {
		c.Close()
		return errors.New("daemon already running on " + sock)
	}
	os.Remove(sock)
	old := umask(0o077)
	ln, err := net.Listen("unix", sock)
	umask(old)
	if err != nil {
		return err
	}
	if err := os.Chmod(sock, 0o600); err != nil && runtime.GOOS != "windows" {
		return err // on Windows the per-user AppData ACL protects the socket
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		ln.Close()
	}()
	go func() {
		for {
			cleanOut()
			time.Sleep(time.Hour)
		}
	}()
	log.Printf("agentssh daemon listening on %s", sock)
	err = d.ServeListener(ln)
	os.Remove(sock)
	d.lock()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// ServeListener accepts connections only from processes of the same user.
func (d *Daemon) ServeListener(ln net.Listener) error {
	srv := rpc.NewServer()
	if err := srv.RegisterName("A", &Service{d}); err != nil {
		return err
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		if err := checkPeer(c); err != nil {
			log.Printf("rejected connection: %v", err)
			c.Close()
			continue
		}
		go srv.ServeCodec(jsonrpc.NewServerCodec(c))
	}
}

// checkPeer accepts only processes running as the same user.
func checkPeer(c net.Conn) error {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return errors.New("not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	var cerr error
	if err := raw.Control(func(fd uintptr) { cerr = samePeerUser(fd) }); err != nil {
		return err
	}
	return cerr
}
