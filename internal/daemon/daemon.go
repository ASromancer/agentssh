// Package daemon is the long-running agentssh process: it holds decrypted
// keys in memory, enforces policy, runs approvals and talks SSH.
package daemon

import (
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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hiepnt01/agentssh/internal/approval"
	"github.com/hiepnt01/agentssh/internal/audit"
	"github.com/hiepnt01/agentssh/internal/hosts"
	"github.com/hiepnt01/agentssh/internal/paths"
	"github.com/hiepnt01/agentssh/internal/policy"
	"github.com/hiepnt01/agentssh/internal/sshconn"
	"github.com/hiepnt01/agentssh/internal/vault"
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

	q    *approval.Queue
	pool *sshconn.Pool
	log  *audit.Log
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
	if err := d.loadConfig(); err != nil {
		return nil, err
	}
	d.autoUnlock()
	return d, nil
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
	old := syscall.Umask(0o077)
	ln, err := net.Listen("unix", sock)
	syscall.Umask(old)
	if err != nil {
		return err
	}
	if err := os.Chmod(sock, 0o600); err != nil {
		return err
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
		uid, err := peerUID(c)
		if err != nil || uid != os.Getuid() {
			log.Printf("rejected connection from uid %d (%v)", uid, err)
			c.Close()
			continue
		}
		go srv.ServeCodec(jsonrpc.NewServerCodec(c))
	}
}

func peerUID(c net.Conn) (int, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return -1, errors.New("not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return -1, err
	}
	uid := -1
	var cerr error
	if err := raw.Control(func(fd uintptr) { uid, cerr = peerUIDFd(int(fd)) }); err != nil {
		return -1, err
	}
	return uid, cerr
}
