// Package sshconn runs commands and transfers files over pooled SSH
// connections, with strict host key checking against agentssh's own
// known_hosts file.
package sshconn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Exit codes produced locally, mirroring ssh(1) and timeout(1).
const (
	ExitConnLost = 255
	ExitTimeout  = 124
)

type Target struct {
	Name, Addr, User string
	Auth             ssh.AuthMethod
}

type Pool struct {
	KnownHosts string
	mu         sync.Mutex
	conns      map[string]*ssh.Client
}

func NewPool(knownHosts string) *Pool {
	return &Pool{KnownHosts: knownHosts, conns: map[string]*ssh.Client{}}
}

// HostKeyError explains an unknown or changed host key.
type HostKeyError struct {
	Name    string
	Changed bool
}

func (e *HostKeyError) Error() string {
	if e.Changed {
		return fmt.Sprintf("HOST KEY CHANGED for %s; refusing to connect. If expected, the user must run 'agentssh host trust %s'", e.Name, e.Name)
	}
	return fmt.Sprintf("unknown host key for %s; the user must run 'agentssh host trust %s'", e.Name, e.Name)
}

func (p *Pool) client(t Target) (*ssh.Client, error) {
	p.mu.Lock()
	c := p.conns[t.Name]
	p.mu.Unlock()
	if c != nil {
		if _, _, err := c.SendRequest("keepalive@openssh.com", true, nil); err == nil {
			return c, nil
		}
		p.Drop(t.Name)
	}
	if f, err := os.OpenFile(p.KnownHosts, os.O_CREATE|os.O_RDONLY, 0o600); err == nil {
		f.Close()
	}
	check, err := knownhosts.New(p.KnownHosts)
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ClientConfig{
		User:    t.User,
		Auth:    []ssh.AuthMethod{t.Auth},
		Timeout: 15 * time.Second,
		HostKeyCallback: func(host string, remote net.Addr, key ssh.PublicKey) error {
			err := check(host, remote, key)
			var ke *knownhosts.KeyError
			if errors.As(err, &ke) {
				return &HostKeyError{Name: t.Name, Changed: len(ke.Want) > 0}
			}
			return err
		},
	}
	c, err = ssh.Dial("tcp", t.Addr, cfg)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.conns[t.Name] = c
	p.mu.Unlock()
	return c, nil
}

func (p *Pool) Drop(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c := p.conns[name]; c != nil {
		c.Close()
		delete(p.conns, name)
	}
}

// Exec runs cmd with stdout and stderr both written to out. It returns the
// remote exit code, 124 on timeout, or 255 with an error if the connection
// failed.
func (p *Pool) Exec(ctx context.Context, t Target, cmd string, out io.Writer) (int, error) {
	c, err := p.client(t)
	if err != nil {
		return ExitConnLost, err
	}
	s, err := c.NewSession()
	if err != nil {
		p.Drop(t.Name)
		return ExitConnLost, err
	}
	defer s.Close()
	w := &syncWriter{w: out}
	s.Stdout, s.Stderr = w, w
	if err := s.Start(cmd); err != nil {
		p.Drop(t.Name)
		return ExitConnLost, err
	}
	done := make(chan error, 1)
	go func() { done <- s.Wait() }()
	select {
	case err = <-done:
		return p.exitCode(t.Name, err)
	case <-ctx.Done():
		_ = s.Signal(ssh.SIGTERM)
		s.Close()
		return ExitTimeout, nil
	}
}

func (p *Pool) exitCode(name string, err error) (int, error) {
	var ee *ssh.ExitError
	switch {
	case err == nil:
		return 0, nil
	case errors.As(err, &ee):
		return ee.ExitStatus(), nil
	default: // includes *ssh.ExitMissingError: the connection went away
		p.Drop(name)
		return ExitConnLost, fmt.Errorf("connection lost: %w", err)
	}
}

type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(b)
}

// Job is a command running in the background on its own session.
type Job struct {
	Name, Cmd string
	Started   time.Time
	sess      *ssh.Session
	done      chan struct{}
	exit      int
	err       error
}

// Start launches cmd in the background; onExit runs when it finishes.
func (p *Pool) Start(t Target, cmd string, out io.Writer, onExit func(exit int, err error)) (*Job, error) {
	c, err := p.client(t)
	if err != nil {
		return nil, err
	}
	s, err := c.NewSession()
	if err != nil {
		p.Drop(t.Name)
		return nil, err
	}
	w := &syncWriter{w: out}
	s.Stdout, s.Stderr = w, w
	if err := s.Start(cmd); err != nil {
		s.Close()
		return nil, err
	}
	j := &Job{Name: t.Name, Cmd: cmd, Started: time.Now(), sess: s, done: make(chan struct{})}
	go func() {
		j.exit, j.err = p.exitCode(t.Name, s.Wait())
		s.Close()
		close(j.done)
		if onExit != nil {
			onExit(j.exit, j.err)
		}
	}()
	return j, nil
}

// Status returns whether the job still runs, and its exit code if not.
func (j *Job) Status() (running bool, exit int) {
	select {
	case <-j.done:
		return false, j.exit
	default:
		return true, 0
	}
}

func (j *Job) Kill() {
	_ = j.sess.Signal(ssh.SIGTERM)
	j.sess.Close()
}

// Get copies a remote file into w, refusing files larger than max bytes.
func (p *Pool) Get(t Target, remote string, w io.Writer, max int64) (int64, error) {
	c, err := p.client(t)
	if err != nil {
		return 0, err
	}
	sc, err := sftp.NewClient(c)
	if err != nil {
		return 0, err
	}
	defer sc.Close()
	f, err := sc.Open(remote)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() > max {
		return 0, fmt.Errorf("remote file is %d bytes, limit is %d", st.Size(), max)
	}
	n, err := io.Copy(w, io.LimitReader(f, max+1))
	if err == nil && n > max {
		err = fmt.Errorf("remote file exceeds limit of %d bytes", max)
	}
	return n, err
}

// Put writes r to a remote file.
func (p *Pool) Put(t Target, r io.Reader, remote string) (int64, error) {
	c, err := p.client(t)
	if err != nil {
		return 0, err
	}
	sc, err := sftp.NewClient(c)
	if err != nil {
		return 0, err
	}
	defer sc.Close()
	f, err := sc.Create(remote)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(f, r)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return n, err
}

// FetchHostKey connects just far enough to learn the server's host key.
func FetchHostKey(addr string) (ssh.PublicKey, error) {
	var key ssh.PublicKey
	errGot := errors.New("got key")
	cfg := &ssh.ClientConfig{
		Timeout: 15 * time.Second,
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			key = k
			return errGot
		},
	}
	c, err := ssh.Dial("tcp", addr, cfg)
	if c != nil {
		c.Close()
	}
	if key == nil {
		return nil, err
	}
	return key, nil
}

// Trust records key for addr in the known_hosts file, replacing any
// previous key for that address.
func Trust(knownHostsFile, addr string, key ssh.PublicKey) error {
	norm := knownhosts.Normalize(addr)
	old, err := os.ReadFile(knownHostsFile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(string(old)), "\n") {
		if f := strings.Fields(l); len(f) > 0 && f[0] != norm {
			out = append(out, l)
		}
	}
	out = append(out, knownhosts.Line([]string{norm}, key))
	return os.WriteFile(knownHostsFile, []byte(strings.Join(out, "\n")+"\n"), 0o600)
}
