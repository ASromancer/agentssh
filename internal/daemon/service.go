package daemon

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ASromancer/agentssh/internal/approval"
	"github.com/ASromancer/agentssh/internal/audit"
	"github.com/ASromancer/agentssh/internal/hosts"
	"github.com/ASromancer/agentssh/internal/paths"
	"github.com/ASromancer/agentssh/internal/policy"
	"github.com/ASromancer/agentssh/internal/sshconn"
)

const (
	DefaultTimeout = 60 * time.Second
	MaxTransfer    = 50 << 20
	headLines      = 40
	tailLines      = 40
	maxLineBytes   = 2000
)

// Service is the RPC surface of the daemon.
type Service struct{ d *Daemon }

// snapshot returns the approved config and engine plus lock state.
func (d *Daemon) snapshot() (*hosts.Config, *policy.Engine, bool, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cfg, d.engine, d.data == nil, d.userOnly
}

func (s *Service) Hosts(a *Env, r *HostsReply) error {
	cfg, _, _, _ := s.d.snapshot()
	repo, err := hosts.FindRepo(a.Cwd)
	if err != nil {
		return err
	}
	for name, p := range cfg.Visible(repo) {
		r.Hosts = append(r.Hosts, HostInfo{name, p, cfg.Hosts[name].Description})
	}
	sort.Slice(r.Hosts, func(i, j int) bool { return r.Hosts[i].Name < r.Hosts[j].Name })
	return nil
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// policyCommand is what gets classified. File transfers are classified as
// the equivalent shell command so the same rules (sensitive paths, system
// paths) apply to them.
func policyCommand(a *ExecArgs) (classify, display string) {
	switch a.Kind {
	case "get":
		return "cat " + shellQuote(a.Remote), fmt.Sprintf("get %s:%s -> %s", a.Host, a.Remote, a.Local)
	case "put":
		return "tee " + shellQuote(a.Remote), fmt.Sprintf("put %s -> %s:%s", a.Local, a.Host, a.Remote)
	}
	return a.Cmd, a.Cmd
}

// localProblem refuses local paths that would leak or tamper with secrets.
func localProblem(eng *policy.Engine, p string) string {
	if !filepath.IsAbs(p) {
		return "local path must be absolute"
	}
	check := []string{filepath.Clean(p)}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		check = append(check, r)
	} else if r, err := filepath.EvalSymlinks(filepath.Dir(p)); err == nil {
		check = append(check, filepath.Join(r, filepath.Base(p)))
	}
	for _, c := range check {
		for _, dir := range []string{paths.Config(), paths.State()} {
			if paths.Within(c, dir) {
				return "local path is inside agentssh's own files"
			}
		}
		if eng.Classify("cat "+shellQuote(c), nil, nil).Level == policy.Forbidden {
			return "local path refers to a sensitive file: " + c
		}
	}
	return ""
}

func reasonSummary(res policy.Result) string {
	var parts []string
	for _, r := range res.Reasons {
		if r.Level == res.Level {
			parts = append(parts, r.Text)
		}
	}
	return strings.Join(parts, "; ")
}

func (s *Service) Exec(a *ExecArgs, r *ExecReply) error {
	d := s.d
	cfg, eng, locked, userOnly := d.snapshot()
	switch {
	case locked:
		r.Code, r.Msg = CodeNoDaemon, "vault is locked; ask the user to run 'agentssh unlock'"
		return nil
	case userOnly:
		r.Code, r.Msg = CodeBlocked, "agentssh config changed on disk and is not approved; ask the user to review it and run 'agentssh reload'"
		return nil
	}
	repo, err := hosts.FindRepo(a.Cwd)
	if err != nil {
		r.Code, r.Msg = CodeBlocked, err.Error()
		return nil
	}
	profile, ok := cfg.Visible(repo)[a.Host]
	if !ok {
		r.Code, r.Msg = CodeBlocked, fmt.Sprintf("host %q is not available to agents here; see 'agentssh hosts'", a.Host)
		return nil
	}
	h := cfg.Hosts[a.Host]
	cmd, display := policyCommand(a)
	res := eng.Classify(cmd, h.Allow, h.Deny)
	if a.Kind == "get" || a.Kind == "put" {
		if p := localProblem(eng, a.Local); p != "" {
			res.Level = policy.Forbidden
			res.Reasons = append(res.Reasons, policy.Reason{Level: policy.Forbidden, Text: p})
		}
	}
	if a.Kind == "put" {
		if fi, err := os.Stat(a.Local); err != nil {
			r.Code, r.Msg = CodeBlocked, err.Error()
			return nil
		} else if fi.Size() > MaxTransfer {
			r.Code, r.Msg = CodeBlocked, fmt.Sprintf("file is %d bytes; limit is %d", fi.Size(), MaxTransfer)
			return nil
		}
	}
	r.Level = res.Level.String()
	repoDir := ""
	if repo != nil {
		repoDir = repo.Dir
	}
	e := audit.Entry{Kind: a.Kind, Agent: a.Agent, Cwd: a.Cwd, Repo: repoDir, Host: a.Host, Cmd: display, Level: r.Level}

	act := policy.Decide(res.Level, profile)
	id := 0
	switch act {
	case policy.Block:
		e.ID, e.Decision, e.Note = newID(), "blocked", reasonSummary(res)
		if res.Level == policy.Forbidden {
			e.Decision = "forbidden"
		}
		d.log.Write(e)
		r.Code = CodeBlocked
		r.Msg = fmt.Sprintf("blocked: level=%s profile=%s: %s", res.Level, profile, reasonSummary(res))
		return nil
	case policy.Approve:
		switch {
		case a.ApprovalID != 0:
			req, dec, ok := d.q.Wait(a.ApprovalID)
			if !ok || req.Host != a.Host || req.Cmd != display || req.Kind != a.Kind {
				r.Code, r.Msg = CodeDenied, "unknown or expired approval request; stop and ask the user"
				return nil
			}
			id = a.ApprovalID
			e.ID, e.CodeOK = id, &dec.CodeOK
			if !dec.OK {
				e.Decision, e.Note = dec.Outcome, dec.Message
				d.log.Write(e)
				r.Code, r.ID = CodeDenied, id
				r.Msg = fmt.Sprintf("request #%d %s; stop and ask the user, do not retry another way", id, dec.Outcome)
				if dec.Message != "" {
					r.Msg += ". User says: " + dec.Message
				}
				return nil
			}
			e.Decision = "approved"
		case d.q.Sticky(a.Host, display):
			id = newID()
			e.Decision, e.Note = "approved", "same command approved within the last 30 minutes"
		default:
			id = newID()
			d.q.Add(approval.Request{ID: id, Time: time.Now(), Host: a.Host, User: h.User, Cwd: a.Cwd,
				Repo: repoDir, Agent: a.Agent, Kind: a.Kind, Cmd: display, Level: r.Level, Reasons: res.Reasons})
			r.Pending, r.ID = id, id
			return nil
		}
	default:
		id = newID()
		e.Decision = "allow"
		if act == policy.Ask {
			e.Note = "mutate under standard profile (soft layer asks via agent hook)"
		}
	}
	e.ID, r.ID = id, id

	t, err := d.target(a.Host, h)
	if err != nil {
		e.Decision, e.Note = "error", err.Error()
		d.log.Write(e)
		r.Code, r.Msg = CodeBlocked, err.Error()
		return nil
	}
	start := time.Now()
	exit, n, err := d.execute(a, t, id, &e)
	e.Exit, e.Bytes, e.DurationMs = &exit, n, time.Since(start).Milliseconds()
	if err != nil {
		e.Note = strings.TrimSpace(e.Note + " " + err.Error())
		r.Msg = err.Error()
	}
	if a.Kind != "job" {
		d.log.Write(e)
	}
	r.Exit, r.DurMs = exit, e.DurationMs
	if a.Kind == "run" {
		r.Output = Summarize(OutPath(id), id)
	}
	return nil
}

func (d *Daemon) target(name string, h *hosts.Host) (sshconn.Target, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	t := sshconn.Target{Name: name, Addr: h.Addr(), User: h.User}
	if d.data == nil {
		return t, errors.New("vault is locked")
	}
	if pem, ok := d.data.Keys[h.Key]; ok {
		signer, err := ssh.ParsePrivateKey(pem)
		if err != nil {
			return t, fmt.Errorf("key %q: %w", h.Key, err)
		}
		t.Auth = ssh.PublicKeys(signer)
	} else if pw, ok := d.data.Passwords[h.Key]; ok {
		t.Auth = ssh.Password(string(pw))
	} else {
		return t, fmt.Errorf("host %s: no key %q in the vault; ask the user to add it", name, h.Key)
	}
	return t, nil
}

func (d *Daemon) execute(a *ExecArgs, t sshconn.Target, id int, e *audit.Entry) (exit int, n int64, err error) {
	switch a.Kind {
	case "run":
		f, err := os.OpenFile(OutPath(id), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return sshconn.ExitConnLost, 0, err
		}
		timeout := a.Timeout
		if timeout <= 0 {
			timeout = DefaultTimeout
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		exit, err = d.pool.Exec(ctx, t, a.Cmd, f)
		if exit == sshconn.ExitTimeout && err == nil && ctx.Err() != nil {
			err = fmt.Errorf("command timed out after %s and was terminated", timeout)
		}
		if fi, serr := f.Stat(); serr == nil {
			n = fi.Size()
		}
		f.Close()
		return exit, n, err
	case "job":
		f, err := os.OpenFile(OutPath(id), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return sshconn.ExitConnLost, 0, err
		}
		entry := *e
		entry.Time = time.Now()
		j, err := d.pool.Start(t, a.Cmd, f, func(exit int, err error) {
			fi, _ := f.Stat()
			f.Close()
			entry.Exit, entry.DurationMs = &exit, time.Since(entry.Time).Milliseconds()
			if fi != nil {
				entry.Bytes = fi.Size()
			}
			if err != nil {
				entry.Note = err.Error()
			}
			d.log.Write(entry)
		})
		if err != nil {
			f.Close()
			d.log.Write(*e)
			return sshconn.ExitConnLost, 0, err
		}
		d.mu.Lock()
		d.jobs[id] = j
		d.mu.Unlock()
		return 0, 0, nil
	case "get":
		f, err := os.OpenFile(a.Local, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return 1, 0, err
		}
		n, err = d.pool.Get(t, a.Remote, f, MaxTransfer)
		f.Close()
		if err != nil {
			return sshconn.ExitConnLost, n, err
		}
		return 0, n, nil
	case "put":
		f, err := os.Open(a.Local)
		if err != nil {
			return 1, 0, err
		}
		defer f.Close()
		n, err = d.pool.Put(t, io.LimitReader(f, MaxTransfer), a.Remote)
		if err != nil {
			return sshconn.ExitConnLost, n, err
		}
		return 0, n, nil
	}
	return 2, 0, fmt.Errorf("unknown kind %q", a.Kind)
}

// readLine reads one line, keeping at most maxLineBytes of it.
func readLine(br *bufio.Reader) (string, bool) {
	var b []byte
	dropped := 0
	for {
		chunk, isPrefix, err := br.ReadLine()
		if err != nil {
			return string(b), len(b) > 0 || dropped > 0
		}
		if room := maxLineBytes - len(b); room > 0 {
			if len(chunk) > room {
				dropped += len(chunk) - room
				chunk = chunk[:room]
			}
			b = append(b, chunk...)
		} else {
			dropped += len(chunk)
		}
		if !isPrefix {
			break
		}
	}
	if dropped > 0 {
		return fmt.Sprintf("%s… [+%d bytes]", b, dropped), true
	}
	return string(b), true
}

// Summarize returns the output file, keeping the first and last 40 lines
// when it is longer than 80 lines.
func Summarize(path string, id int) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	br := bufio.NewReader(f)
	var head, tail []string
	total := 0
	for {
		l, ok := readLine(br)
		if !ok {
			break
		}
		total++
		if len(head) < headLines {
			head = append(head, l)
			continue
		}
		tail = append(tail, l)
		if len(tail) > tailLines {
			tail = tail[1:]
		}
	}
	out := head
	if omitted := total - len(head) - len(tail); omitted > 0 {
		out = append(out, fmt.Sprintf("… %d lines omitted, full: agentssh out %d", omitted, id))
	}
	out = append(out, tail...)
	if len(out) == 0 {
		return ""
	}
	return strings.Join(out, "\n") + "\n"
}

// Tail returns the last n lines of a file.
func Tail(path string, n int) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	br := bufio.NewReader(f)
	var lines []string
	for {
		l, ok := readLine(br)
		if !ok {
			break
		}
		lines = append(lines, l)
		if len(lines) > n {
			lines = lines[1:]
		}
	}
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

func (s *Service) Explain(a *ExplainArgs, r *ExplainReply) error {
	cfg, eng, _, _ := s.d.snapshot()
	var allow, deny []string
	if a.Host != "" {
		r.Host = a.Host
		repo, err := hosts.FindRepo(a.Cwd)
		if err != nil {
			return err
		}
		r.Profile, r.HostOK = cfg.Visible(repo)[a.Host]
		if r.HostOK {
			allow, deny = cfg.Hosts[a.Host].Allow, cfg.Hosts[a.Host].Deny
		}
	}
	r.Result = eng.Classify(a.Cmd, allow, deny)
	if r.HostOK {
		r.Action = policy.Decide(r.Level, r.Profile).String()
	} else if a.Host != "" {
		r.Action, r.Msg = policy.Block.String(), fmt.Sprintf("host %q is not available to agents here", a.Host)
	}
	return nil
}

func (s *Service) job(id int) (*sshconn.Job, error) {
	s.d.mu.Lock()
	defer s.d.mu.Unlock()
	j := s.d.jobs[id]
	if j == nil {
		return nil, fmt.Errorf("no job %d (jobs are lost when the daemon restarts; output may still be in 'agentssh out %d')", id, id)
	}
	return j, nil
}

func (s *Service) JobTail(a *JobArgs, r *JobReply) error {
	j, err := s.job(a.ID)
	if err != nil {
		return err
	}
	if a.Lines <= 0 {
		a.Lines = 20
	}
	r.Running, r.Exit = j.Status()
	r.Output = Tail(OutPath(a.ID), a.Lines)
	return nil
}

func (s *Service) JobKill(a *JobArgs, r *JobReply) error {
	j, err := s.job(a.ID)
	if err != nil {
		return err
	}
	j.Kill()
	return nil
}

func (s *Service) Status(_ *Empty, r *StatusReply) error {
	d := s.d
	d.mu.Lock()
	r.Locked, r.UserOnly = d.data == nil, d.userOnly
	d.mu.Unlock()
	salt, err := vaultSalt()
	r.VaultMissing = err != nil
	r.Passphrase = salt != nil
	r.Pending = len(d.q.Pending())
	return nil
}

func (s *Service) Pending(_ *Empty, r *[]approval.Request) error {
	// Never nil: jsonrpc rejects a null result.
	*r = append([]approval.Request{}, s.d.q.Pending()...)
	sort.Slice(*r, func(i, j int) bool { return (*r)[i].ID < (*r)[j].ID })
	return nil
}

func (s *Service) Decide(a *DecideArgs, _ *Empty) error {
	_, err := s.d.q.Decide(a.ID, a.Code, a.Choice, a.Note)
	return err
}

func (s *Service) Lock(_ *Empty, _ *Empty) error {
	s.d.lock()
	s.d.log.Write(audit.Entry{Kind: "admin", Cmd: "lock", Decision: "allow"})
	return nil
}
