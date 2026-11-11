package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/rpc"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/ASromancer/agentssh/internal/approval"
	"github.com/ASromancer/agentssh/internal/hosts"
	"github.com/ASromancer/agentssh/internal/humanok"
	"github.com/ASromancer/agentssh/internal/paths"
	"github.com/ASromancer/agentssh/internal/sshconn"
	"github.com/ASromancer/agentssh/internal/vault"
)

// testServer is a minimal SSH server that runs exec requests with sh -c
// and serves sftp, accepting only clientKey.
func testServer(t *testing.T, clientKey ssh.PublicKey) (addr string, hostKey ssh.PublicKey) {
	_, hk, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(hk)
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if bytes.Equal(k.Marshal(), clientKey.Marshal()) {
			return nil, nil
		}
		return nil, errors.New("denied")
	}}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, creqs, _ := nc.Accept()
					go serveSession(ch, creqs)
				}
			}()
		}
	}()
	return ln.Addr().String(), signer.PublicKey()
}

// shell runs remote commands in the fake server (Git's sh on Windows).
var shell = func() string {
	for _, s := range []string{"sh", "bash"} {
		if p, err := exec.LookPath(s); err == nil {
			return p
		}
	}
	return ""
}()

func serveSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for req := range reqs {
		switch req.Type {
		case "exec":
			n := binary.BigEndian.Uint32(req.Payload)
			cmd := exec.Command(shell, "-c", string(req.Payload[4:4+n]))
			cmd.Stdout, cmd.Stderr = ch, ch.Stderr()
			req.Reply(true, nil)
			cmd.Start()
			go func() {
				for r := range reqs {
					if r.Type == "signal" && cmd.Process != nil {
						cmd.Process.Kill()
					}
				}
			}()
			code := 0
			if err := cmd.Wait(); err != nil {
				code = 1
				if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() >= 0 {
					code = ee.ExitCode()
				}
			}
			ch.SendRequest("exit-status", false, binary.BigEndian.AppendUint32(nil, uint32(code)))
			return
		case "subsystem":
			req.Reply(true, nil)
			srv, _ := sftp.NewServer(ch)
			srv.Serve()
			return
		default:
			req.Reply(false, nil)
		}
	}
}

type harness struct {
	t      *testing.T
	c      *rpc.Client
	d      *Daemon
	mu     sync.Mutex
	notes  []string
	tmp    string
	remote string
}

func (h *harness) notify(n approval.Notice) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.notes = append(h.notes, n.Body)
	return nil
}

// useHuman swaps the confirmer and decides the mode again, as a daemon
// start would.
func (h *harness) useHuman(c humanok.Confirmer) {
	h.d.human = c
	h.d.pickAuth()
}

func (h *harness) lastCode() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := h.notes[len(h.notes)-1]
	return n[strings.LastIndex(n, " ")+1:]
}

func (h *harness) call(method string, args, reply any) error {
	return h.c.Call("A."+method, args, reply)
}

func (h *harness) exec(a ExecArgs) ExecReply {
	h.t.Helper()
	if a.Agent == "" {
		a.Agent = AgentClaude
	}
	a.Env = Env{Cwd: h.tmp, Agent: a.Agent}
	if a.Kind == "" {
		a.Kind = "run"
	}
	if a.Host == "" {
		a.Host = "web1"
	}
	var r ExecReply
	if err := h.call("Exec", &a, &r); err != nil {
		h.t.Fatal(err)
	}
	return r
}

func setup(t *testing.T) *harness {
	if shell == "" {
		t.Skip("no sh/bash to act as the remote shell")
	}
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, "cfg"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(tmp, "state"))
	sockBase := "/tmp" // short: unix socket paths are limited to ~104 bytes
	if runtime.GOOS == "windows" {
		sockBase = ""
	}
	sockDir, _ := os.MkdirTemp(sockBase, "agentssh-test")
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	t.Setenv("AGENTSSH_SOCKET", filepath.Join(sockDir, "s"))

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)
	addr, hostKey := testServer(t, sshPub)
	host, port, _ := net.SplitHostPort(addr)

	os.MkdirAll(paths.Config(), 0o700)
	os.WriteFile(paths.Hosts(), []byte(fmt.Sprintf(`
[hosts.web1]
host = %q
port = %s
user = "test"
key = "k1"
agent = true
[hosts.hidden]
host = "127.0.0.1"
key = "k1"
`, host, port)), 0o600)
	if err := sshconn.Trust(paths.KnownHosts(), addr, hostKey); err != nil {
		t.Fatal(err)
	}
	block, _ := ssh.MarshalPrivateKey(priv, "")
	salt := vault.NewSalt()
	if err := vault.Save(paths.Vault(), vault.DeriveKey([]byte("pw"), salt), salt,
		&vault.Data{Keys: map[string][]byte{"k1": pem.EncodeToMemory(block)}, ConfigHash: ConfigHash()}); err != nil {
		t.Fatal(err)
	}

	// Remote paths go through sh: forward slashes work on Windows too.
	h := &harness{t: t, tmp: tmp, remote: filepath.ToSlash(t.TempDir())}
	d, err := New(h.notify, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	h.d = d
	h.useHuman(&humanok.Fake{Err: humanok.ErrUnavailable}) // stay in code mode even where polkit exists
	ln, err := net.Listen("unix", paths.Socket())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go d.ServeListener(ln)
	if h.c, err = Dial(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.c.Close() })
	return h
}

func TestDaemonEndToEnd(t *testing.T) {
	h := setup(t)

	var none []approval.Request
	if err := h.call("Pending", &Empty{}, &none); err != nil || len(none) != 0 {
		t.Fatalf("empty pending list: %v %v", none, err)
	}

	// Locked vault: 102.
	if r := h.exec(ExecArgs{Cmd: "echo hi"}); r.Code != CodeNoDaemon {
		t.Fatalf("locked: %+v", r)
	}
	if err := h.call("Unlock", &UnlockArgs{Pass: "wrong"}, &Empty{}); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	if err := h.call("Unlock", &UnlockArgs{Pass: "pw"}, &Empty{}); err != nil {
		t.Fatal(err)
	}

	var hr HostsReply
	h.call("Hosts", &Env{Cwd: h.tmp}, &hr)
	if len(hr.Hosts) != 1 || hr.Hosts[0].Name != "web1" || hr.Hosts[0].Profile != "standard" {
		t.Fatalf("hosts: %+v", hr)
	}
	var hl HostListReply
	if err := h.call("HostList", &Empty{}, &hl); err != nil {
		t.Fatal(err)
	}
	if len(hl.Hosts) != 2 || hl.Hosts["hidden"].Agent || !hl.Hosts["web1"].Agent || !hl.Trusted["web1"] || hl.Trusted["hidden"] {
		t.Fatalf("host list: %+v", hl)
	}
	if h.d.Service() == nil {
		t.Fatal("Service accessor")
	}

	r := h.exec(ExecArgs{Cmd: "echo hello"})
	if r.Code != 0 || r.Exit != 0 || r.Output != "hello\n" || r.Level != "read" {
		t.Fatalf("read: %+v", r)
	}
	if r := h.exec(ExecArgs{Cmd: "sh -c 'exit 3'"}); r.Exit != 3 || r.Code != 0 {
		t.Fatalf("exit code: %+v", r)
	}
	// Without Claude Code's soft ask, mutate on a standard host needs approval.
	if r := h.exec(ExecArgs{Env: Env{Agent: "codex"}, Cmd: "sh -c 'exit 3'"}); r.Pending == 0 {
		t.Fatalf("mutate from codex should need approval: %+v", r)
	}
	if r := h.exec(ExecArgs{Cmd: "seq 1 200"}); !strings.Contains(r.Output, "120 lines omitted") ||
		!strings.HasPrefix(r.Output, "1\n") || !strings.HasSuffix(r.Output, "200\n") {
		t.Fatalf("summary: %q", r.Output)
	}
	if r := h.exec(ExecArgs{Cmd: "cat ~/.ssh/id_rsa"}); r.Code != CodeBlocked {
		t.Fatalf("forbidden: %+v", r)
	}
	if r := h.exec(ExecArgs{Host: "hidden", Cmd: "ls"}); r.Code != CodeBlocked {
		t.Fatalf("hidden host: %+v", r)
	}
	if r := h.exec(ExecArgs{Cmd: "sleep 5", Timeout: 200 * time.Millisecond}); r.Exit != sshconn.ExitTimeout {
		t.Fatalf("timeout: %+v", r)
	}

	// Destructive: pending, approve with the notified code, then it runs.
	victim := h.remote + "/victim"
	os.WriteFile(victim, []byte("x"), 0o600)
	rm := ExecArgs{Cmd: "rm " + victim}
	r = h.exec(rm)
	if r.Pending == 0 {
		t.Fatalf("expected pending: %+v", r)
	}
	if err := h.call("Decide", &DecideArgs{ID: r.Pending, Code: "XXXX", Choice: "y"}, &Empty{}); err == nil {
		t.Fatal("bad code accepted")
	}
	if err := h.call("Decide", &DecideArgs{ID: r.Pending, Code: h.lastCode(), Choice: "s"}, &Empty{}); err != nil {
		t.Fatal(err)
	}
	rm.ApprovalID = r.Pending
	if r := h.exec(rm); r.Code != 0 || r.Exit != 0 {
		t.Fatalf("approved run: %+v", r)
	}
	if _, err := os.Stat(victim); !os.IsNotExist(err) {
		t.Fatal("rm did not run")
	}
	// Sticky approval covers the identical command only.
	if r := h.exec(ExecArgs{Cmd: "rm " + victim}); r.Pending != 0 || r.Exit == 0 {
		t.Fatalf("sticky: %+v", r)
	}
	if r := h.exec(ExecArgs{Cmd: "rm -f " + victim}); r.Pending == 0 {
		t.Fatalf("sticky leaked to another command: %+v", r)
	}

	// Denial with a message.
	r = h.exec(ExecArgs{Cmd: "rm -rf /tmp/nothing-here"})
	h.call("Decide", &DecideArgs{ID: r.Pending, Code: h.lastCode(), Choice: "m", Note: "not now"}, &Empty{})
	if r2 := h.exec(ExecArgs{Cmd: "rm -rf /tmp/nothing-here", ApprovalID: r.Pending}); r2.Code != CodeDenied || !strings.Contains(r2.Msg, "not now") {
		t.Fatalf("denied: %+v", r2)
	}

	// Transfers.
	local := filepath.Join(h.tmp, "up.txt")
	os.WriteFile(local, []byte("payload"), 0o600)
	remote := h.remote + "/up.txt"
	if r := h.exec(ExecArgs{Kind: "put", Local: local, Remote: remote}); r.Code != 0 || r.Exit != 0 {
		t.Fatalf("put: %+v", r)
	}
	back := filepath.Join(h.tmp, "back.txt")
	if r := h.exec(ExecArgs{Kind: "get", Local: back, Remote: remote}); r.Code != 0 || r.Exit != 0 {
		t.Fatalf("get: %+v", r)
	}
	if b, _ := os.ReadFile(back); string(b) != "payload" {
		t.Fatalf("roundtrip: %q", b)
	}
	if r := h.exec(ExecArgs{Kind: "put", Local: paths.Vault(), Remote: remote}); r.Code != CodeBlocked {
		t.Fatalf("vault upload: %+v", r)
	}

	// Jobs.
	r = h.exec(ExecArgs{Kind: "job", Cmd: "sleep 0.2; echo done"})
	if r.Code != 0 {
		t.Fatalf("job: %+v", r)
	}
	var jr JobReply
	for i := 0; i < 50; i++ {
		h.call("JobTail", &JobArgs{ID: r.ID}, &jr)
		if !jr.Running {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if jr.Running || jr.Output != "done\n" {
		t.Fatalf("job tail: %+v", jr)
	}

	// Admin: key generation needs the notified code.
	var br BeginReply
	if err := h.call("Begin", &BeginArgs{Op: "key-gen", Name: "k2"}, &br); err != nil {
		t.Fatal(err)
	}
	var ar AdminReply
	if err := h.call("Admin", &AdminArgs{Ticket: br.Ticket, Code: "ZZZZ", Op: "key-gen", Name: "k2"}, &ar); err == nil {
		t.Fatal("bad admin code accepted")
	}
	if err := h.call("Admin", &AdminArgs{Ticket: br.Ticket, Code: h.lastCode(), Op: "key-gen", Name: "k2"}, &ar); err != nil ||
		!strings.HasPrefix(ar.Out, "ssh-ed25519 ") {
		t.Fatalf("key-gen: %v %q", err, ar.Out)
	}

	// Config edited behind the daemon's back: agent requests refused after
	// the next unlock until the user reloads with a code.
	f, _ := os.OpenFile(paths.Hosts(), os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("\n[hosts.hidden2]\nhost = \"x\"\nagent = true\n")
	f.Close()
	h.call("Lock", &Empty{}, &Empty{})
	h.call("Unlock", &UnlockArgs{Pass: "pw"}, &Empty{})
	if r := h.exec(ExecArgs{Cmd: "echo hi"}); r.Code != CodeBlocked {
		t.Fatalf("userOnly: %+v", r)
	}
	h.call("Begin", &BeginArgs{Op: "reload"}, &br)
	if err := h.call("Admin", &AdminArgs{Ticket: br.Ticket, Code: h.lastCode(), Op: "reload"}, &ar); err != nil {
		t.Fatal(err)
	}
	if r := h.exec(ExecArgs{Cmd: "echo hi"}); r.Code != 0 {
		t.Fatalf("after reload: %+v", r)
	}

	// Audit has entries and no command output.
	b, _ := os.ReadFile(paths.Audit())
	if !bytes.Contains(b, []byte(`"decision":"approved"`)) || bytes.Contains(b, []byte("payload")) {
		t.Fatalf("audit:\n%s", b)
	}
}

func TestOSAuth(t *testing.T) {
	h := setup(t)
	fake := &humanok.Fake{Allow: false}
	h.useHuman(fake)
	if err := h.call("Unlock", &UnlockArgs{Pass: "pw"}, &Empty{}); err != nil {
		t.Fatal(err)
	}
	var st StatusReply
	h.call("Status", &Empty{}, &st)
	if st.Auth != "os" {
		t.Fatalf("status auth %q", st.Auth)
	}

	victim := h.remote + "/osauth"
	os.WriteFile(victim, []byte("x"), 0o600)
	rm := ExecArgs{Cmd: "rm " + victim}
	r := h.exec(rm)
	if r.Pending == 0 {
		t.Fatalf("expected pending: %+v", r)
	}
	h.mu.Lock()
	note := h.notes[len(h.notes)-1]
	h.mu.Unlock()
	if strings.Contains(note, "code:") {
		t.Fatal("notification carries a code in OS-auth mode")
	}
	// The OS dialog is refused: still pending, nothing ran.
	if err := h.call("Decide", &DecideArgs{ID: r.Pending, Choice: "y"}, &Empty{}); err == nil {
		t.Fatal("approved without OS authentication")
	}
	if msgs := fake.Msgs(); len(msgs) != 1 || msgs[0] != fmt.Sprintf("[DESTRUCTIVE] approve #%d on web1: rm %s", r.Pending, victim) {
		t.Fatalf("dialog text %q", msgs)
	}
	// A deny-with-message reaches the agent, so it needs proof too.
	if err := h.call("Decide", &DecideArgs{ID: r.Pending, Choice: "m", Note: "use logrotate"}, &Empty{}); err == nil {
		t.Fatal("message decision without OS authentication")
	}
	if m := fake.Msgs()[1]; m != fmt.Sprintf(`[DESTRUCTIVE] deny #%d on web1 with a message to the agent: rm %s — message: "use logrotate"`, r.Pending, victim) {
		t.Fatalf("m dialog text %q", m)
	}
	if p := h.d.q.Pending(); len(p) != 1 {
		t.Fatalf("request not pending after refused m: %v", p)
	}
	if err := h.call("Decide", &DecideArgs{ID: r.Pending, Choice: "q"}, &Empty{}); err == nil {
		t.Fatal("unknown choice accepted")
	}
	fake.Allow = true
	if err := h.call("Decide", &DecideArgs{ID: r.Pending, Choice: "y"}, &Empty{}); err != nil {
		t.Fatal(err)
	}
	rm.ApprovalID = r.Pending
	if r := h.exec(rm); r.Exit != 0 || r.Code != 0 {
		t.Fatalf("run after OS approval: %+v", r)
	}

	// Denial needs no authentication.
	before := len(fake.Msgs())
	never := ExecArgs{Cmd: "rm -rf /tmp/never"}
	r = h.exec(never)
	if err := h.call("Decide", &DecideArgs{ID: r.Pending, Choice: "n"}, &Empty{}); err != nil || len(fake.Msgs()) != before {
		t.Fatalf("deny: %v, dialogs %d", err, len(fake.Msgs())-before)
	}
	never.ApprovalID = r.Pending
	if r := h.exec(never); r.Code != CodeDenied {
		t.Fatalf("denied run: %+v", r)
	}

	// Admin without a code.
	var br BeginReply
	h.call("Begin", &BeginArgs{Op: "key-gen", Name: "os1"}, &br)
	var ar AdminReply
	if !br.OSAuth {
		t.Fatal("Begin did not report OS auth")
	}
	if err := h.call("Admin", &AdminArgs{Ticket: br.Ticket, Op: "key-gen", Name: "os1"}, &ar); err != nil || !strings.HasPrefix(ar.Out, "ssh-ed25519 ") {
		t.Fatalf("admin: %v %q", err, ar.Out)
	}
	if last := fake.Msgs()[len(fake.Msgs())-1]; !strings.Contains(last, "key-gen os1") {
		t.Fatalf("admin dialog %q", last)
	}
	// host-set shows every field that takes effect.
	host := &hosts.Host{Host: "10.0.0.9", User: "deploy", Key: "k1", Agent: true, Profile: "full",
		Allow: []string{"systemctl restart *"}, Deny: []string{"psql *"}}
	h.call("Begin", &BeginArgs{Op: "host-set", Name: "web2"}, &br)
	if err := h.call("Admin", &AdminArgs{Ticket: br.Ticket, Op: "host-set", Name: "web2", Host: host}, &ar); err != nil {
		t.Fatal(err)
	}
	want := `save host web2 (deploy@10.0.0.9:22, profile full, agent access true, key=k1, allow=["systemctl restart *"], deny=["psql *"])`
	if last := fake.Msgs()[len(fake.Msgs())-1]; last != want {
		t.Fatalf("host-set dialog %q", last)
	}

	b, _ := os.ReadFile(paths.Audit())
	var runOS, denyNone bool
	for _, l := range bytes.Split(b, []byte("\n")) {
		runOS = runOS || bytes.Contains(l, []byte(`"kind":"run"`)) && bytes.Contains(l, []byte(`"auth":"os"`))
		denyNone = denyNone || bytes.Contains(l, []byte(`rm -rf /tmp/never`)) && bytes.Contains(l, []byte(`"auth":"none"`))
	}
	if !runOS || !denyNone || !bytes.Contains(b, []byte(`"kind":"admin"`)) {
		t.Fatalf("audit lacks run auth=os / deny auth=none:\n%s", b)
	}
}

func TestDialogText(t *testing.T) {
	const blank = "confirm an agentssh action"
	pad := "[DESTRUCTIVE] approve on h: ls" + strings.Repeat(" ", 1500) + "; rm -rf ~"
	got := dialogText(pad)
	if got != "[DESTRUCTIVE] approve on h: ls ; rm -rf ~" {
		t.Errorf("padding attack: %q", got)
	}
	long := "[DESTRUCTIVE] approve on h: " + strings.Repeat("x", 2000) + "; rm -rf ~"
	got = dialogText(long)
	if !strings.HasSuffix(got, "; rm -rf ~") || !strings.HasPrefix(got, "[DESTRUCTIVE]") || !strings.Contains(got, " bytes hidden ") || len(got) > 1000 {
		t.Errorf("long: %q", got)
	}
	m := "a" + strings.Repeat("é", 600) // 1201 bytes
	want := "a" + strings.Repeat("é", 249) + " … 302 bytes hidden … " + strings.Repeat("é", 200)
	if got := dialogText(m); got != want {
		t.Errorf("multibyte: %q", got)
	}
	for _, c := range []struct{ in, want string }{
		{"hello", "hello"},
		{"", blank},
		{" \t\n\r", blank},
		{"\x00\x00", blank},
		{"a\x00b", "ab"},
		{"a\xffb", "a\uFFFDb"},
		{"a\nb\r\nc\td", "a b c d"},
		{"ls\u202e txt.exe", "ls txt.exe"},
		{"r\u200bm", "rm"},
		{"a\u0085b\x1bc", "a b c"},
		{"r\u061cm", "rm"},
		{"r\u00adm", "rm"},
		{"a\u3164b\u2800c\u2066d", "abcd"},
	} {
		if got := dialogText(c.in); got != c.want {
			t.Errorf("dialogText(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// blocker is a confirmer whose dialog stays open until release is closed.
type blocker struct{ started, release chan struct{} }

func (b *blocker) Available() error { return nil }
func (b *blocker) Confirm(context.Context, string) error {
	b.started <- struct{}{}
	<-b.release
	return nil
}

func TestConfirmOneAtATime(t *testing.T) {
	b := &blocker{started: make(chan struct{}), release: make(chan struct{})}
	d := &Daemon{human: b}
	first := make(chan error)
	go func() { first <- d.confirm("first") }()
	<-b.started
	if err := d.confirm("second"); err == nil || err.Error() != "another confirmation is already in progress; finish it first" {
		t.Fatalf("second dialog while the first is open: %v", err)
	}
	close(b.release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	go func() { <-b.started }()
	if err := d.confirm("third"); err != nil {
		t.Fatalf("dialog after the first closed: %v", err)
	}
}

func TestOSAuthBreaksDecide(t *testing.T) {
	h := setup(t)
	fake := &humanok.Fake{ConfirmErr: fmt.Errorf("%w: no polkit authentication agent", humanok.ErrUnavailable)}
	h.useHuman(fake)
	h.call("Unlock", &UnlockArgs{Pass: "pw"}, &Empty{})
	victim := h.remote + "/broken"
	os.WriteFile(victim, []byte("x"), 0o600)
	r := h.exec(ExecArgs{Cmd: "rm " + victim})
	if r.Pending == 0 {
		t.Fatalf("expected pending: %+v", r)
	}
	err := h.call("Decide", &DecideArgs{ID: r.Pending, Choice: "y"}, &Empty{})
	if err == nil || !strings.Contains(err.Error(), "no polkit authentication agent") ||
		!strings.Contains(err.Error(), "agentssh doctor") || !strings.Contains(err.Error(), "AGENTSSH_OS_AUTH=0") {
		t.Fatalf("decide: %v", err)
	}
	var st StatusReply
	h.call("Status", &Empty{}, &st)
	if st.Auth != "os" {
		t.Fatalf("mode changed after a broken dialog: %+v", st)
	}
	if p := h.d.q.Pending(); len(p) != 1 || p[0].Code != "" {
		t.Fatalf("request not pending, or a code appeared: %+v", p)
	}
	h.mu.Lock()
	for _, n := range h.notes {
		if strings.Contains(n, "code:") {
			t.Fatalf("a code was sent: %q", n)
		}
	}
	h.mu.Unlock()
	if err := h.call("Decide", &DecideArgs{ID: r.Pending, Choice: "n"}, &Empty{}); err != nil {
		t.Fatalf("deny after a broken dialog: %v", err)
	}
}

func TestOSAuthBreaksAdmin(t *testing.T) {
	h := setup(t)
	h.useHuman(&humanok.Fake{ConfirmErr: humanok.ErrUnavailable})
	h.call("Unlock", &UnlockArgs{Pass: "pw"}, &Empty{})
	var br BeginReply
	var ar AdminReply
	h.call("Begin", &BeginArgs{Op: "key-gen", Name: "k9"}, &br)
	if !br.OSAuth || br.Code != "" {
		t.Fatalf("expected OS mode: %+v", br)
	}
	err := h.call("Admin", &AdminArgs{Ticket: br.Ticket, Op: "key-gen", Name: "k9"}, &ar)
	if err == nil || !strings.Contains(err.Error(), "AGENTSSH_OS_AUTH=0") {
		t.Fatalf("admin: %v", err)
	}
	h.call("Begin", &BeginArgs{Op: "key-gen", Name: "k9"}, &br)
	if !br.OSAuth || br.Code != "" {
		t.Fatalf("left OS mode after a broken dialog: %+v", br)
	}
}

// The mode is decided at start and on an approved reload only: whatever
// an agent does to the session afterwards cannot switch it.
func TestAuthModeDecidedOnce(t *testing.T) {
	h := setup(t)
	fake := &humanok.Fake{Allow: true}
	h.useHuman(fake)
	fake.Err = humanok.ErrUnavailable // e.g. the display socket was renamed
	var st StatusReply
	if h.call("Status", &Empty{}, &st); st.Auth != "os" || !h.d.osAuth() {
		t.Fatalf("OS mode lost after start: %+v", st)
	}

	h.useHuman(&humanok.Fake{Err: fmt.Errorf("%w: polkit action not installed", humanok.ErrUnavailable)})
	if h.call("Status", &Empty{}, &st); st.Auth != "code" || !strings.Contains(st.AuthNote, "polkit action not installed") {
		t.Fatalf("status %+v", st)
	}
	h.d.human.(*humanok.Fake).Err = nil // the human fixed polkit
	if h.d.osAuth() {
		t.Fatal("mode changed without a reload")
	}
	h.call("Unlock", &UnlockArgs{Pass: "pw"}, &Empty{})
	var br BeginReply
	var ar AdminReply
	h.call("Begin", &BeginArgs{Op: "reload"}, &br)
	if err := h.call("Admin", &AdminArgs{Ticket: br.Ticket, Op: "reload", Code: h.lastCode()}, &ar); err != nil {
		t.Fatal(err)
	}
	if h.call("Status", &Empty{}, &st); st.Auth != "os" || !strings.Contains(ar.Out, "OS authentication") {
		t.Fatalf("approved reload did not pick OS mode: %+v %q", st, ar.Out)
	}
}

func TestOSAuthOff(t *testing.T) {
	for _, c := range []struct {
		goos, env string
		on        bool
	}{
		{"linux", "", true}, {"linux", "1", true}, {"linux", "0", false},
		{"darwin", "", false}, {"darwin", "1", true}, {"darwin", "0", false},
		{"windows", "", false}, {"windows", "1", true}, {"windows", "yes", false},
	} {
		if why := osAuthOff(c.goos, c.env); (why == "") != c.on {
			t.Errorf("%s AGENTSSH_OS_AUTH=%q: %q", c.goos, c.env, why)
		}
	}
	if err := authOff(osAuthOff("darwin", "")).Available(); !errors.Is(err, humanok.ErrUnavailable) ||
		!strings.Contains(err.Error(), "set AGENTSSH_OS_AUTH=1") {
		t.Fatalf("%v", err)
	}
}

func TestDialogTimeoutKeepsOSMode(t *testing.T) {
	h := setup(t)
	h.useHuman(&humanok.Fake{ConfirmErr: fmt.Errorf("%w: timed out", humanok.ErrDenied)})
	if err := h.d.confirm("x"); !errors.Is(err, humanok.ErrDenied) {
		t.Fatalf("got %v", err)
	}
	var st StatusReply
	h.call("Status", &Empty{}, &st)
	if st.Auth != "os" {
		t.Fatalf("status %+v", st)
	}
}

// An approved reload can switch codes to OS authentication, never back.
func TestReloadNeverDowngrades(t *testing.T) {
	h := setup(t)
	fake := &humanok.Fake{Allow: true}
	h.useHuman(fake)
	fake.Err = fmt.Errorf("%w: Wayland display gone", humanok.ErrUnavailable)
	h.call("Unlock", &UnlockArgs{Pass: "pw"}, &Empty{})
	var br BeginReply
	var ar AdminReply
	h.call("Begin", &BeginArgs{Op: "reload"}, &br)
	if err := h.call("Admin", &AdminArgs{Ticket: br.Ticket, Op: "reload"}, &ar); err != nil {
		t.Fatal(err)
	}
	var st StatusReply
	if h.call("Status", &Empty{}, &st); st.Auth != "os" || !strings.Contains(ar.Out, "Wayland display gone") {
		t.Fatalf("reload downgraded or hid the reason: %+v %q", st, ar.Out)
	}
}

func TestRunning(t *testing.T) {
	base := "/tmp" // short: unix socket paths are limited to ~104 bytes
	if runtime.GOOS == "windows" {
		base = ""
	}
	dir, _ := os.MkdirTemp(base, "agentssh-run")
	t.Cleanup(func() { os.RemoveAll(dir) })
	t.Setenv("AGENTSSH_SOCKET", filepath.Join(dir, "s"))
	if Running() {
		t.Fatal("running with no socket")
	}
	ln, err := net.Listen("unix", filepath.Join(dir, "s"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	if !Running() {
		t.Fatal("not running with a listener")
	}
}
