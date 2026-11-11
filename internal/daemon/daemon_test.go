package daemon

import (
	"bytes"
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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

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

func serveSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for req := range reqs {
		switch req.Type {
		case "exec":
			n := binary.BigEndian.Uint32(req.Payload)
			cmd := exec.Command("sh", "-c", string(req.Payload[4:4+n]))
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

func (h *harness) notify(_, body string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.notes = append(h.notes, body)
	return nil
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
	a.Env = Env{Cwd: h.tmp, Agent: "test"}
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
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, "cfg"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(tmp, "state"))
	sockDir, _ := os.MkdirTemp("/tmp", "agentssh-test")
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

	h := &harness{t: t, tmp: tmp, remote: t.TempDir()}
	d, err := New(h.notify, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	h.d = d
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

	r := h.exec(ExecArgs{Cmd: "echo hello"})
	if r.Code != 0 || r.Exit != 0 || r.Output != "hello\n" || r.Level != "read" {
		t.Fatalf("read: %+v", r)
	}
	if r := h.exec(ExecArgs{Cmd: "sh -c 'exit 3'"}); r.Exit != 3 || r.Code != 0 {
		t.Fatalf("exit code: %+v", r)
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
	victim := filepath.Join(h.remote, "victim")
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
	remote := filepath.Join(h.remote, "up.txt")
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
