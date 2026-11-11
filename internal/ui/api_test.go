package ui

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ASromancer/agentssh/internal/approval"
	"github.com/ASromancer/agentssh/internal/paths"
)

const apiHost, apiOrigin = "127.0.0.1:8123", "http://127.0.0.1:8123"

func api(t *testing.T, s *Server, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	ct := ""
	if method != "GET" {
		ct = "application/json"
	}
	return do(t, s, method, target, apiHost, apiOrigin, session(t, s), ct, body)
}

var sessions sync.Map // *Server -> session cookie

func session(t *testing.T, s *Server) string {
	if v, ok := sessions.Load(s); ok {
		return v.(string)
	}
	v := login(t, s)
	sessions.Store(s, v)
	return v
}

func TestAPIDecideAndAdmin(t *testing.T) {
	f := &fakeBackend{pending: []approval.Request{{ID: 5, Host: "web1", Cmd: "rm x", Level: "destructive"}}}
	s := newServer(Options{Backend: f, Version: "9.9"}, 8123)

	if w := api(t, s, "GET", "/api/pending", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"cmd":"rm x"`) {
		t.Fatalf("pending: %d %s", w.Code, w.Body.String())
	}
	if w := api(t, s, "POST", "/api/decide", `{"id":5,"choice":"y"}`); w.Code != 200 || len(f.decided) != 1 || f.decided[0].ID != 5 || f.decided[0].Choice != "y" {
		t.Fatalf("decide: %d %+v", w.Code, f.decided)
	}
	f.failAll = true
	if w := api(t, s, "POST", "/api/decide", `{"id":5,"choice":"y"}`); w.Code != 400 || !strings.Contains(w.Body.String(), "not confirmed") {
		t.Fatalf("decide error: %d %s", w.Code, w.Body.String())
	}
	if w := api(t, s, "GET", "/api/status", ""); !strings.Contains(w.Body.String(), `"version":"9.9"`) || !strings.Contains(w.Body.String(), `"Auth":"os"`) {
		t.Fatalf("status: %s", w.Body.String())
	}
	if w := api(t, s, "POST", "/api/admin/begin", `{"op":"trust","name":"web1"}`); !strings.Contains(w.Body.String(), `"Ticket":77`) {
		t.Fatalf("begin: %s", w.Body.String())
	}
	w := api(t, s, "POST", "/api/admin/commit", `{"ticket":77,"op":"host-set","name":"web2","host":{"host":"10.0.0.9","user":"root","agent":true}}`)
	if w.Code != 200 || len(f.admin) != 1 || f.admin[0].Host == nil || f.admin[0].Host.Host != "10.0.0.9" || f.admin[0].Ticket != 77 {
		t.Fatalf("commit host: %d %s %+v", w.Code, w.Body.String(), f.admin)
	}
	if w := api(t, s, "POST", "/api/unlock", `{"pass":"bad"}`); w.Code != 400 {
		t.Fatalf("unlock bad: %d", w.Code)
	}
	if w := api(t, s, "GET", "/api/hosts", ""); !strings.Contains(w.Body.String(), `"web1"`) {
		t.Fatalf("hosts: %s", w.Body.String())
	}
}

func TestAPIKeyImportConvertsEncryptedKey(t *testing.T) {
	f := &fakeBackend{}
	s := newServer(Options{Backend: f}, 8123)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKeyWithPassphrase(priv, "c", []byte("kp"))
	body, _ := json.Marshal(map[string]any{"ticket": 1, "op": "key-import", "name": "k", "key": string(pem.EncodeToMemory(block)), "keyPassphrase": "kp"})
	if w := api(t, s, "POST", "/api/admin/commit", string(body)); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if len(f.admin) != 1 {
		t.Fatal("no admin call")
	}
	if _, err := ssh.ParsePrivateKey(f.admin[0].PEM); err != nil {
		t.Fatalf("daemon received a key it cannot parse without passphrase: %v", err)
	}
	body, _ = json.Marshal(map[string]any{"ticket": 1, "op": "key-import", "name": "k", "key": string(pem.EncodeToMemory(block)), "keyPassphrase": "wrong"})
	if w := api(t, s, "POST", "/api/admin/commit", string(body)); w.Code != 400 {
		t.Fatalf("wrong passphrase accepted: %d", w.Code)
	}
}

func TestAPIAuditAndOutput(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", dir)
	auditFile := filepath.Join(dir, "audit.jsonl")
	os.WriteFile(auditFile, []byte(strings.Join([]string{
		`{"time":"2026-11-10T10:00:00Z","id":1,"kind":"run","host":"web1","cmd":"ls","decision":"allow"}`,
		`{"time":"2026-11-11T10:00:00Z","id":2,"kind":"run","host":"db","cmd":"rm x","decision":"denied"}`,
		`{"time":"2026-11-11T11:00:00Z","id":3,"kind":"run","host":"web1","cmd":"df","decision":"allow"}`,
		`not json`,
		`{"time":"2026-11-11T12:00:00Z","id":9,"kind":"run","host":"web1","cmd":"` + strings.Repeat("x", 5<<20) + `","decision":"allow"}`,
	}, "\n")+"\n"), 0o600)
	os.MkdirAll(paths.Out(), 0o700)
	os.WriteFile(filepath.Join(paths.Out(), "3"), []byte("x\nerror y\n"), 0o600)
	s := newServer(Options{Backend: &fakeBackend{}, AuditFile: auditFile}, 8123)

	var r struct {
		Entries []struct{ ID int } `json:"entries"`
		Total   int                `json:"total"`
	}
	json.Unmarshal(api(t, s, "GET", "/api/audit?host=web1", "").Body.Bytes(), &r)
	if r.Total != 2 || len(r.Entries) != 2 || r.Entries[0].ID != 3 {
		t.Fatalf("host filter, newest first: %+v", r)
	}
	json.Unmarshal(api(t, s, "GET", "/api/audit?since=2026-11-11&decision=denied", "").Body.Bytes(), &r)
	if r.Total != 1 || r.Entries[0].ID != 2 {
		t.Fatalf("since+decision: %+v", r)
	}
	json.Unmarshal(api(t, s, "GET", "/api/audit?limit=1&offset=1", "").Body.Bytes(), &r)
	if r.Total != 3 || len(r.Entries) != 1 || r.Entries[0].ID != 2 {
		t.Fatalf("paging: %+v", r)
	}
	if w := api(t, s, "GET", "/api/audit?offset=-1", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"total":3`) {
		t.Fatalf("negative offset: %d %s", w.Code, w.Body.String())
	}
	if w := api(t, s, "GET", "/api/out/0", ""); w.Code != 400 {
		t.Fatalf("id 0: %d", w.Code)
	}
	if w := api(t, s, "GET", "/api/out/3?grep=error", ""); !strings.Contains(w.Body.String(), `2: error y`) {
		t.Fatalf("out: %s", w.Body.String())
	}
}

func TestEvents(t *testing.T) {
	f := &fakeBackend{}
	s := newServer(Options{Backend: f}, 8123)
	ts := httptest.NewServer(s.handler())
	defer ts.Close()
	lr, _ := http.NewRequest("GET", ts.URL+loginPath(s), nil)
	lr.Host = apiHost
	nf := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	lresp, err := nf.Do(lr)
	if err != nil {
		t.Fatal(err)
	}
	lresp.Body.Close()
	if len(lresp.Cookies()) != 1 {
		t.Fatalf("login: %d", lresp.StatusCode)
	}
	req, _ := http.NewRequest("GET", ts.URL+"/events", nil)
	req.Host = apiHost
	req.AddCookie(lresp.Cookies()[0])
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content type %q", ct)
	}
	lines := make(chan string, 16)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()
	expect := func(want string) {
		t.Helper()
		deadline := time.After(5 * time.Second)
		for {
			select {
			case l := <-lines:
				if l == want {
					return
				}
			case <-deadline:
				t.Fatalf("no %q", want)
			}
		}
	}
	expect("event: update") // initial state
	f.mu.Lock()
	f.pending = []approval.Request{{ID: 8}}
	f.mu.Unlock()
	expect("event: update") // new pending request
}
