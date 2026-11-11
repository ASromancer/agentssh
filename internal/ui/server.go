// Package ui is agentssh's local web interface: approvals, hosts, vault and
// keys, log and status. It listens on 127.0.0.1 only. A single-use login nonce is
// exchanged for an HttpOnly cookie, and Host and Origin are checked so
// other web pages and other local users cannot drive it. Every change still
// goes through the daemon, which asks the OS to authenticate the human.
package ui

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

//go:embed static
var static embed.FS

type Check struct {
	OK   bool   `json:"ok"`
	Text string `json:"text"`
}

type Options struct {
	Backend        Backend
	Port           int            // 0 = random
	Doctor         func() []Check // status checks shown in the UI
	Version        string
	AuditFile      string // audit.jsonl to read for the log tab
	KnownHostsFile string // known_hosts to list (read-only) in the known-hosts tab
}

type Server struct {
	opt  Options
	port int
	srv  *http.Server
	now  func() time.Time // injectable for tests

	mu       sync.Mutex
	nonces   map[string]time.Time // one-time login nonce -> expiry
	sessions map[string]time.Time // cookie value -> last seen
}

const (
	nonceTTL    = 10 * time.Minute
	sessionIdle = 8 * time.Hour
	maxEntries  = 64
)

func newServer(o Options, port int) *Server {
	return &Server{opt: o, port: port, now: time.Now, nonces: map[string]time.Time{}, sessions: map[string]time.Time{}}
}

// Start listens on 127.0.0.1 and serves in the background.
func Start(o Options) (*Server, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(o.Port)))
	if err != nil {
		return nil, err
	}
	s := newServer(o, ln.Addr().(*net.TCPAddr).Port)
	s.srv = &http.Server{Handler: s.handler(), ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10}
	go s.srv.Serve(ln)
	return s, nil
}

func (s *Server) hostport(h string) string { return h + ":" + strconv.Itoa(s.port) }

// Base is the UI address without any secret.
func (s *Server) Base() string { return "http://" + s.hostport("127.0.0.1") + "/" }

func randHex() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// LoginURL mints a single-use login link valid for 10 minutes.
func (s *Server) LoginURL() string {
	n, err := randHex()
	if err != nil {
		return s.Base() // no nonce: the page answers 401 rather than leaking anything
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if len(s.nonces) >= maxEntries {
		for k, exp := range s.nonces {
			if !exp.After(now) {
				delete(s.nonces, k)
			}
		}
	}
	for len(s.nonces) >= maxEntries { // still full: drop the oldest
		oldest, ot := "", time.Time{}
		for k, exp := range s.nonces {
			if oldest == "" || exp.Before(ot) {
				oldest, ot = k, exp
			}
		}
		delete(s.nonces, oldest)
	}
	s.nonces[n] = now.Add(nonceTTL)
	return s.Base() + "?n=" + n
}

// Link opens the page on one approval request (mints a fresh nonce).
func (s *Server) Link(id int) string { return s.LoginURL() + "#req=" + strconv.Itoa(id) }

func (s *Server) Close() error {
	if s.srv == nil {
		return nil
	}
	return s.srv.Close()
}

// useNonce consumes a login nonce; it is valid once and until it expires.
func (s *Server) useNonce(v string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.nonces[v]
	delete(s.nonces, v)
	return ok && exp.After(s.now())
}

// newSession registers a cookie value; at the cap it drops idle ones, then the stalest.
func (s *Server) newSession() (string, error) {
	sid, err := randHex()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if len(s.sessions) >= maxEntries {
		for k, t := range s.sessions {
			if now.Sub(t) > sessionIdle {
				delete(s.sessions, k)
			}
		}
	}
	for len(s.sessions) >= maxEntries {
		oldest, ot := "", time.Time{}
		for k, t := range s.sessions {
			if oldest == "" || t.Before(ot) {
				oldest, ot = k, t
			}
		}
		delete(s.sessions, oldest)
	}
	s.sessions[sid] = now
	return sid, nil
}

// session checks a cookie and refreshes its last-seen time.
func (s *Server) session(v string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.sessions[v]
	if !ok {
		return false
	}
	now := s.now()
	if now.Sub(t) > sessionIdle {
		delete(s.sessions, v)
		return false
	}
	s.sessions[v] = now
	return true
}

func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	s.routes(mux)
	sub, _ := fs.Sub(static, "static")
	files := map[string][2]string{
		"/":        {"index.html", "text/html; charset=utf-8"},
		"/app.js":  {"app.js", "text/javascript; charset=utf-8"},
		"/app.css": {"app.css", "text/css; charset=utf-8"},
	}
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		f, ok := files[r.URL.Path]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		b, err := fs.ReadFile(sub, f[0])
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", f[1])
		w.Write(b)
	})
	return s.guard(mux)
}

func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		if r.Host != s.hostport("127.0.0.1") {
			http.Error(w, "wrong host", http.StatusMisdirectedRequest)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/" && r.URL.Query().Has("n") {
			if !s.useNonce(r.URL.Query().Get("n")) {
				http.Error(w, "this link is no longer valid; open agentssh from 'agentssh ui' or the tray icon", http.StatusUnauthorized)
				return
			}
			sid, err := s.newSession()
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "agentssh", Value: sid, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		if c, err := r.Cookie("agentssh"); err != nil || !s.session(c.Value) {
			http.Error(w, "open agentssh from 'agentssh ui' or the tray icon", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			o := r.Header.Get("Origin")
			if o != "http://"+s.hostport("127.0.0.1") {
				http.Error(w, "cross-origin request refused", http.StatusForbidden)
				return
			}
			if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
				http.Error(w, "JSON only", http.StatusUnsupportedMediaType)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
