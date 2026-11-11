// Package ui is agentssh's local web interface: approvals, hosts, vault and
// keys, log and status. It listens on 127.0.0.1 only. A per-start token is
// exchanged for an HttpOnly cookie, and Host and Origin are checked so
// other web pages and other local users cannot drive it. Every change still
// goes through the daemon, which asks the OS to authenticate the human.
package ui

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"os"
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
	Backend   Backend
	Port      int            // 0 = random
	URLFile   string         // written with the tokenized URL (mode 0600), removed on Close
	Doctor    func() []Check // status checks shown in the UI
	Version   string
	AuditFile string // audit.jsonl to read for the log tab
}

type Server struct {
	opt   Options
	token string
	port  int
	srv   *http.Server

	mu       sync.Mutex
	sessions map[string]bool // cookie values handed out on login; the URL token is never a cookie
}

func newServer(o Options, token string, port int) *Server {
	return &Server{opt: o, token: token, port: port, sessions: map[string]bool{}}
}

// Start listens on 127.0.0.1 and serves in the background.
func Start(o Options) (*Server, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(o.Port)))
	if err != nil {
		return nil, err
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		ln.Close()
		return nil, err
	}
	s := newServer(o, hex.EncodeToString(b), ln.Addr().(*net.TCPAddr).Port)
	s.srv = &http.Server{Handler: s.handler(), ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10}
	if o.URLFile != "" {
		if err := writeURLFile(o.URLFile, s.URL()+"\n"); err != nil {
			ln.Close()
			return nil, err
		}
	}
	go s.srv.Serve(ln)
	return s, nil
}

// writeURLFile replaces any existing file: WriteFile would keep its old mode.
func writeURLFile(path, content string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func (s *Server) hostport(h string) string { return h + ":" + strconv.Itoa(s.port) }

// URL is the address that logs a browser in (it carries the token).
func (s *Server) URL() string { return "http://" + s.hostport("127.0.0.1") + "/?t=" + s.token }

// Link opens the page on one approval request.
func (s *Server) Link(id int) string { return s.URL() + "#req=" + strconv.Itoa(id) }

func (s *Server) Close() error {
	if s.opt.URLFile != "" {
		os.Remove(s.opt.URLFile)
	}
	if s.srv == nil {
		return nil
	}
	return s.srv.Close()
}

func (s *Server) tokenOK(v string) bool {
	return len(v) == len(s.token) && subtle.ConstantTimeCompare([]byte(v), []byte(s.token)) == 1
}

func (s *Server) session(v string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[v]
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
		if r.Method == http.MethodGet && r.URL.Path == "/" && r.URL.Query().Has("t") {
			if !s.tokenOK(r.URL.Query().Get("t")) {
				http.Error(w, "this link is no longer valid; open agentssh from 'agentssh ui' or the tray icon", http.StatusUnauthorized)
				return
			}
			b := make([]byte, 32)
			if _, err := rand.Read(b); err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			sid := hex.EncodeToString(b)
			s.mu.Lock()
			s.sessions[sid] = true
			s.mu.Unlock()
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
