package ui

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const testTok = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func testServer() *Server {
	return newServer(Options{Backend: &fakeBackend{}}, testTok, 8123)
}

func do(t *testing.T, s *Server, method, target, host, origin, cookie, ctype, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.Host = host
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: "agentssh", Value: cookie})
	}
	if ctype != "" {
		r.Header.Set("Content-Type", ctype)
	}
	w := httptest.NewRecorder()
	s.handler().ServeHTTP(w, r)
	return w
}

// login performs the token exchange and returns the session cookie value.
func login(t *testing.T, s *Server) string {
	t.Helper()
	w := do(t, s, "GET", "/?t="+testTok, "127.0.0.1:8123", "", "", "", "")
	c := w.Result().Cookies()
	if w.Code != 303 || len(c) != 1 {
		t.Fatalf("login: %d %+v", w.Code, c)
	}
	return c[0].Value
}

func TestGuard(t *testing.T) {
	s := testServer()
	const host, origin = "127.0.0.1:8123", "http://127.0.0.1:8123"
	sess := login(t, s)

	w := do(t, s, "GET", "/?t="+testTok, host, "", "", "", "")
	if w.Code != 303 || w.Header().Get("Location") != "/" {
		t.Fatalf("token exchange: %d %v", w.Code, w.Header())
	}
	c := w.Result().Cookies()
	if len(c) != 1 || c[0].Name != "agentssh" || c[0].Value == testTok || len(c[0].Value) != 64 || !c[0].HttpOnly || c[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie: %+v", c)
	}
	if w := do(t, s, "GET", "/?t=wrong", host, "", "", "", ""); w.Code != 401 {
		t.Fatalf("bad token: %d", w.Code)
	}
	if w := do(t, s, "GET", "/", host, "", "", "", ""); w.Code != 401 {
		t.Fatalf("no cookie: %d", w.Code)
	}
	if w := do(t, s, "GET", "/", "evil.example:8123", "", sess, "", ""); w.Code != 421 {
		t.Fatalf("bad host: %d", w.Code)
	}
	if w := do(t, s, "GET", "/", "localhost:8123", "", sess, "", ""); w.Code != 421 {
		t.Fatalf("localhost host: %d", w.Code)
	}
	w = do(t, s, "GET", "/", host, "", sess, "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "/app.js") {
		t.Fatalf("index: %d %s", w.Code, w.Body.String())
	}
	for k, v := range map[string]string{
		"Content-Security-Policy": "default-src 'self'", "X-Frame-Options": "DENY",
		"Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store",
	} {
		if w.Header().Get(k) != v {
			t.Errorf("header %s = %q", k, w.Header().Get(k))
		}
	}
	if w := do(t, s, "POST", "/api/lock", host, "", sess, "application/json", "{}"); w.Code != 403 {
		t.Fatalf("post without origin: %d", w.Code)
	}
	if w := do(t, s, "POST", "/api/lock", host, "http://evil.example", sess, "application/json", "{}"); w.Code != 403 {
		t.Fatalf("post foreign origin: %d", w.Code)
	}
	if w := do(t, s, "POST", "/api/lock", host, origin, sess, "text/plain", "{}"); w.Code != 415 {
		t.Fatalf("post text/plain: %d", w.Code)
	}
	if w := do(t, s, "POST", "/api/lock", host, origin, sess, "application/jsonx", "{}"); w.Code != 415 {
		t.Fatalf("post application/jsonx: %d", w.Code)
	}
	if w := do(t, s, "POST", "/api/lock", "localhost:8123", "http://localhost:8123", sess, "application/json", "{}"); w.Code != 421 {
		t.Fatalf("post localhost: %d", w.Code)
	}
	if w := do(t, s, "GET", "/", host, "", testTok, "", ""); w.Code != 401 {
		t.Fatalf("url token as cookie: %d", w.Code)
	}
	if w := do(t, s, "POST", "/api/lock", host, origin, sess, "application/json; charset=utf-8", "{}"); w.Code != 200 {
		t.Fatalf("good post: %d", w.Code)
	}
}

func TestStatic(t *testing.T) {
	s := testServer()
	sess := login(t, s)
	w := do(t, s, "GET", "/nope", "127.0.0.1:8123", "", sess, "", "")
	if w.Code != 404 {
		t.Fatalf("/nope: %d", w.Code)
	}
	for k, v := range map[string]string{
		"Content-Security-Policy": "default-src 'self'", "X-Frame-Options": "DENY",
		"Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store",
	} {
		if w.Header().Get(k) != v {
			t.Errorf("404 header %s = %q", k, w.Header().Get(k))
		}
	}
	for p, ct := range map[string]string{"/": "text/html; charset=utf-8", "/app.js": "text/javascript; charset=utf-8", "/app.css": "text/css; charset=utf-8"} {
		w := do(t, s, "GET", p, "127.0.0.1:8123", "", sess, "", "")
		if w.Code != 200 || w.Header().Get("Content-Type") != ct {
			t.Errorf("%s: %d %q", p, w.Code, w.Header().Get("Content-Type"))
		}
	}
}

func TestURLFileMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ui.url")
	if err := os.WriteFile(p, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Start(Options{Backend: &fakeBackend{}, URLFile: p})
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 { // Windows uses the profile ACL
		t.Fatalf("mode: %v", st.Mode())
	}
	b, _ := os.ReadFile(p)
	if string(b) != s.URL()+"\n" {
		t.Fatalf("content %q", b)
	}
	s.Close()
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("not removed: %v", err)
	}
}

func TestURL(t *testing.T) {
	s := testServer()
	if s.URL() != "http://127.0.0.1:8123/?t="+testTok || s.Link(9) != s.URL()+"#req=9" {
		t.Fatalf("%s %s", s.URL(), s.Link(9))
	}
}

func TestSessionCap(t *testing.T) {
	s := testServer()
	var last string
	for i := 0; i < 70; i++ {
		last = login(t, s)
	}
	if w := do(t, s, "GET", "/", "127.0.0.1:8123", "", last, "", ""); w.Code != 200 {
		t.Fatalf("latest session: %d", w.Code)
	}
}
