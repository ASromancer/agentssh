package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testServer() *Server {
	return newServer(Options{Backend: &fakeBackend{}}, 8123)
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

// loginPath mints a nonce and returns its request path.
func loginPath(s *Server) string { return strings.TrimPrefix(s.LoginURL(), "http://127.0.0.1:8123") }

// login performs the nonce exchange and returns the session cookie value.
func login(t *testing.T, s *Server) string {
	t.Helper()
	w := do(t, s, "GET", loginPath(s), "127.0.0.1:8123", "", "", "", "")
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

	w := do(t, s, "GET", loginPath(s), host, "", "", "", "")
	if w.Code != 303 || w.Header().Get("Location") != "/" {
		t.Fatalf("token exchange: %d %v", w.Code, w.Header())
	}
	c := w.Result().Cookies()
	if len(c) != 1 || c[0].Name != "agentssh" || len(c[0].Value) != 64 || !c[0].HttpOnly || c[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie: %+v", c)
	}
	if w := do(t, s, "GET", "/?n=wrong", host, "", "", "", ""); w.Code != 401 {
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
	if n := strings.SplitN(s.LoginURL(), "?n=", 2)[1]; do(t, s, "GET", "/", host, "", n, "", "").Code != 401 {
		t.Fatal("nonce as cookie accepted")
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

func TestLoginURL(t *testing.T) {
	s := testServer()
	u := s.LoginURL()
	if !strings.HasPrefix(u, "http://127.0.0.1:8123/?n=") || len(u) != len("http://127.0.0.1:8123/?n=")+64 || u == s.LoginURL() {
		t.Fatalf("login url %s", u)
	}
	if s.Base() != "http://127.0.0.1:8123/" || !strings.Contains(s.Link(9), "?n=") || !strings.HasSuffix(s.Link(9), "#req=9") {
		t.Fatalf("%s %s", s.Base(), s.Link(9))
	}
}

func TestNonceSingleUse(t *testing.T) {
	s := testServer()
	p := loginPath(s)
	if w := do(t, s, "GET", p, "127.0.0.1:8123", "", "", "", ""); w.Code != 303 {
		t.Fatalf("first: %d", w.Code)
	}
	if w := do(t, s, "GET", p, "127.0.0.1:8123", "", "", "", ""); w.Code != 401 {
		t.Fatalf("reuse: %d", w.Code)
	}
}

func TestNonceExpiryAndHost(t *testing.T) {
	s := testServer()
	now := time.Now()
	s.now = func() time.Time { return now }
	p := loginPath(s)
	if w := do(t, s, "GET", p, "evil.example:8123", "", "", "", ""); w.Code != 421 {
		t.Fatalf("bad host with valid nonce: %d", w.Code)
	}
	now = now.Add(nonceTTL + time.Second)
	if w := do(t, s, "GET", p, "127.0.0.1:8123", "", "", "", ""); w.Code != 401 {
		t.Fatalf("expired: %d", w.Code)
	}
	// the bad-host attempt must not have consumed it, but expiry still wins
	now = now.Add(-nonceTTL)
	p = loginPath(s)
	do(t, s, "GET", p, "evil.example:8123", "", "", "", "")
	if w := do(t, s, "GET", p, "127.0.0.1:8123", "", "", "", ""); w.Code != 303 {
		t.Fatalf("nonce survives bad host: %d", w.Code)
	}
}

func TestNonceCap(t *testing.T) {
	s := testServer()
	for i := 0; i < maxEntries+5; i++ {
		s.LoginURL()
	}
	if len(s.nonces) > maxEntries {
		t.Fatalf("nonces: %d", len(s.nonces))
	}
}

func TestSessionIdleExpiry(t *testing.T) {
	s := testServer()
	now := time.Now()
	s.now = func() time.Time { return now }
	sess := login(t, s)
	now = now.Add(7 * time.Hour)
	if w := do(t, s, "GET", "/", "127.0.0.1:8123", "", sess, "", ""); w.Code != 200 { // refreshes last-seen
		t.Fatalf("active: %d", w.Code)
	}
	now = now.Add(7 * time.Hour)
	if w := do(t, s, "GET", "/", "127.0.0.1:8123", "", sess, "", ""); w.Code != 200 {
		t.Fatalf("refreshed: %d", w.Code)
	}
	now = now.Add(8*time.Hour + time.Second)
	if w := do(t, s, "GET", "/", "127.0.0.1:8123", "", sess, "", ""); w.Code != 401 {
		t.Fatalf("idle: %d", w.Code)
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
