package ui

import (
	"net/http"
	"net/http/httptest"
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

func TestGuard(t *testing.T) {
	s := testServer()
	const host, origin = "127.0.0.1:8123", "http://127.0.0.1:8123"

	w := do(t, s, "GET", "/?t="+testTok, host, "", "", "", "")
	if w.Code != 303 || w.Header().Get("Location") != "/" {
		t.Fatalf("token exchange: %d %v", w.Code, w.Header())
	}
	c := w.Result().Cookies()
	if len(c) != 1 || c[0].Name != "agentssh" || c[0].Value != testTok || !c[0].HttpOnly || c[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie: %+v", c)
	}
	if w := do(t, s, "GET", "/?t=wrong", host, "", "", "", ""); w.Code != 401 {
		t.Fatalf("bad token: %d", w.Code)
	}
	if w := do(t, s, "GET", "/", host, "", "", "", ""); w.Code != 401 {
		t.Fatalf("no cookie: %d", w.Code)
	}
	if w := do(t, s, "GET", "/", "evil.example:8123", "", testTok, "", ""); w.Code != 421 {
		t.Fatalf("bad host: %d", w.Code)
	}
	if w := do(t, s, "GET", "/", "localhost:8123", "", testTok, "", ""); w.Code != 200 {
		t.Fatalf("localhost host: %d", w.Code)
	}
	w = do(t, s, "GET", "/", host, "", testTok, "", "")
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
	if w := do(t, s, "POST", "/api/lock", host, "", testTok, "application/json", "{}"); w.Code != 403 {
		t.Fatalf("post without origin: %d", w.Code)
	}
	if w := do(t, s, "POST", "/api/lock", host, "http://evil.example", testTok, "application/json", "{}"); w.Code != 403 {
		t.Fatalf("post foreign origin: %d", w.Code)
	}
	if w := do(t, s, "POST", "/api/lock", host, origin, testTok, "text/plain", "{}"); w.Code != 415 {
		t.Fatalf("post text/plain: %d", w.Code)
	}
	if w := do(t, s, "POST", "/api/lock", host, origin, testTok, "application/json", "{}"); w.Code != 200 {
		t.Fatalf("good post: %d", w.Code)
	}
}

func TestURL(t *testing.T) {
	s := testServer()
	if s.URL() != "http://127.0.0.1:8123/?t="+testTok || s.Link(9) != s.URL()+"#req=9" {
		t.Fatalf("%s %s", s.URL(), s.Link(9))
	}
}
