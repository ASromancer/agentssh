package ui

import (
	"strings"
	"testing"
)

func TestStaticPage(t *testing.T) {
	s := testServer()
	sess := login(t, s)
	page := do(t, s, "GET", "/", "127.0.0.1:8123", "", sess, "", "").Body.String()
	for _, want := range []string{`<script src="/app.js"></script>`, `href="/app.css"`, `data-tab="approvals"`, `data-tab="hosts"`, `data-tab="vault"`, `data-tab="log"`} {
		if !strings.Contains(page, want) {
			t.Errorf("index.html lacks %s", want)
		}
	}
	if strings.Contains(page, "<script>") || strings.Contains(page, "<style") || strings.Contains(page, "style=") || strings.Contains(page, "onclick=") {
		t.Error("inline script/style/handlers violate the CSP")
	}
	js := do(t, s, "GET", "/app.js", "127.0.0.1:8123", "", sess, "", "").Body.String()
	for _, want := range []string{"/api/pending", "/api/decide", "/api/admin/begin", "/api/admin/commit", "/api/audit", "/events"} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js lacks %s", want)
		}
	}
	if strings.Contains(js, "innerHTML") {
		t.Error("app.js must build DOM with textContent, never innerHTML (agent-controlled text)")
	}
}
