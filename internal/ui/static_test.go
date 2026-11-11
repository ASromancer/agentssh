package ui

import (
	"regexp"
	"strings"
	"testing"
)

func TestStaticPage(t *testing.T) {
	s := testServer()
	sess := login(t, s)
	get := func(path string) string {
		return do(t, s, "GET", path, "127.0.0.1:8123", "", sess, "", "").Body.String()
	}
	page := get("/")
	for _, want := range []string{`<script src="/app.js"></script>`, `href="/app.css"`} {
		if !strings.Contains(page, want) {
			t.Errorf("index.html lacks %s", want)
		}
	}
	for _, v := range []string{"approvals", "hosts", "keychain", "knownhosts", "log"} {
		if !strings.Contains(page, `data-view="`+v+`"`) || !strings.Contains(page, `data-nav="`+v+`"`) {
			t.Errorf("index.html lacks view %s", v)
		}
	}
	if !strings.Contains(page, `data-view="setup"`) {
		t.Error("index.html lacks view setup")
	}
	if regexp.MustCompile(`<script>|<script[^>]*>[^<]*[^<\s]`).MatchString(page) || strings.Contains(page, "<style") ||
		regexp.MustCompile(`\sstyle\s*=`).MatchString(page) || regexp.MustCompile(`\son[a-z]+\s*=`).MatchString(page) {
		t.Error("inline script/style/handlers violate the CSP")
	}
	js := get("/app.js")
	for _, want := range []string{"/api/pending", "/api/decide", "/api/admin/begin", "/api/admin/commit", "/api/audit", "/api/hosts",
		"/api/keys", "/api/knownhosts", "/api/unlock", "/api/lock", "/api/doctor", "/api/setup", "/api/setup/skip", "/api/out/", "/events"} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js lacks %s", want)
		}
	}
	for _, bad := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "confirm(", "prompt(", "setAttribute(\"style\"", "setAttribute('style'"} {
		if strings.Contains(js, bad) {
			t.Errorf("app.js must not use %s (agent-controlled text; CSP)", bad)
		}
	}
	if css := get("/app.css"); strings.Contains(css, "@import") || strings.Contains(css, "url(http") {
		t.Error("app.css must not load external resources")
	}
}
