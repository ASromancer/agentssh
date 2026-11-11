package daemon

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func releaseServer(t *testing.T, version string) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"tag_name":"v%s","html_url":"https://example.invalid/r","body":"notes","assets":[]}`, version)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestUpdateCheckAndAdminGate(t *testing.T) {
	h := setupEmpty(t)
	h.d.updBase = releaseServer(t, "0.2.0")
	h.d.SetVersion("0.1.0")
	h.d.checkUpdate()

	var st StatusReply
	if err := h.call("Status", &Empty{}, &st); err != nil || st.Update == nil || st.Update.Version != "0.2.0" || st.Update.Notes != "notes" {
		t.Fatalf("status: %v %+v", err, st.Update)
	}
	if err := h.call("Begin", &BeginArgs{Op: "upgrade", Name: "9.9.9"}, &BeginReply{}); err == nil {
		t.Fatal("upgrade to a version that is not offered was accepted")
	}
	var br BeginReply
	if err := h.call("Begin", &BeginArgs{Op: "upgrade", Name: "0.2.0"}, &br); err != nil || br.Ticket == 0 {
		t.Fatalf("begin: %v %+v", err, br)
	}
	want := "upgrade Ostiary from 0.1.0 to 0.2.0 (signature verified before install)"
	if got := h.d.adminMessage(&AdminArgs{Op: "upgrade", Name: "0.2.0"}, nil); got != want {
		t.Fatalf("message %q", got)
	}

	h.d.SetVersion("0.2.0") // now current
	h.d.checkUpdate()
	st = StatusReply{}
	h.call("Status", &Empty{}, &st)
	if st.Update != nil {
		t.Fatalf("up to date but Update=%+v", st.Update)
	}
	if err := h.call("Begin", &BeginArgs{Op: "upgrade", Name: "0.2.0"}, &BeginReply{}); err == nil {
		t.Fatal("upgrade begun with nothing to install")
	}
}

func TestUpdateCheckEnabled(t *testing.T) {
	get := func(v string) func(string) string {
		return func(k string) string {
			if k == "OSTIARY_NO_UPDATE_CHECK" {
				return v
			}
			return ""
		}
	}
	if !updateCheckEnabled(get("")) || !updateCheckEnabled(get("0")) || updateCheckEnabled(get("1")) {
		t.Fatal("OSTIARY_NO_UPDATE_CHECK=1 must be the only way off")
	}
}

func TestManagedRestart(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if managedRestart(env(nil)) || !managedRestart(env(map[string]string{"INVOCATION_ID": "x"})) ||
		!managedRestart(env(map[string]string{"XPC_SERVICE_NAME": "dev.ostiary.daemon"})) ||
		managedRestart(env(map[string]string{"XPC_SERVICE_NAME": "0"})) {
		t.Fatal("managedRestart")
	}
}
