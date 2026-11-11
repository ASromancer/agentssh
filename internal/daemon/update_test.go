package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
	h.d.checkUpdate(context.Background())

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
	h.d.checkUpdate(context.Background())
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
	comm := func(c string) func(int) string { return func(int) string { return c } }
	inv := map[string]string{"INVOCATION_ID": "x"}
	xpc := map[string]string{"XPC_SERVICE_NAME": "dev.ostiary.daemon"}
	for i, c := range []struct {
		goos string
		env  map[string]string
		ppid int
		comm string
		want bool
	}{
		{"linux", inv, 900, "systemd", true},
		{"linux", inv, 900, "bash", false}, // inherited INVOCATION_ID
		{"linux", nil, 900, "systemd", false},
		{"darwin", xpc, 1, "", true},
		{"darwin", xpc, 77, "", false},
		{"darwin", map[string]string{"XPC_SERVICE_NAME": "0"}, 1, "", false},
		{"windows", inv, 1, "systemd", false},
	} {
		if got := managedRestart(c.goos, env(c.env), c.ppid, comm(c.comm)); got != c.want {
			t.Errorf("case %d: got %v", i, got)
		}
	}
}

func TestRestartFailureKeepsServing(t *testing.T) {
	h := setupEmpty(t)
	h.d.managedFn = func() bool { return false }
	h.d.respawn = func(int) error { return errors.New("boom") }
	err := h.call("Restart", &Empty{}, &Empty{})
	if err == nil || !strings.Contains(err.Error(), "restart Ostiary manually") {
		t.Fatalf("restart error: %v", err)
	}
	time.Sleep(400 * time.Millisecond)
	if err := h.call("Status", &Empty{}, &StatusReply{}); err != nil {
		t.Fatalf("daemon stopped serving after a failed restart: %v", err)
	}
	if err := h.d.restart(0); err == nil { // respawn still fails; not "in progress"
		t.Fatal("expected error")
	} else if strings.Contains(err.Error(), "in progress") {
		t.Fatal("failed restart left the in-progress flag set")
	}
}

func TestRestartIdempotent(t *testing.T) {
	h := setupEmpty(t)
	h.d.managedFn = func() bool { return false }
	n := 0
	h.d.respawn = func(int) error { n++; return nil }
	if err := h.d.restart(time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := h.d.restart(time.Hour); err == nil || !strings.Contains(err.Error(), "already in progress") || n != 1 {
		t.Fatalf("second restart: %v (spawned %d)", err, n)
	}
}

func TestUpdateLoopStops(t *testing.T) {
	h := setupEmpty(t)
	t.Setenv("OSTIARY_NO_UPDATE_CHECK", "")
	h.d.SetVersion("0.1.0")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.d.updateLoop(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("updateLoop did not stop")
	}
}
