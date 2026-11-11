//go:build linux && !e2efake

package humanok

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestPkResult(t *testing.T) {
	for _, tc := range []struct {
		code   int
		err    error
		killed bool
		want   error
	}{
		{0, nil, false, nil},
		{1, nil, false, ErrDenied},
		{3, nil, false, ErrDenied},
		{2, nil, false, ErrUnavailable},
		{127, nil, false, ErrUnavailable},
		{4, nil, false, ErrUnavailable},
		{-1, errors.New("exec: not found"), false, ErrUnavailable},
		{-1, nil, false, ErrDenied}, // killed by a signal
		{-1, nil, true, ErrDenied},  // timeout
		{2, nil, true, ErrDenied},   // context ended first
		{-1, errors.New("context canceled"), true, ErrDenied},
	} {
		if got := pkResult(tc.code, "", tc.err, tc.killed); !errors.Is(got, tc.want) && !(tc.want == nil && got == nil) {
			t.Errorf("code %d killed %v: got %v want %v", tc.code, tc.killed, got, tc.want)
		}
	}
}

func TestConfirmArgs(t *testing.T) {
	var args []string
	old := runPkcheck
	runPkcheck = func(_ context.Context, a ...string) (int, string, error) { args = a; return 0, "", nil }
	defer func() { runPkcheck = old }()
	if err := (platform{}).Confirm(context.Background(), "approve on web1: rm x [destructive]"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--action-id", ActionID, "--allow-user-interaction", "--detail", "message", "approve on web1: rm x [destructive]"} {
		if !slices.Contains(args, want) {
			t.Errorf("missing %q in %v", want, args)
		}
	}
}

func TestSetupProblem(t *testing.T) {
	policy := []byte(PolicyXML("alice"))
	files := map[string]bool{"/run/user/1000/wayland-0": true, "/tmp/.X11-unix/X0": true, "/abs/wl": true}
	exists := func(p string) bool { return files[p] }
	for _, tc := range []struct {
		user string
		env  map[string]string
		ok   bool
	}{
		{"alice", map[string]string{"WAYLAND_DISPLAY": "wayland-0", "XDG_RUNTIME_DIR": "/run/user/1000"}, true},
		{"alice", map[string]string{"WAYLAND_DISPLAY": "/abs/wl"}, true},
		{"alice", map[string]string{"WAYLAND_DISPLAY": "wayland-1", "XDG_RUNTIME_DIR": "/run/user/1000", "DISPLAY": ":0"}, false},
		{"alice", map[string]string{"DISPLAY": ":0"}, true},
		{"alice", map[string]string{"DISPLAY": ":0.0"}, true},
		{"alice", map[string]string{"DISPLAY": ":1"}, false},
		{"alice", map[string]string{"DISPLAY": "localhost:10.0"}, false},
		{"alice", map[string]string{"DISPLAY": ":0.x"}, false},
		{"alice", map[string]string{}, false},
		{"bob", map[string]string{"DISPLAY": ":0"}, false},
		{"ali", map[string]string{"DISPLAY": ":0"}, false},
		{"", map[string]string{"DISPLAY": ":0"}, false},
	} {
		err := setupProblem(policy, tc.user, func(k string) string { return tc.env[k] }, exists)
		if (err == nil) != tc.ok || (err != nil && !errors.Is(err, ErrUnavailable)) {
			t.Errorf("user %q env %v: got %v", tc.user, tc.env, err)
		}
	}
	if err := setupProblem(policy, "bob", func(string) string { return ":0" }, exists); err == nil ||
		!strings.Contains(err.Error(), "belongs to another user") {
		t.Errorf("owner message: %v", err)
	}
}

func TestConfirmCancelledIsDenied(t *testing.T) {
	old := runPkcheck
	runPkcheck = func(context.Context, ...string) (int, string, error) { return -1, "", nil }
	defer func() { runPkcheck = old }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (platform{}).Confirm(ctx, "x"); !errors.Is(err, ErrDenied) || errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v", err)
	}
}

func TestUntrustedPkcheckNeverRuns(t *testing.T) {
	fake := filepath.Join(t.TempDir(), "pkcheck")
	ran := fake + ".ran"
	os.WriteFile(fake, []byte("#!/bin/sh\ntouch "+ran+"\nexit 0\n"), 0o755)
	old := pkcheckPaths
	pkcheckPaths = []string{fake}
	defer func() { pkcheckPaths = old }()
	if err := (platform{}).Confirm(context.Background(), "x"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("confirm: %v", err)
	}
	if _, err := os.Stat(ran); err == nil {
		t.Fatal("untrusted pkcheck was run")
	}
}
