//go:build linux && !e2efake

package humanok

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestPkResult(t *testing.T) {
	for _, tc := range []struct {
		code int
		err  error
		want error
	}{
		{0, nil, nil},
		{1, nil, ErrDenied},
		{3, nil, ErrDenied},
		{2, nil, ErrUnavailable},
		{4, nil, ErrUnavailable},
		{-1, errors.New("exec: not found"), ErrUnavailable},
	} {
		if got := pkResult(tc.code, "", tc.err); !errors.Is(got, tc.want) && !(tc.want == nil && got == nil) {
			t.Errorf("code %d: got %v want %v", tc.code, got, tc.want)
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
