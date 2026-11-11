//go:build linux && !e2efake

package humanok

import (
	"context"
	"errors"
	"slices"
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
