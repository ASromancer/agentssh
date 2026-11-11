package cli

import (
	"errors"
	"testing"
)

func TestOpenFlow(t *testing.T) {
	var calls []string
	f := openDeps{
		running:     func() bool { return false },
		installed:   func() bool { return true },
		startSvc:    func() error { calls = append(calls, "svc"); return nil },
		startDetach: func() error { calls = append(calls, "detach"); return nil },
		wait:        func() error { calls = append(calls, "wait"); return nil },
		login:       func() (string, error) { return "http://127.0.0.1:1/?n=x", nil },
		browse:      func(u string) error { calls = append(calls, "open "+u); return nil },
	}
	if err := openFlow(f); err != nil || len(calls) != 3 || calls[0] != "svc" || calls[2] != "open http://127.0.0.1:1/?n=x" {
		t.Fatalf("%v %v", err, calls)
	}
	// service start fails: fall back to a detached daemon
	calls = nil
	f.startSvc = func() error { return errors.New("no systemd") }
	if err := openFlow(f); err != nil || calls[0] != "detach" {
		t.Fatalf("fallback: %v %v", err, calls)
	}
	// already running: no start at all
	calls = nil
	f.running = func() bool { return true }
	if err := openFlow(f); err != nil || calls[0] != "open http://127.0.0.1:1/?n=x" {
		t.Fatalf("running: %v %v", err, calls)
	}
}

func TestAppDefault(t *testing.T) {
	for exe, want := range map[string]bool{
		`C:\Users\a\AppData\Local\Programs\Ostiary\ostiary-app.exe`: true,
		`C:\x\OSTIARY-APP.EXE`: true,
		`C:\x\ostiary.exe`:     false,
		"/usr/bin/ostiary":     false,
	} {
		if appDefault(exe) != want {
			t.Errorf("%s: want %v", exe, want)
		}
	}
}
