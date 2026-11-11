//go:build linux || darwin

package cli

import "testing"

// The auth mode is fixed when the daemon starts, so it must start inside
// the graphical session, not at default.target before the display exists.
func TestSystemdUnit(t *testing.T) {
	want := "[Unit]\nDescription=ostiary daemon\nAfter=graphical-session.target\nPartOf=graphical-session.target\n\n" +
		"[Service]\nExecStart=/opt/ostiary daemon\nRestart=on-failure\n\n" +
		"[Install]\nWantedBy=graphical-session.target\n"
	if got := systemdUnit("/opt/ostiary"); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}
