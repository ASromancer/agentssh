package approval

import (
	"strings"
	"testing"
)

func TestLocalURL(t *testing.T) {
	for u, want := range map[string]bool{
		"http://127.0.0.1:8123/?t=abc":     true,
		"http://localhost:8123/#req=4":     true,
		"https://127.0.0.1:8123/":          false,
		"http://example.com/":              false,
		"http://127.0.0.1.evil.com:80/":    false,
		"file:///etc/passwd":               false,
		"http://127.0.0.1:8123/\nrm -rf ~": false,
		"http://evil@127.0.0.1:1/":         true,
		"http://127.0.0.1@evil.com/":       false,
		"HTTP://127.0.0.1:1/":              true,
		"http://LOCALHOST:1/":              true,
		"http://[::1]:1/":                  false,
	} {
		if got := LocalURL(u); got != want {
			t.Errorf("LocalURL(%q) = %v", u, got)
		}
	}
}

func TestOpenEnv(t *testing.T) {
	env := []string{"BROWSER=/tmp/evil", "LD_PRELOAD=/tmp/evil.so", "PATH=/tmp/evil", "DISPLAY=:0", "XAUTHORITY=/x",
		"XDG_CURRENT_DESKTOP=GNOME", "HOME=/home/u", "GTK_IM_MODULE=ibus", "XMODIFIERS=@im=ibus", "LANGUAGE=vi", "SystemRoot=C:\\Windows", "AGENTSSH_X=1"}
	got := strings.Join(openEnv(env, "linux"), " ")
	if want := "DISPLAY=:0 XAUTHORITY=/x XDG_CURRENT_DESKTOP=GNOME HOME=/home/u GTK_IM_MODULE=ibus XMODIFIERS=@im=ibus LANGUAGE=vi PATH=/usr/local/bin:/usr/bin:/bin:/snap/bin"; got != want {
		t.Errorf("linux:\n got %s\nwant %s", got, want)
	}
	got = strings.Join(openEnv(env, "windows"), " ")
	if !strings.Contains(got, "SystemRoot=") || strings.Contains(got, "PATH=") || strings.Contains(got, "BROWSER") || strings.Contains(got, "LD_") {
		t.Errorf("windows: %s", got)
	}
}
