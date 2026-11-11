package approval

import "testing"

func TestLocalURL(t *testing.T) {
	for u, want := range map[string]bool{
		"http://127.0.0.1:8123/?t=abc":     true,
		"http://localhost:8123/#req=4":     true,
		"https://127.0.0.1:8123/":          false,
		"http://example.com/":              false,
		"http://127.0.0.1.evil.com:80/":    false,
		"file:///etc/passwd":               false,
		"http://127.0.0.1:8123/\nrm -rf ~": false,
	} {
		if got := LocalURL(u); got != want {
			t.Errorf("LocalURL(%q) = %v", u, got)
		}
	}
}
