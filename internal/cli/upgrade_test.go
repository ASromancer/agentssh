package cli

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUpgradeCheckExitCodes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"tag_name":"v0.2.0","html_url":"https://example.invalid/r","body":"","assets":[]}`)
	}))
	defer srv.Close()
	oldV, oldB := Version, updateBase
	defer func() { Version, updateBase = oldV, oldB }()
	updateBase = srv.URL
	for v, want := range map[string]int{"0.1.0": 10, "0.2.0": 0, "0.3.0": 0} {
		Version = v
		if got := cmdUpgrade([]string{"--check"}); got != want {
			t.Errorf("version %s: exit %d, want %d", v, got, want)
		}
	}
}
