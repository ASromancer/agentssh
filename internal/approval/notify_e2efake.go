//go:build e2efake

package approval

import (
	"errors"
	"fmt"
	"os"
)

// Notify appends "title\tbody\tlink" to $AGENTSSH_E2E_NOTES, where the e2e test
// reads the codes. Test builds only, never in releases.
func Notify(n Notice) error {
	p := os.Getenv("AGENTSSH_E2E_NOTES")
	if p == "" {
		return errors.New("AGENTSSH_E2E_NOTES is not set")
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s\t%s\t%s\n", n.Title, n.Body, n.Link)
	return err
}
