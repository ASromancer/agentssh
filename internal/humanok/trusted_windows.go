//go:build windows

package humanok

import (
	"fmt"
	"os"
	"strings"
)

func trusted(p string) (string, error) {
	root := os.Getenv("SystemRoot")
	if root == "" || !strings.HasPrefix(strings.ToLower(p), strings.ToLower(strings.TrimRight(root, `\`))+`\`) {
		return "", fmt.Errorf("%s is not under %%SystemRoot%%", p)
	}
	fi, err := os.Stat(p)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", p)
	}
	return p, nil
}
