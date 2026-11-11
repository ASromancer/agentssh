//go:build windows

package humanok

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// SystemDir is the Windows System32 directory.
func SystemDir() string {
	d, _ := windows.GetSystemDirectory()
	return d
}

func trusted(p string) (string, error) {
	root := strings.TrimRight(SystemDir(), `\`)
	if root == "" || !strings.HasPrefix(strings.ToLower(p), strings.ToLower(root)+`\`) {
		return "", fmt.Errorf("%s is not under %s", p, root)
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
