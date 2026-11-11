package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ASromancer/ostiary/internal/daemon"
	"github.com/ASromancer/ostiary/internal/update"
)

// updateBase overrides the release API base; only tests set it.
var updateBase string

const exitUpdateAvailable = 10

func cmdUpgrade(args []string) int {
	fs := newFlags("upgrade")
	check := fs.Bool("check", false, "only report whether an update exists (exit 10 if so)")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	if _, err := parse(fs, args); err != nil {
		return 2
	}
	base := updateBase
	if base == "" {
		base = update.Base()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	r, err := update.Latest(ctx, base, Version)
	if err != nil {
		return errf(1, "%v", err)
	}
	fmt.Printf("current version: %s\nlatest version:  %s\n", Version, r.Version)
	if !update.Newer(r.Version, Version) {
		fmt.Println("Ostiary is up to date")
		return 0
	}
	if *check {
		fmt.Printf("update available: %s\n", r.URL)
		return exitUpdateAvailable
	}
	if !*yes {
		t, code := openTTY("upgrade")
		if t == nil {
			return code
		}
		if !t.yes(fmt.Sprintf("Upgrade Ostiary from %s to %s?", Version, r.Version), false) {
			fmt.Println("cancelled")
			return 1
		}
	} else if t, code := openTTY("upgrade"); t == nil { // --yes skips the question, not the human
		return code
	}
	exe, err := os.Executable()
	if err != nil {
		return errf(1, "%v", err)
	}
	exe = strings.TrimSuffix(exe, " (deleted)")
	kind := update.DetectKind(exe, runtime.GOOS)
	msg, err := update.Apply(ctx, r, Version, kind, exe, runtime.GOOS, runtime.GOARCH, nil)
	if err != nil {
		return errf(1, "%v", err)
	}
	fmt.Println(msg)
	if kind == update.WindowsInstaller { // Setup stops the daemon and starts the new one itself
		return 0
	}
	if daemon.Running() {
		if c, _ := dial(); c != nil {
			defer c.Close()
			if err := c.Call("A.Restart", &daemon.Empty{}, &daemon.Empty{}); err != nil {
				return callErr(err)
			}
			fmt.Println("restarting the daemon")
		}
	}
	return 0
}

// cleanOldBinaries removes *.old files left by a Windows update (a running exe cannot be deleted).
func cleanOldBinaries() {
	if runtime.GOOS != "windows" {
		return
	}
	if exe, err := os.Executable(); err == nil {
		old, _ := filepath.Glob(filepath.Join(filepath.Dir(exe), "*.old"))
		for _, f := range old {
			os.Remove(f)
		}
	}
}
