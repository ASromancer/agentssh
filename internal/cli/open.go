package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ASromancer/ostiary/internal/approval"
	"github.com/ASromancer/ostiary/internal/daemon"
	"github.com/ASromancer/ostiary/internal/paths"
)

type openDeps struct {
	running               func() bool
	installed             func() bool
	startSvc, startDetach func() error
	wait                  func() error
	login                 func() (string, error)
	browse                func(string) error
}

// openFlow starts the daemon when needed (service first, detached daemon as
// fallback), waits for its socket, and opens a one-time UI login link.
func openFlow(f openDeps) error {
	if !f.running() {
		started := false
		if f.installed() {
			started = f.startSvc() == nil
		}
		if !started {
			if err := f.startDetach(); err != nil {
				return fmt.Errorf("start the daemon: %w", err)
			}
		}
		if err := f.wait(); err != nil {
			return errors.New("the daemon did not start; see " + filepath.Join(paths.State(), "daemon.log"))
		}
	}
	u, err := f.login()
	if err != nil {
		return err
	}
	return f.browse(u)
}

// appDefault: the Windows GUI build runs "open" when started with no arguments.
func appDefault(exe string) bool {
	return strings.EqualFold(filepath.Base(strings.ReplaceAll(exe, `\`, "/")), "ostiary-app.exe")
}

// cliExe is the console binary: hooks must run it so agents get stdout.
func cliExe() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if runtime.GOOS == "windows" && appDefault(exe) {
		c := filepath.Join(filepath.Dir(exe), "ostiary.exe")
		if _, err := os.Stat(c); err != nil {
			return "", fmt.Errorf("console build not found: %w", err)
		}
		return c, nil
	}
	return exe, nil
}

func cmdOpen(args []string) int {
	err := openFlow(openDeps{
		running:     daemon.Running,
		installed:   serviceInstalled,
		startSvc:    startService,
		startDetach: func() error { return startDetached(filepath.Join(paths.State(), "daemon.log"), nil) },
		wait: func() error {
			c, err := dialRetry(5 * time.Second)
			if err == nil {
				c.Close()
			}
			return err
		},
		login: func() (string, error) {
			c, err := dialRetry(2 * time.Second)
			if err != nil {
				return "", err
			}
			defer c.Close()
			var r daemon.UILoginReply
			if err := c.Call("A.UILogin", &daemon.Empty{}, &r); err != nil {
				return "", fmt.Errorf("%v (daemon started with --no-ui?)", err)
			}
			return r.URL, nil
		},
		browse: approval.OpenURL,
	})
	if err != nil {
		// No terminal behind an app icon: tell the user on the desktop too.
		approval.Notify(approval.Notice{Title: "Ostiary", Body: "Không mở được Ostiary: " + err.Error()})
		return errf(1, "%v", err)
	}
	return 0
}

func cmdStop(args []string) int {
	if !daemon.Running() {
		fmt.Println("daemon is not running")
		return 0
	}
	c, code := dial()
	if c == nil {
		return code
	}
	defer c.Close()
	if err := c.Call("A.Shutdown", &daemon.Empty{}, &daemon.Empty{}); err != nil {
		return callErr(err)
	}
	for i := 0; i < 50 && daemon.Running(); i++ {
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Println("daemon stopped")
	return 0
}
