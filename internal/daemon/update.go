package daemon

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/ASromancer/ostiary/internal/audit"
	"github.com/ASromancer/ostiary/internal/update"
)

// UpdateInfo describes a newer release that is available but not installed.
type UpdateInfo struct {
	Version, URL, Notes string
	Manual              string // non-empty for .deb: the command the user must run
}

// ExitRestart asks the service manager (systemd Restart=on-failure, launchd KeepAlive) to start us again.
const ExitRestart = 75

// SetVersion records the running version and enables the background update check.
func (d *Daemon) SetVersion(v string) { d.version = v }

// SetRespawn sets how a daemon outside a service manager starts its successor.
func (d *Daemon) SetRespawn(f func(oldPid int) error) { d.respawn = f }

// RestartCode is ExitRestart when the process should exit for the service manager to restart it, else 0.
func (d *Daemon) RestartCode() int { return int(d.restartCode.Load()) }

// updateCheckEnabled: the background check is on unless OSTIARY_NO_UPDATE_CHECK=1.
func updateCheckEnabled(env func(string) string) bool { return env("OSTIARY_NO_UPDATE_CHECK") != "1" }

// selfExe is the running binary; Linux appends " (deleted)" once an update replaced it.
func selfExe() string {
	exe, _ := os.Executable()
	return strings.TrimSuffix(exe, " (deleted)")
}

func (d *Daemon) updateBase() string {
	if d.updBase != "" {
		return d.updBase
	}
	return update.Base()
}

// checkUpdate looks up the latest release and records it in Status. It never installs.
func (d *Daemon) checkUpdate(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	r, err := update.Latest(ctx, d.updateBase(), d.version)
	if err != nil {
		log.Printf("update check: %v", err)
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !update.Newer(r.Version, d.version) {
		d.update, d.release = nil, nil
		return
	}
	u := &UpdateInfo{Version: r.Version, URL: r.URL, Notes: r.Notes}
	if k := update.DetectKind(selfExe(), runtime.GOOS); k == update.Deb {
		u.Manual = "sudo apt install ./" + update.AssetName(k, runtime.GOOS, runtime.GOARCH, r.Version)
	}
	d.update, d.release = u, r
}

// updateLoop: first check 1 minute after start, then every 24 hours, until ctx ends.
func (d *Daemon) updateLoop(ctx context.Context) {
	if d.version == "" || !updateCheckEnabled(os.Getenv) {
		return
	}
	for t := time.Minute; ; t = 24 * time.Hour {
		select {
		case <-ctx.Done():
			return
		case <-time.After(t):
			d.checkUpdate(ctx)
		}
	}
}

// managedRestart: the service manager will start us again after exit 75. An inherited
// INVOCATION_ID / XPC_SERVICE_NAME alone is not enough: the parent must be the manager.
func managedRestart(goos string, env func(string) string, ppid int, comm func(int) string) bool {
	switch goos {
	case "linux":
		return env("INVOCATION_ID") != "" && comm(ppid) == "systemd"
	case "darwin":
		return strings.Contains(env("XPC_SERVICE_NAME"), "dev.ostiary") && ppid == 1
	}
	return false
}

func procComm(pid int) string {
	b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	return strings.TrimSpace(string(b))
}

func (d *Daemon) managed() bool {
	if d.managedFn != nil {
		return d.managedFn()
	}
	return managedRestart(runtime.GOOS, os.Getenv, os.Getppid(), procComm)
}

// restart makes a new daemon take over, then stops this one after delay. If the successor
// cannot be started it keeps serving and says so.
func (d *Daemon) restart(delay time.Duration) error {
	if !d.restarting.CompareAndSwap(false, true) {
		return errors.New("restart already in progress")
	}
	if d.managed() {
		d.restartCode.Store(ExitRestart)
	} else {
		err := errors.New("no way to start a successor")
		if d.respawn != nil {
			err = d.respawn(os.Getpid())
		}
		if err != nil {
			d.restarting.Store(false)
			return fmt.Errorf("the new version is installed but the daemon could not restart (%v); restart Ostiary manually", err)
		}
	}
	time.AfterFunc(delay, func() {
		d.mu.Lock()
		ln := d.ln
		d.mu.Unlock()
		if ln != nil {
			ln.Close()
		}
	})
	return nil
}

// WaitForPredecessor blocks until the old daemon has released the socket (at most 10 s).
func WaitForPredecessor() {
	for i := 0; i < 100 && Running(); i++ {
		time.Sleep(100 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond) // ponytail: grace for the old UI/tray to let go; wait on the pid if this ever races
}

// Restart replies, then restarts the daemon (used by 'ostiary upgrade' after installing).
func (s *Service) Restart(_ *Empty, _ *Empty) error {
	s.d.log.Write(audit.Entry{Kind: "admin", Cmd: "restart", Decision: "allow"})
	return s.d.restart(200 * time.Millisecond)
}

// upgrade runs the approved "upgrade" admin op.
func (d *Daemon) upgrade(version string, r *AdminReply) error {
	d.mu.Lock()
	rel := d.release
	d.mu.Unlock()
	if rel == nil || rel.Version != version {
		return errors.New("no update is available")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	exe := selfExe()
	kind := update.DetectKind(exe, runtime.GOOS)
	msg, err := update.Apply(ctx, rel, d.version, kind, exe, runtime.GOOS, runtime.GOARCH, nil)
	if err != nil {
		return err
	}
	r.Out = msg
	d.mu.Lock()
	d.update, d.release = nil, nil // installed: a second approval must not re-apply it
	d.mu.Unlock()
	if kind == update.WindowsInstaller {
		return nil // Setup stops this daemon (ostiary stop) and starts the new one itself
	}
	if err := d.restart(time.Second); err != nil {
		r.Out += "; " + err.Error()
	}
	return nil
}

func (d *Daemon) upgradeMessage(version string) string {
	return fmt.Sprintf("upgrade Ostiary from %s to %s (signature verified before install)", d.version, version)
}
