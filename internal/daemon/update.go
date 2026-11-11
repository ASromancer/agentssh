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
func (d *Daemon) checkUpdate() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
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

// updateLoop: first check 1 minute after start, then every 24 hours.
func (d *Daemon) updateLoop() {
	if d.version == "" || !updateCheckEnabled(os.Getenv) {
		return
	}
	for t := time.Minute; ; t = 24 * time.Hour {
		time.Sleep(t)
		d.checkUpdate()
	}
}

// managedRestart: systemd or launchd will start us again after exit 75.
func managedRestart(env func(string) string) bool {
	return env("INVOCATION_ID") != "" || strings.Contains(env("XPC_SERVICE_NAME"), "dev.ostiary")
}

// restart stops this daemon so that a new one (the updated binary) takes over.
func (d *Daemon) restart() {
	if managedRestart(os.Getenv) {
		d.restartCode.Store(ExitRestart)
	} else if d.respawn != nil {
		if err := d.respawn(os.Getpid()); err != nil {
			log.Printf("restart: %v (start the daemon again by hand)", err)
		}
	}
	d.restarting.Store(true)
	d.mu.Lock()
	ln := d.ln
	d.mu.Unlock()
	if ln != nil {
		ln.Close()
	}
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
	time.AfterFunc(200*time.Millisecond, s.d.restart)
	return nil
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
	msg, err := update.Apply(ctx, rel, d.version, update.DetectKind(exe, runtime.GOOS), exe, runtime.GOOS, runtime.GOARCH, nil)
	if err != nil {
		return err
	}
	r.Out = msg
	time.AfterFunc(time.Second, d.restart)
	return nil
}

func (d *Daemon) upgradeMessage(version string) string {
	return fmt.Sprintf("upgrade Ostiary from %s to %s (signature verified before install)", d.version, version)
}
