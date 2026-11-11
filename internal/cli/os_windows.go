package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"

	"github.com/ASromancer/ostiary/internal/paths"
)

func openConsole() (in, out *os.File, err error) {
	if in, err = os.OpenFile("CONIN$", os.O_RDWR, 0); err != nil {
		return nil, nil, err
	}
	if out, err = os.OpenFile("CONOUT$", os.O_RDWR, 0); err != nil {
		in.Close()
		return nil, nil, err
	}
	return in, out, nil
}

func echoOff(in *os.File) (restore func()) {
	h := windows.Handle(in.Fd())
	var mode uint32
	if windows.GetConsoleMode(h, &mode) != nil {
		return func() {}
	}
	_ = windows.SetConsoleMode(h, mode&^windows.ENABLE_ECHO_INPUT)
	return func() { _ = windows.SetConsoleMode(h, mode) }
}

// startDetached runs "ostiary daemon" without a console window.
func startDetached(logPath string, extra []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	c := exec.Command(exe, append([]string{"daemon", "--log", logPath}, extra...)...)
	c.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW | windows.CREATE_NEW_PROCESS_GROUP,
	}
	if err := c.Start(); err != nil {
		return err
	}
	fmt.Printf("daemon started (pid %d, log %s)\n", c.Process.Pid, logPath)
	return c.Process.Release()
}

// installService registers a logon task that starts the daemon hidden,
// then starts it now when startNow.
func installService(startNow bool) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if app := filepath.Join(filepath.Dir(exe), "ostiary-app.exe"); fileExists0(app) {
		exe = app // GUI binary: no console window at every sign-in
	}
	tr := fmt.Sprintf(`"%s" daemon --detach`, exe)
	if out, err := exec.Command("schtasks", "/Create", "/F", "/SC", "ONLOGON", "/RL", "LIMITED",
		"/TN", "ostiary", "/TR", tr).CombinedOutput(); err != nil {
		return fmt.Errorf("schtasks: %v: %s", err, out)
	}
	if startNow {
		if err := startDetached(filepath.Join(paths.State(), "daemon.log"), nil); err != nil {
			return err
		}
	}
	fmt.Println("logon task 'ostiary' installed")
	return nil
}

// removeService deletes the logon task; the running daemon is left alone.
func removeService() error {
	if !serviceInstalled() { // a missing task is success
		return nil
	}
	if out, err := exec.Command("schtasks", "/Delete", "/F", "/TN", "ostiary").CombinedOutput(); err != nil {
		return fmt.Errorf("schtasks: %v: %s", err, out)
	}
	return nil
}

func startService() error {
	if out, err := exec.Command("schtasks", "/Run", "/TN", "ostiary").CombinedOutput(); err != nil {
		return fmt.Errorf("schtasks: %v: %s", err, out)
	}
	return nil
}

func serviceInstalled() bool {
	return exec.Command("schtasks", "/Query", "/TN", "ostiary").Run() == nil
}

func fileExists0(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
