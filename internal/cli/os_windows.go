package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"

	"github.com/ASromancer/agentssh/internal/paths"
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

// startDetached runs "agentssh daemon" without a console window.
func startDetached(logPath string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	c := exec.Command(exe, "daemon", "--log", logPath)
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
// then starts it now.
func installService() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	tr := fmt.Sprintf(`"%s" daemon --detach`, exe)
	if out, err := exec.Command("schtasks", "/Create", "/F", "/SC", "ONLOGON", "/RL", "LIMITED",
		"/TN", "agentssh", "/TR", tr).CombinedOutput(); err != nil {
		return fmt.Errorf("schtasks: %v: %s", err, out)
	}
	if err := startDetached(filepath.Join(paths.State(), "daemon.log")); err != nil {
		return err
	}
	fmt.Println("logon task 'agentssh' installed")
	return nil
}
