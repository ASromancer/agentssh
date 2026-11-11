//go:build linux || darwin

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
)

func openConsole() (in, out *os.File, err error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	return f, f, err
}

func echoOff(in *os.File) (restore func()) {
	stty := func(arg string) {
		c := exec.Command("stty", arg)
		c.Stdin = in
		_ = c.Run()
	}
	stty("-echo")
	return func() { stty("echo") }
}

// startDetached runs "agentssh daemon" in its own session, logging to logPath.
func startDetached(logPath string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	c := exec.Command(exe, "daemon", "--log", logPath)
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := c.Start(); err != nil {
		return err
	}
	fmt.Printf("daemon started (pid %d, log %s)\n", c.Process.Pid, logPath)
	return c.Process.Release()
}

func installService() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "linux":
		p := filepath.Join(home, ".config", "systemd", "user", "agentssh.service")
		unit := fmt.Sprintf("[Unit]\nDescription=agentssh daemon\n\n[Service]\nExecStart=%s daemon\nRestart=on-failure\n\n[Install]\nWantedBy=default.target\n", exe)
		if err := writeFile(p, unit); err != nil {
			return err
		}
		if out, err := exec.Command("systemctl", "--user", "daemon-reload").CombinedOutput(); err != nil {
			return fmt.Errorf("%v: %s", err, out)
		}
		if out, err := exec.Command("systemctl", "--user", "enable", "--now", "agentssh.service").CombinedOutput(); err != nil {
			return fmt.Errorf("%v: %s", err, out)
		}
	case "darwin":
		p := filepath.Join(home, "Library", "LaunchAgents", "dev.agentssh.plist")
		plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>dev.agentssh</string>
  <key>ProgramArguments</key><array><string>%s</string><string>daemon</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict></plist>
`, exe)
		if err := writeFile(p, plist); err != nil {
			return err
		}
		if out, err := exec.Command("launchctl", "load", "-w", p).CombinedOutput(); err != nil {
			return fmt.Errorf("%v: %s", err, out)
		}
	default: // unreachable: build tags limit this file to linux and darwin
		return fmt.Errorf("no service manager support for %s; run 'agentssh daemon' yourself", runtime.GOOS)
	}
	fmt.Println("service installed and started")
	return nil
}
