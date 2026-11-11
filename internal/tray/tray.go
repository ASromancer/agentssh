//go:build linux || windows || (darwin && cgo)

// Package tray shows ostiary in the system tray: the pending count, and a
// menu to open the UI, lock the vault or hide the icon.
package tray

import (
	"log"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"

	"fyne.io/systray"
)

type Options struct {
	Login   func() string // mints a one-time login URL
	Pending func() int
	Lock    func() error
	Open    func(string) error
}

// Supported reports whether a tray can be shown in this session.
func Supported() bool {
	if runtime.GOOS == "linux" {
		return os.Getenv("DBUS_SESSION_BUS_ADDRESS") != ""
	}
	return true
}

// Run shows the tray until done is closed. It must run on the main
// goroutine (macOS). Hiding the icon keeps the daemon running.
func Run(o Options, done <-chan struct{}) {
	// An upstream panic (e.g. at shutdown on a failed D-Bus connect) must not take the daemon down.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("tray: %v", r)
		}
	}()
	var once sync.Once
	quit := func() { once.Do(systray.Quit) }
	systray.Run(func() {
		systray.SetIcon(Icon(runtime.GOOS))
		systray.SetTooltip(Title(0))
		open := systray.AddMenuItem("Mở Ostiary", "Mở trang quản lý Ostiary")
		lock := systray.AddMenuItem("Khóa vault", "Xóa key khỏi bộ nhớ daemon")
		systray.AddSeparator()
		hide := systray.AddMenuItem("Ẩn biểu tượng", "Ẩn tới lần khởi động sau")
		go func() {
			t := time.NewTicker(2 * time.Second)
			defer t.Stop()
			last := -1
			for {
				select {
				case <-open.ClickedCh:
					_ = o.Open(o.Login())
				case <-lock.ClickedCh:
					_ = o.Lock()
				case <-hide.ClickedCh:
					quit()
					return
				case <-done:
					return
				case <-t.C:
					if n := o.Pending(); n != last {
						last = n
						systray.SetTooltip(Title(n))
						if runtime.GOOS == "darwin" {
							title := ""
							if n > 0 {
								title = strconv.Itoa(n)
							}
							systray.SetTitle(title)
						}
					}
				}
			}
		}()
		// Started last: Quit before the Windows window exists is lost.
		go func() { <-done; quit() }()
	}, func() {})
	<-done
}
