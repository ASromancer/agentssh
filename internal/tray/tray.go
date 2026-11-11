//go:build linux || windows || (darwin && cgo)

// Package tray shows agentssh in the system tray: the pending count, and a
// menu to open the UI, lock the vault or hide the icon.
package tray

import (
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"

	"fyne.io/systray"
)

type Options struct {
	URL     string
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
	var once sync.Once
	quit := func() { once.Do(systray.Quit) }
	go func() { <-done; quit() }()
	systray.Run(func() {
		systray.SetIcon(Icon(runtime.GOOS))
		systray.SetTooltip(Title(0))
		open := systray.AddMenuItem("Mở agentssh", "Mở trang quản lý agentssh")
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
					_ = o.Open(o.URL)
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
	}, func() {})
	<-done
}
