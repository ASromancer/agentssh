//go:build !(linux || windows || (darwin && cgo))

package tray

type Options struct {
	URL     string
	Pending func() int
	Lock    func() error
	Open    func(string) error
}

func Supported() bool { return false }

func Run(o Options, done <-chan struct{}) { <-done }
