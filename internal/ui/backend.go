package ui

import (
	"github.com/ASromancer/agentssh/internal/approval"
	"github.com/ASromancer/agentssh/internal/daemon"
)

// Backend is what the UI needs from the daemon. ServiceBackend calls the
// daemon's RPC methods in-process, so plan A's OS authentication and every
// policy check apply exactly as for the CLI.
type Backend interface {
	Status() (daemon.StatusReply, error)
	Pending() ([]approval.Request, error)
	Decide(a daemon.DecideArgs) error
	HostList() (daemon.HostListReply, error)
	Begin(a daemon.BeginArgs) (daemon.BeginReply, error)
	Admin(a daemon.AdminArgs) (daemon.AdminReply, error)
	Unlock(pass string) error
	Lock() error
	Keys() ([]string, error)
}

type ServiceBackend struct{ S *daemon.Service }

func (b ServiceBackend) Status() (r daemon.StatusReply, err error) {
	err = b.S.Status(&daemon.Empty{}, &r)
	return
}
func (b ServiceBackend) Pending() (r []approval.Request, err error) {
	err = b.S.Pending(&daemon.Empty{}, &r)
	return
}
func (b ServiceBackend) Decide(a daemon.DecideArgs) error { return b.S.Decide(&a, &daemon.Empty{}) }
func (b ServiceBackend) HostList() (r daemon.HostListReply, err error) {
	err = b.S.HostList(&daemon.Empty{}, &r)
	return
}
func (b ServiceBackend) Begin(a daemon.BeginArgs) (r daemon.BeginReply, err error) {
	err = b.S.Begin(&a, &r)
	return
}
func (b ServiceBackend) Admin(a daemon.AdminArgs) (r daemon.AdminReply, err error) {
	err = b.S.Admin(&a, &r)
	return
}
func (b ServiceBackend) Unlock(pass string) error {
	return b.S.Unlock(&daemon.UnlockArgs{Pass: pass}, &daemon.Empty{})
}
func (b ServiceBackend) Lock() error { return b.S.Lock(&daemon.Empty{}, &daemon.Empty{}) }
func (b ServiceBackend) Keys() ([]string, error) {
	var r daemon.KeysReply
	err := b.S.Keys(&daemon.Empty{}, &r)
	return r.Keys, err
}
