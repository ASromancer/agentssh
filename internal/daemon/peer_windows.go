package daemon

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

func umask(int) int { return 0 }

// SIO_AF_UNIX_GETPEERPID = _WSAIOR(IOC_VENDOR, 256)
const sioAfUnixGetPeerPid = 0x58000100

// samePeerUser compares the token user SID of the peer process with ours.
func samePeerUser(fd uintptr) error {
	var pid, n uint32
	if err := windows.WSAIoctl(windows.Handle(fd), sioAfUnixGetPeerPid, nil, 0,
		(*byte)(unsafe.Pointer(&pid)), uint32(unsafe.Sizeof(pid)), &n, nil, 0); err != nil {
		return fmt.Errorf("get peer pid: %w", err)
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return fmt.Errorf("open peer process %d: %w", pid, err)
	}
	defer windows.CloseHandle(h)
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return err
	}
	defer tok.Close()
	peer, err := tok.GetTokenUser()
	if err != nil {
		return err
	}
	me, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	if !windows.EqualSid(peer.User.Sid, me.User.Sid) {
		return errors.New("peer process runs as another user")
	}
	return nil
}
