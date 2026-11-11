//go:build windows && !e2efake

package humanok

import (
	"context"
	"fmt"
	"os/user"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	credui     = windows.NewLazySystemDLL("credui.dll")
	advapi     = windows.NewLazySystemDLL("advapi32.dll")
	ole32      = windows.NewLazySystemDLL("ole32.dll")
	procPrompt = credui.NewProc("CredUIPromptForWindowsCredentialsW")
	procPack   = credui.NewProc("CredPackAuthenticationBufferW")
	procUnpack = credui.NewProc("CredUnPackAuthenticationBufferW")
	procLogon  = advapi.NewProc("LogonUserW")
	procFree   = ole32.NewProc("CoTaskMemFree")
)

type creduiInfo struct {
	cbSize         uint32
	hwndParent     uintptr
	pszMessageText *uint16
	pszCaptionText *uint16
	hbmBanner      uintptr
}

const (
	creduiwinGeneric     = 0x1
	creduiwinInCredOnly  = 0x20
	errorCancelled       = 1223
	logonInteractive     = 2
	logonProviderDefault = 0
)

type platform struct{}

func (platform) Available() error {
	for _, p := range []*windows.LazyProc{procPrompt, procPack, procUnpack, procLogon, procFree} {
		if err := p.Find(); err != nil {
			return fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
	}
	return nil
}

func ptr[T any](p *T) uintptr { return uintptr(unsafe.Pointer(p)) }

// Confirm asks for the current user's Windows password and checks it with
// LogonUserW; the resulting token must belong to the user running agentssh.
// ponytail: ctx is not honoured while the modal prompt is open.
func (platform) Confirm(_ context.Context, msg string) error {
	u, err := user.Current()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	caption, _ := windows.UTF16PtrFromString("agentssh")
	text, _ := windows.UTF16PtrFromString(msg)
	info := creduiInfo{cbSize: uint32(unsafe.Sizeof(creduiInfo{})), pszMessageText: text, pszCaptionText: caption}

	// Pre-fill the current account so the prompt asks only for its password.
	name, _ := windows.UTF16PtrFromString(u.Username)
	empty, _ := windows.UTF16PtrFromString("")
	var inSize uint32
	procPack.Call(0, ptr(name), ptr(empty), 0, ptr(&inSize))
	in := make([]byte, inSize)
	if r, _, e := procPack.Call(0, ptr(name), ptr(empty), ptr(&in[0]), ptr(&inSize)); r == 0 {
		return fmt.Errorf("%w: pack: %v", ErrUnavailable, e)
	}

	var authPkg, outSize uint32
	var out uintptr
	var save int32
	r, _, _ := procPrompt.Call(ptr(&info), 0, ptr(&authPkg), ptr(&in[0]), uintptr(inSize),
		ptr(&out), ptr(&outSize), ptr(&save), creduiwinGeneric|creduiwinInCredOnly)
	if r == errorCancelled {
		return ErrDenied
	}
	if r != 0 {
		return fmt.Errorf("%w: credential prompt error %d", ErrUnavailable, r)
	}
	defer procFree.Call(out)

	var userBuf, domBuf, passBuf [512]uint16
	un, dn, pn := uint32(len(userBuf)), uint32(len(domBuf)), uint32(len(passBuf))
	defer clear(passBuf[:])
	if r, _, e := procUnpack.Call(0, out, uintptr(outSize), ptr(&userBuf[0]), ptr(&un),
		ptr(&domBuf[0]), ptr(&dn), ptr(&passBuf[0]), ptr(&pn)); r == 0 {
		return fmt.Errorf("%w: unpack: %v", ErrUnavailable, e)
	}
	account := windows.UTF16ToString(userBuf[:])
	domain := windows.UTF16ToString(domBuf[:])
	if d, n, ok := strings.Cut(account, `\`); ok && domain == "" {
		domain, account = d, n
	}
	acc16, _ := windows.UTF16PtrFromString(account)
	dom16, _ := windows.UTF16PtrFromString(domain)
	var tok windows.Token
	if r, _, _ := procLogon.Call(ptr(acc16), ptr(dom16), ptr(&passBuf[0]), logonInteractive, logonProviderDefault, ptr(&tok)); r == 0 {
		return ErrDenied
	}
	defer tok.Close()
	got, err := tok.GetTokenUser()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	me, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if !windows.EqualSid(got.User.Sid, me.User.Sid) {
		return fmt.Errorf("%w: credentials of another account", ErrDenied)
	}
	return nil
}
