//go:build windows && !e2efake

package humanok

import (
	"context"
	"fmt"
	"os/user"
	"runtime"
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

// Confirm asks for the current user's Windows password and checks it with
// LogonUserW; the resulting token must belong to the user running agentssh.
// ponytail: ctx is not honoured while the modal prompt is open.
func (platform) Confirm(_ context.Context, msg string) error {
	u, err := user.Current()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	caption, err := windows.UTF16PtrFromString("agentssh")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	text, err := windows.UTF16PtrFromString(strings.ReplaceAll(msg, "\x00", ""))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	info := creduiInfo{cbSize: uint32(unsafe.Sizeof(creduiInfo{})), pszMessageText: text, pszCaptionText: caption}

	// Pre-fill the current account so the prompt asks only for its password.
	name, err := windows.UTF16PtrFromString(u.Username)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	empty, err := windows.UTF16PtrFromString("")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	var inSize uint32
	procPack.Call(0, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(empty)), 0, uintptr(unsafe.Pointer(&inSize)))
	if inSize == 0 {
		return fmt.Errorf("%w: pack size query failed", ErrUnavailable)
	}
	in := make([]byte, inSize)
	r, _, e := procPack.Call(0, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(empty)),
		uintptr(unsafe.Pointer(&in[0])), uintptr(unsafe.Pointer(&inSize)))
	runtime.KeepAlive(name)
	runtime.KeepAlive(empty)
	runtime.KeepAlive(in)
	if r == 0 {
		return fmt.Errorf("%w: pack: %v", ErrUnavailable, e)
	}

	var authPkg, outSize uint32
	var out *byte
	var save int32
	r, _, _ = procPrompt.Call(uintptr(unsafe.Pointer(&info)), 0, uintptr(unsafe.Pointer(&authPkg)),
		uintptr(unsafe.Pointer(&in[0])), uintptr(inSize),
		uintptr(unsafe.Pointer(&out)), uintptr(unsafe.Pointer(&outSize)), uintptr(unsafe.Pointer(&save)),
		creduiwinGeneric|creduiwinInCredOnly)
	runtime.KeepAlive(&info)
	runtime.KeepAlive(text)
	runtime.KeepAlive(caption)
	runtime.KeepAlive(in)
	if r == errorCancelled {
		return ErrDenied
	}
	if r != 0 {
		return fmt.Errorf("%w: credential prompt error %d", ErrUnavailable, r)
	}
	if out == nil {
		return fmt.Errorf("%w: credential prompt returned no buffer", ErrUnavailable)
	}
	// Deferred calls run last-in first-out: zero the typed credential, then free it.
	defer procFree.Call(uintptr(unsafe.Pointer(out)))
	defer clear(unsafe.Slice(out, outSize))

	var userBuf, domBuf, passBuf [512]uint16
	un, dn, pn := uint32(len(userBuf)), uint32(len(domBuf)), uint32(len(passBuf))
	defer clear(passBuf[:])
	if r, _, e := procUnpack.Call(0, uintptr(unsafe.Pointer(out)), uintptr(outSize),
		uintptr(unsafe.Pointer(&userBuf[0])), uintptr(unsafe.Pointer(&un)),
		uintptr(unsafe.Pointer(&domBuf[0])), uintptr(unsafe.Pointer(&dn)),
		uintptr(unsafe.Pointer(&passBuf[0])), uintptr(unsafe.Pointer(&pn))); r == 0 {
		return fmt.Errorf("%w: unpack: %v", ErrUnavailable, e)
	}
	account := windows.UTF16ToString(userBuf[:])
	domain := windows.UTF16ToString(domBuf[:])
	if d, n, ok := strings.Cut(account, `\`); ok && domain == "" {
		domain, account = d, n
	}
	acc16, err := windows.UTF16PtrFromString(account)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	dom16, err := windows.UTF16PtrFromString(domain)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	var tok windows.Token
	r, _, _ = procLogon.Call(uintptr(unsafe.Pointer(acc16)), uintptr(unsafe.Pointer(dom16)),
		uintptr(unsafe.Pointer(&passBuf[0])), logonInteractive, logonProviderDefault,
		uintptr(unsafe.Pointer(&tok)))
	runtime.KeepAlive(acc16)
	runtime.KeepAlive(dom16)
	if r == 0 {
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
