//go:build darwin && cgo && !e2efake

package humanok

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework LocalAuthentication -framework Foundation
#import <LocalAuthentication/LocalAuthentication.h>
#include <stdlib.h>

static int la_available(void) {
	LAContext *c = [[LAContext alloc] init];
	return [c canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:nil] ? 1 : 0;
}

// 0 = authenticated, 1 = refused or cancelled, 2 = could not run.
static int la_confirm(const char *reason) {
	__block int result = 2;
	dispatch_semaphore_t sem = dispatch_semaphore_create(0);
	LAContext *c = [[LAContext alloc] init];
	[c evaluatePolicy:LAPolicyDeviceOwnerAuthentication
	  localizedReason:[NSString stringWithUTF8String:reason]
	            reply:^(BOOL ok, NSError *err) {
		if (ok) {
			result = 0;
		} else if (err.code == LAErrorUserCancel || err.code == LAErrorAuthenticationFailed ||
		           err.code == LAErrorAppCancel || err.code == LAErrorSystemCancel || err.code == LAErrorUserFallback) {
			result = 1;
		}
		dispatch_semaphore_signal(sem);
	}];
	dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
	return result;
}
*/
import "C"

import (
	"context"
	"fmt"
	"unsafe"
)

type platform struct{}

func (platform) Available() error {
	if C.la_available() == 0 {
		return fmt.Errorf("%w: LocalAuthentication cannot evaluate device-owner authentication", ErrUnavailable)
	}
	return nil
}

// ponytail: ctx is not honoured once the dialog is up (LAContext has no
// simple cancel from here); the dialog itself times out with the session.
func (platform) Confirm(_ context.Context, msg string) error {
	cs := C.CString(msg)
	defer C.free(unsafe.Pointer(cs))
	switch C.la_confirm(cs) {
	case 0:
		return nil
	case 1:
		return ErrDenied
	}
	return fmt.Errorf("%w: LocalAuthentication failed", ErrUnavailable)
}
