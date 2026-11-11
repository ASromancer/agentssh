package approval

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

type sink struct{ last, link string }

func (s *sink) notify(n Notice) error { s.last, s.link = n.Body, n.Link; return nil }
func (s *sink) code() string          { return s.last[strings.LastIndex(s.last, " ")+1:] }

func TestWrongCodeThreeTimes(t *testing.T) {
	s := &sink{}
	q := NewQueue(s.notify, time.Minute)
	q.Add(Request{ID: 1, Host: "web1", Cmd: "rm x"})
	for i := 0; i < 3; i++ {
		if _, err := q.Decide(1, "ZZZZ", "y", ""); !errors.Is(err, ErrBadCode) {
			t.Fatalf("try %d: %v", i, err)
		}
	}
	_, d, _ := q.Wait(1)
	if d.OK || d.Outcome != "denied" {
		t.Fatalf("%+v", d)
	}
}

func TestTimeout(t *testing.T) {
	q := NewQueue((&sink{}).notify, 50*time.Millisecond)
	q.Add(Request{ID: 7})
	_, d, ok := q.Wait(7)
	if !ok || d.OK || d.Outcome != "timeout" {
		t.Fatalf("%+v", d)
	}
}

func TestStickyOnlySameCommand(t *testing.T) {
	s := &sink{}
	q := NewQueue(s.notify, time.Minute)
	q.Add(Request{ID: 2, Host: "web1", Cmd: "rm /tmp/a"})
	if _, err := q.Decide(2, strings.ToLower(s.code()), "s", ""); err != nil {
		t.Fatal(err)
	}
	if _, d, _ := q.Wait(2); !d.OK {
		t.Fatal("not approved")
	}
	if !q.Sticky("web1", "rm /tmp/a") || q.Sticky("web1", "rm /tmp/b") || q.Sticky("web2", "rm /tmp/a") {
		t.Fatal("sticky scope wrong")
	}
}

func TestDenyWithMessage(t *testing.T) {
	s := &sink{}
	q := NewQueue(s.notify, time.Minute)
	q.Add(Request{ID: 3})
	q.Decide(3, s.code(), "m", "use logrotate instead")
	if _, d, _ := q.Wait(3); d.OK || d.Message != "use logrotate instead" {
		t.Fatalf("%+v", d)
	}
}

func TestNotifyFailureExposesCode(t *testing.T) {
	q := NewQueue(func(Notice) error { return errors.New("no display") }, time.Minute)
	q.Add(Request{ID: 4})
	if p := q.Pending(); len(p) != 1 || len(p[0].Code) != 4 {
		t.Fatalf("%+v", p)
	}
}

func TestTicket(t *testing.T) {
	s := &sink{}
	q := NewQueue(s.notify, time.Minute)
	id, shown := q.Ticket("key-rm a", "", 42)
	if shown != "" {
		t.Fatal("code shown although notification worked")
	}
	code := s.code()
	if _, err := q.Check(id, "key-export a", code); err == nil {
		t.Fatal("ticket accepted for a different op")
	}
	id, _ = q.Ticket("key-rm a", "", 42)
	code = s.code()
	if v, err := q.Check(id, "key-rm a", code); err != nil || v != 42 {
		t.Fatalf("%v %v", v, err)
	}
	if _, err := q.Check(id, "key-rm a", code); err == nil {
		t.Fatal("ticket reused")
	}
}

func TestWaitForLimit(t *testing.T) {
	s := &sink{}
	q := NewQueue(s.notify, time.Minute)
	q.Add(Request{ID: 9})
	if _, _, done, ok := q.WaitFor(9, 20*time.Millisecond); done || !ok {
		t.Fatalf("done=%v ok=%v", done, ok)
	}
	q.Decide(9, s.code(), "y", "")
	if _, d, done, _ := q.WaitFor(9, time.Second); !done || !d.OK {
		t.Fatalf("after decision: %+v", d)
	}
}

func TestResolveWithoutCode(t *testing.T) {
	s := &sink{}
	q := NewQueue(s.notify, time.Minute)
	q.UseCodes = func() bool { return false }
	q.Add(Request{ID: 11, Host: "web1", Cmd: "rm x", Level: "destructive"})
	if strings.Contains(s.last, "code:") {
		t.Fatalf("notification leaks a code in OS-auth mode: %q", s.last)
	}
	if r, ok := q.Get(11); !ok || r.Cmd != "rm x" || r.Code != "" {
		t.Fatalf("get: %+v %v", r, ok)
	}
	if _, err := q.Resolve(11, "s", "", "os"); err != nil {
		t.Fatal(err)
	}
	_, d, _ := q.Wait(11)
	if !d.OK || d.Auth != "os" || !d.CodeOK || !q.Sticky("web1", "rm x") {
		t.Fatalf("%+v", d)
	}
	if _, err := q.Resolve(11, "y", "", "os"); err == nil {
		t.Fatal("resolved twice")
	}
}

func TestCodeDecisionAuth(t *testing.T) {
	s := &sink{}
	q := NewQueue(s.notify, time.Minute)
	q.Add(Request{ID: 12})
	q.Decide(12, s.code(), "y", "")
	if _, d, _ := q.Wait(12); d.Auth != "code" {
		t.Fatalf("auth %q", d.Auth)
	}
}

func TestTakeTicket(t *testing.T) {
	s := &sink{}
	q := NewQueue(s.notify, time.Minute)
	q.UseCodes = func() bool { return false }
	s.last = ""
	id, code := q.Ticket("key-rm a", "", 7)
	if code != "" || s.last != "" {
		t.Fatalf("OS-auth tickets must not notify a code: %q %q", code, s.last)
	}
	if _, err := q.Take(id, "key-rm b"); err == nil {
		t.Fatal("ticket taken for another op")
	}
	id, _ = q.Ticket("key-rm a", "", 7)
	if v, err := q.Take(id, "key-rm a"); err != nil || v != 7 {
		t.Fatalf("%v %v", v, err)
	}
	if _, err := q.Take(id, "key-rm a"); err == nil {
		t.Fatal("ticket reused")
	}
}

func TestResolveApprovalNeedsAuth(t *testing.T) {
	q := NewQueue((&sink{}).notify, time.Minute)
	q.Add(Request{ID: 20, Host: "web1", Cmd: "rm x"})
	if _, err := q.Resolve(20, "y", "", "none"); err == nil {
		t.Fatal("approval accepted without auth")
	}
	if _, ok := q.Get(20); !ok {
		t.Fatal("request no longer pending after rejected approval")
	}
}

func TestResolveDenyWithoutAuth(t *testing.T) {
	q := NewQueue((&sink{}).notify, time.Minute)
	q.Add(Request{ID: 21})
	if _, err := q.Resolve(21, "n", "", "none"); err != nil {
		t.Fatal(err)
	}
	if _, d, _ := q.Wait(21); d.OK || d.Outcome != "denied" || d.Auth != "none" {
		t.Fatalf("%+v", d)
	}
}

func TestResolveUnknownAuth(t *testing.T) {
	q := NewQueue((&sink{}).notify, time.Minute)
	q.Add(Request{ID: 22})
	if _, err := q.Resolve(22, "n", "", "password"); err == nil {
		t.Fatal("unknown auth accepted")
	}
	if _, ok := q.Get(22); !ok {
		t.Fatal("request decided by rejected call")
	}
}

func TestResolveAfterTimeout(t *testing.T) {
	q := NewQueue((&sink{}).notify, 10*time.Millisecond)
	q.Add(Request{ID: 23})
	time.Sleep(30 * time.Millisecond)
	if _, err := q.Resolve(23, "y", "", "os"); err == nil {
		t.Fatal("resolved after timeout")
	}
	if _, d, _ := q.Wait(23); d.OK || d.Outcome != "timeout" {
		t.Fatalf("%+v", d)
	}
}

func TestResolveRacingDecisions(t *testing.T) {
	for i := 0; i < 200; i++ {
		q := NewQueue((&sink{}).notify, time.Minute)
		q.Add(Request{ID: 30})
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for j, c := range []string{"y", "n"} {
			wg.Add(1)
			go func(j int, c string) {
				defer wg.Done()
				_, errs[j] = q.Resolve(30, c, "", "os")
			}(j, c)
		}
		wg.Wait()
		if (errs[0] == nil) == (errs[1] == nil) {
			t.Fatalf("iteration %d: want exactly one winner, got %v / %v", i, errs[0], errs[1])
		}
	}
}

func TestTicketIDsRandom(t *testing.T) {
	q := NewQueue((&sink{}).notify, time.Minute)
	a, _ := q.Ticket("reload", "", nil)
	b, _ := q.Ticket("reload", "", nil)
	if a <= 0 || b <= 0 || a == b || b == a+1 || a == b+1 {
		t.Fatalf("ticket ids %d, %d: want random positive ids", a, b)
	}
	// the web UI parses ids as JS numbers: they must stay exact
	for i := 0; i < 1000; i++ {
		if id, _ := q.Ticket("reload", "", nil); id > maxJSInt {
			t.Fatalf("ticket id %d exceeds 2^53-1", id)
		}
	}
}

func TestOSModeNotifyFailureHidesCode(t *testing.T) {
	q := NewQueue(func(Notice) error { return errors.New("no display") }, time.Minute)
	q.UseCodes = func() bool { return false }
	q.Add(Request{ID: 40})
	if p := q.Pending(); len(p) != 1 || p[0].Code != "" {
		t.Fatalf("pending exposes a code in OS mode: %+v", p)
	}
	if r, ok := q.Get(40); !ok || r.Code != "" {
		t.Fatalf("get exposes a code in OS mode: %+v", r)
	}
}

func TestNotifyEnv(t *testing.T) {
	env := []string{"LD_PRELOAD=/tmp/evil.so", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1/bus",
		"XDG_RUNTIME_DIR=/run/user/1", "DISPLAY=:0", "WAYLAND_DISPLAY=wayland-0", "HOME=/home/u",
		"LANG=C.UTF-8", "LC_ALL=C", "PATH=/tmp/evil", "DBUS_SYSTEM_BUS_ADDRESS=x", "display=:9",
		"SystemRoot=C:\\Windows", "TEMP=C:\\t", "OSTIARY_TITLE=forged"}
	got := strings.Join(notifyEnv(env, "linux"), " ")
	if want := "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1/bus XDG_RUNTIME_DIR=/run/user/1 DISPLAY=:0 WAYLAND_DISPLAY=wayland-0 HOME=/home/u LANG=C.UTF-8 LC_ALL=C"; got != want {
		t.Errorf("linux:\n got %s\nwant %s", got, want)
	}
	got = strings.Join(notifyEnv(env, "windows"), " ")
	for _, w := range []string{"SystemRoot=C:\\Windows", "TEMP=C:\\t", "display=:9", "HOME=/home/u"} {
		if !strings.Contains(got, w) {
			t.Errorf("windows: missing %s in %s", w, got)
		}
	}
	for _, bad := range []string{"LD_PRELOAD", "PATH=", "DBUS_SYSTEM", "OSTIARY_TITLE"} {
		if strings.Contains(got, bad) {
			t.Errorf("windows: %s leaked into %s", bad, got)
		}
	}
}

func TestNoticeLink(t *testing.T) {
	s := &sink{}
	q := NewQueue(s.notify, time.Minute)
	q.UseCodes = func() bool { return false }
	q.Add(Request{ID: 3, Host: "web1", Cmd: "rm x", Level: "destructive"})
	if s.link != "" {
		t.Fatalf("link without Queue.Link: %q", s.link)
	}
	q.Link = func(id int) string { return fmt.Sprintf("http://127.0.0.1:1/#req=%d", id) }
	q.Add(Request{ID: 4, Host: "web1", Cmd: "rm y", Level: "destructive"})
	if s.link != "http://127.0.0.1:1/#req=4" {
		t.Fatalf("link %q", s.link)
	}
	q.UseCodes = func() bool { return true }
	q.Add(Request{ID: 5, Host: "web1", Cmd: "rm z", Level: "destructive"})
	if s.link != "" {
		t.Fatalf("code mode must send no link: %q", s.link)
	}
	q.Ticket("key-rm a", "", nil)
	if s.link != "" {
		t.Fatalf("admin notices carry no link: %q", s.link)
	}
}

func TestLinuxNotifyArgs(t *testing.T) {
	plain := linuxNotifyArgs(Notice{Title: "t", Body: "b"})
	if strings.Join(plain, " ") != "-u critical -a ostiary -- t b" {
		t.Fatalf("plain %q", plain)
	}
	linked := strings.Join(linuxNotifyArgs(Notice{Title: "t", Body: "b", Link: "http://127.0.0.1:9/"}), " ")
	if linked != "-u critical -a ostiary -A open=Mở --wait -- t b" {
		t.Fatalf("linked %q", linked)
	}
}

func TestExpiresSet(t *testing.T) {
	q := NewQueue((&sink{}).notify, time.Minute)
	before := time.Now()
	q.Add(Request{ID: 3})
	p := q.Pending()
	if len(p) != 1 || p[0].Expires.Before(before.Add(time.Minute)) || p[0].Expires.After(time.Now().Add(time.Minute)) {
		t.Fatalf("%+v", p)
	}
}
