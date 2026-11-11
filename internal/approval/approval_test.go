package approval

import (
	"errors"
	"strings"
	"testing"
	"time"
)

type sink struct{ last string }

func (s *sink) notify(_, body string) error { s.last = body; return nil }
func (s *sink) code() string                { return s.last[strings.LastIndex(s.last, " ")+1:] }

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
	q := NewQueue(func(_, _ string) error { return errors.New("no display") }, time.Minute)
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
