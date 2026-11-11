// Package approval holds requests waiting for a human decision and the
// one-time codes that prove the human saw the out-of-band notification.
package approval

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/hiepnt01/agentssh/internal/policy"
)

type Request struct {
	ID      int             `json:"id"`
	Time    time.Time       `json:"time"`
	Host    string          `json:"host"`
	User    string          `json:"user"`
	Cwd     string          `json:"cwd"`
	Repo    string          `json:"repo"`
	Agent   string          `json:"agent"`
	Kind    string          `json:"kind"`
	Cmd     string          `json:"cmd"`
	Level   string          `json:"level"`
	Reasons []policy.Reason `json:"reasons"`
	// Code is only filled in when the desktop notification could not be
	// sent, so the human can still approve from a terminal (spec 7).
	Code string `json:"code,omitempty"`
}

type Decision struct {
	OK      bool
	Outcome string // approved|denied|timeout
	Message string // optional note from the human, passed back to the agent
	CodeOK  bool
	Sticky  bool
}

const (
	alphabet    = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // no 0 O 1 I
	maxTries    = 3
	StickyFor   = 30 * time.Minute
	TicketValid = 2 * time.Minute
)

var ErrBadCode = errors.New("bad code")

func NewCode() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

type entry struct {
	req     Request
	code    string
	tries   int
	decided bool
	done    chan Decision
}

type ticket struct {
	op, code string
	data     any
	tries    int
	expires  time.Time
}

type Queue struct {
	Notify  func(title, body string) error
	Timeout time.Duration

	mu         sync.Mutex
	pending    map[int]*entry
	sticky     map[string]time.Time
	tickets    map[int]*ticket
	nextTicket int
}

func NewQueue(notify func(title, body string) error, timeout time.Duration) *Queue {
	return &Queue{Notify: notify, Timeout: timeout, pending: map[int]*entry{},
		sticky: map[string]time.Time{}, tickets: map[int]*ticket{}}
}

func stickyKey(host, cmd string) string { return host + "\x00" + cmd }

// Sticky reports whether the same command on the same host was approved
// with "s" in the last 30 minutes.
func (q *Queue) Sticky(host, cmd string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	t, ok := q.sticky[stickyKey(host, cmd)]
	return ok && time.Now().Before(t)
}

// Add registers a request, notifies the human and starts its timeout.
// It returns whether the notification was delivered.
func (q *Queue) Add(r Request) bool {
	e := &entry{req: r, code: NewCode(), done: make(chan Decision, 1)}
	err := q.Notify("agentssh approval #"+fmt.Sprint(r.ID),
		fmt.Sprintf("%s: %s [%s] code: %s", r.Host, r.Cmd, r.Level, e.code))
	if err != nil {
		e.req.Code = e.code
	}
	q.mu.Lock()
	q.pending[r.ID] = e
	q.mu.Unlock()
	time.AfterFunc(q.Timeout, func() { q.finish(r.ID, Decision{Outcome: "timeout"}) })
	time.AfterFunc(q.Timeout+time.Minute, func() { // nobody waited for it
		q.mu.Lock()
		delete(q.pending, r.ID)
		q.mu.Unlock()
	})
	return err == nil
}

func (q *Queue) finish(id int, d Decision) {
	q.mu.Lock()
	defer q.mu.Unlock()
	e, ok := q.pending[id]
	if !ok || e.decided {
		return
	}
	e.decided = true
	if d.Sticky {
		q.sticky[stickyKey(e.req.Host, e.req.Cmd)] = time.Now().Add(StickyFor)
	}
	e.done <- d
}

// Wait blocks until request id is decided or times out. ok=false means the
// id is unknown.
func (q *Queue) Wait(id int) (Request, Decision, bool) {
	q.mu.Lock()
	e, ok := q.pending[id]
	q.mu.Unlock()
	if !ok {
		return Request{}, Decision{}, false
	}
	d := <-e.done
	q.mu.Lock()
	delete(q.pending, id)
	q.mu.Unlock()
	return e.req, d, true
}

func (q *Queue) Pending() []Request {
	q.mu.Lock()
	defer q.mu.Unlock()
	var out []Request
	for _, e := range q.pending {
		if !e.decided {
			out = append(out, e.req)
		}
	}
	return out
}

// Decide applies a human decision. choice: y (once), s (same command for
// 30 min), n (deny), m (deny with message). A wrong code returns ErrBadCode;
// the third wrong code denies the request.
func (q *Queue) Decide(id int, code, choice, msg string) (Decision, error) {
	q.mu.Lock()
	e, ok := q.pending[id]
	if !ok || e.decided {
		q.mu.Unlock()
		return Decision{}, fmt.Errorf("no pending request #%d", id)
	}
	if !strings.EqualFold(strings.TrimSpace(code), e.code) {
		e.tries++
		left := maxTries - e.tries
		q.mu.Unlock()
		if left <= 0 {
			q.finish(id, Decision{Outcome: "denied", Message: "wrong approval code entered 3 times"})
			return Decision{}, fmt.Errorf("%w: request denied after %d wrong codes", ErrBadCode, maxTries)
		}
		return Decision{}, fmt.Errorf("%w: %d tries left", ErrBadCode, left)
	}
	q.mu.Unlock()
	d := Decision{CodeOK: true}
	switch choice {
	case "y":
		d.OK, d.Outcome = true, "approved"
	case "s":
		d.OK, d.Outcome, d.Sticky = true, "approved", true
	case "n":
		d.Outcome = "denied"
	case "m":
		d.Outcome, d.Message = "denied", msg
	default:
		return Decision{}, fmt.Errorf("unknown choice %q", choice)
	}
	q.finish(id, d)
	return d, nil
}

// Ticket starts an admin operation: it sends a code out of band and
// returns the ticket id. data is handed back by Check (e.g. the host key
// whose fingerprint the human saw). code is returned only if the
// notification failed.
func (q *Queue) Ticket(op, detail string, data any) (id int, code string) {
	t := &ticket{op: op, code: NewCode(), data: data, expires: time.Now().Add(TicketValid)}
	q.mu.Lock()
	q.nextTicket++
	id = q.nextTicket
	q.tickets[id] = t
	q.mu.Unlock()
	body := fmt.Sprintf("admin: %s code: %s", op, t.code)
	if detail != "" {
		body = fmt.Sprintf("admin: %s (%s) code: %s", op, detail, t.code)
	}
	if err := q.Notify("agentssh", body); err != nil {
		return id, t.code
	}
	return id, ""
}

// Check verifies an admin code. A ticket is single-use and bound to op.
func (q *Queue) Check(id int, op, code string) (any, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	t, ok := q.tickets[id]
	if !ok || t.op != op || time.Now().After(t.expires) {
		delete(q.tickets, id)
		return nil, errors.New("approval ticket expired or invalid; start again")
	}
	if !strings.EqualFold(strings.TrimSpace(code), t.code) {
		t.tries++
		if t.tries >= maxTries {
			delete(q.tickets, id)
			return nil, fmt.Errorf("%w: ticket cancelled after %d wrong codes", ErrBadCode, maxTries)
		}
		return nil, fmt.Errorf("%w: %d tries left", ErrBadCode, maxTries-t.tries)
	}
	delete(q.tickets, id)
	return t.data, nil
}

// Desktop sends a desktop notification (notify-send / osascript).
func Desktop(title, body string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("notify-send", "-u", "critical", "-a", "agentssh", title, body)
	case "darwin":
		q := func(s string) string { return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"` }
		cmd = exec.Command("osascript", "-e", "display notification "+q(body)+" with title "+q(title))
	default:
		return errors.New("desktop notifications not supported on " + runtime.GOOS)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
