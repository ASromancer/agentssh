// Package approval holds requests waiting for a human decision and the
// one-time codes that prove the human saw the out-of-band notification.
package approval

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ASromancer/agentssh/internal/humanok"
	"github.com/ASromancer/agentssh/internal/policy"
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

// Notice is one desktop notification. Link, when set, is opened if the
// human clicks the notification (Linux and Windows).
type Notice struct{ Title, Body, Link string }

type Decision struct {
	OK      bool
	Outcome string // approved|denied|timeout
	Message string // optional note from the human, passed back to the agent
	CodeOK  bool
	Sticky  bool
	Auth    string // code|os|none
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
	Notify  func(Notice) error
	Timeout time.Duration
	// Link returns the UI address of a request, shown as the notification's
	// click target. nil means no link. Set it before the queue is used.
	Link func(id int) string
	// UseCodes reports whether approvals use out-of-band codes. When it
	// returns false, the daemon authenticates the human through the OS and
	// notifications carry no code. nil means true.
	UseCodes func() bool

	mu      sync.Mutex
	pending map[int]*entry
	sticky  map[string]time.Time
	tickets map[int]*ticket
}

func NewQueue(notify func(Notice) error, timeout time.Duration) *Queue {
	return &Queue{Notify: notify, Timeout: timeout, pending: map[int]*entry{},
		sticky: map[string]time.Time{}, tickets: map[int]*ticket{}}
}

func stickyKey(host, cmd string) string { return host + "\x00" + cmd }

func (q *Queue) codes() bool { return q.UseCodes == nil || q.UseCodes() }

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
	codes := q.codes()
	body := fmt.Sprintf("%s: %s [%s] code: %s", r.Host, r.Cmd, r.Level, e.code)
	if !codes {
		body = fmt.Sprintf("%s: %s [%s] — open agentssh to approve", r.Host, r.Cmd, r.Level)
	}
	link := ""
	if q.Link != nil && !codes {
		link = q.Link(r.ID)
	}
	err := q.Notify(Notice{Title: "agentssh approval #" + fmt.Sprint(r.ID), Body: body, Link: link})
	if err != nil && codes {
		e.req.Code = e.code
	}
	q.mu.Lock()
	q.pending[r.ID] = e
	q.mu.Unlock()
	time.AfterFunc(q.Timeout, func() { _ = q.finish(r.ID, Decision{Outcome: "timeout"}) })
	time.AfterFunc(q.Timeout+time.Minute, func() { // nobody waited for it
		q.mu.Lock()
		delete(q.pending, r.ID)
		q.mu.Unlock()
	})
	return err == nil
}

// finish records d as the decision for id. It returns false, and changes
// nothing, when the request is unknown or already decided.
func (q *Queue) finish(id int, d Decision) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	e, ok := q.pending[id]
	if !ok || e.decided {
		return false
	}
	e.decided = true
	if d.Sticky {
		q.sticky[stickyKey(e.req.Host, e.req.Cmd)] = time.Now().Add(StickyFor)
	}
	e.done <- d
	return true
}

// Wait blocks until request id is decided or times out. ok=false means the
// id is unknown.
func (q *Queue) Wait(id int) (Request, Decision, bool) {
	r, d, _, ok := q.WaitFor(id, 0)
	return r, d, ok
}

// WaitFor is Wait with a limit: done=false means the human has not
// decided within max (0 = no limit) and the request is still pending.
func (q *Queue) WaitFor(id int, max time.Duration) (r Request, d Decision, done, ok bool) {
	q.mu.Lock()
	e, ok := q.pending[id]
	q.mu.Unlock()
	if !ok {
		return Request{}, Decision{}, false, false
	}
	var limit <-chan time.Time
	if max > 0 {
		limit = time.After(max)
	}
	select {
	case d = <-e.done:
	case <-limit:
		return e.req, Decision{}, false, true
	}
	q.mu.Lock()
	delete(q.pending, id)
	q.mu.Unlock()
	return e.req, d, true, true
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
			_ = q.finish(id, Decision{Outcome: "denied", Message: "wrong approval code entered 3 times"})
			return Decision{}, fmt.Errorf("%w: request denied after %d wrong codes", ErrBadCode, maxTries)
		}
		return Decision{}, fmt.Errorf("%w: %d tries left", ErrBadCode, left)
	}
	q.mu.Unlock()
	return q.Resolve(id, choice, msg, "code")
}

// Resolve applies a decision whose human proof was already checked by the
// caller (OS authentication), or that needs none (denials).
func (q *Queue) Resolve(id int, choice, msg, auth string) (Decision, error) {
	switch auth {
	case "code", "os", "none":
	default:
		return Decision{}, fmt.Errorf("unknown auth %q", auth)
	}
	q.mu.Lock()
	e, ok := q.pending[id]
	decided := ok && e.decided
	q.mu.Unlock()
	if !ok || decided {
		return Decision{}, fmt.Errorf("no pending request #%d", id)
	}
	d := Decision{CodeOK: auth == "code" || auth == "os", Auth: auth}
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
	if d.OK && !d.CodeOK {
		return Decision{}, errors.New("approval needs a code or OS authentication")
	}
	if !q.finish(id, d) {
		return Decision{}, fmt.Errorf("request #%d was already decided", id)
	}
	return d, nil
}

// Get returns a pending, undecided request.
func (q *Queue) Get(id int) (Request, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	e, ok := q.pending[id]
	if !ok || e.decided {
		return Request{}, false
	}
	return e.req, true
}

// Ticket starts an admin operation: it sends a code out of band and
// returns the ticket id, a random positive number so that another caller
// cannot guess and take the human's ticket. data is handed back by Check (e.g. the host key
// whose fingerprint the human saw). code is returned only if the
// notification failed.
func (q *Queue) Ticket(op, detail string, data any) (id int, code string) {
	t := &ticket{op: op, code: NewCode(), data: data, expires: time.Now().Add(TicketValid)}
	q.mu.Lock()
	for id == 0 || q.tickets[id] != nil {
		n, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt))
		if err != nil {
			panic(err)
		}
		id = int(n.Int64()) + 1 // 1..MaxInt
	}
	q.tickets[id] = t
	q.mu.Unlock()
	body := fmt.Sprintf("admin: %s code: %s", op, t.code)
	if detail != "" {
		body = fmt.Sprintf("admin: %s (%s) code: %s", op, detail, t.code)
	}
	if !q.codes() {
		return id, ""
	}
	if err := q.Notify(Notice{Title: "agentssh", Body: body}); err != nil {
		return id, t.code
	}
	return id, ""
}

// Take consumes a ticket without a code; the caller authenticates the
// human through the OS instead.
func (q *Queue) Take(id int, op string) (any, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	t, ok := q.tickets[id]
	delete(q.tickets, id)
	if !ok || t.op != op || time.Now().After(t.expires) {
		return nil, errors.New("approval ticket expired or invalid; start again")
	}
	return t.data, nil
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

// Desktop sends a desktop notification (notify-send / osascript /
// powershell). The helper is run only from a root-owned system path, never
// found through PATH; without one, Desktop fails and the code is shown in
// the terminal instead. A Link is opened when the human clicks the
// notification (Linux: notify-send action; Windows: toast launch).
func Desktop(n Notice) error {
	var cands []string
	switch runtime.GOOS {
	case "linux":
		cands = []string{"/usr/bin/notify-send", "/bin/notify-send"}
	case "darwin":
		cands = []string{"/usr/bin/osascript"}
	case "windows":
		cands = []string{filepath.Join(humanok.SystemDir(), "WindowsPowerShell", "v1.0", "powershell.exe")}
	default:
		return errors.New("desktop notifications not supported on " + runtime.GOOS)
	}
	bin, err := humanok.TrustedBinary(cands...)
	if err != nil {
		return err
	}
	if n.Link != "" && !LocalURL(n.Link) {
		n.Link = ""
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command(bin, linuxNotifyArgs(n)...)
	case "darwin":
		q := func(s string) string { return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"` }
		cmd = exec.Command(bin, "-e", "display notification "+q(n.Body)+" with title "+q(n.Title))
	case "windows":
		// Title, body and link go through the environment, never into the script.
		cmd = exec.Command(bin, "-NoProfile", "-NonInteractive", "-Command", windowsToast)
	}
	cmd.Env = append(notifyEnv(os.Environ(), runtime.GOOS),
		"AGENTSSH_TITLE="+n.Title, "AGENTSSH_BODY="+n.Body, "AGENTSSH_LINK="+n.Link)
	if runtime.GOOS == "linux" && n.Link != "" {
		return waitForClick(cmd, n)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func linuxNotifyArgs(n Notice) []string {
	args := []string{"-u", "critical", "-a", "agentssh"}
	if n.Link != "" {
		args = append(args, "-A", "open=Mở", "--wait")
	}
	return append(args, "--", n.Title, n.Body)
}

// waitForClick runs a notify-send that waits for its action. It returns
// once the notification is up; a later click on "Mở" opens the link. An
// old notify-send without -A/--wait fails at once: retry without the link.
func waitForClick(cmd *exec.Cmd, n Notice) error {
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return Desktop(Notice{Title: n.Title, Body: n.Body})
		}
		if strings.TrimSpace(out.String()) == "open" {
			_ = OpenURL(n.Link)
		}
		return nil
	case <-time.After(300 * time.Millisecond):
		go func() {
			if <-done == nil && strings.TrimSpace(out.String()) == "open" {
				_ = OpenURL(n.Link)
			}
		}()
		return nil
	}
}

// notifyEnv keeps only the variables a notifier needs. The daemon's
// environment is not trusted (an agent can change it and restart the
// daemon), so LD_PRELOAD, PATH and the like never reach the helper.
func notifyEnv(environ []string, goos string) []string {
	keep := []string{"DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR", "DISPLAY", "WAYLAND_DISPLAY", "HOME", "LANG", "LC_ALL"}
	if goos == "windows" {
		keep = append(keep, "SystemRoot", "USERPROFILE", "TEMP", "TMP", "LOCALAPPDATA", "APPDATA")
	}
	var out []string
	for _, kv := range environ {
		k, _, _ := strings.Cut(kv, "=")
		for _, w := range keep {
			if k == w || (goos == "windows" && strings.EqualFold(k, w)) {
				out = append(out, kv)
				break
			}
		}
	}
	return out
}

// windowsToast shows a toast as Windows PowerShell's own app id, which is
// registered on every Windows 10/11 install.
const windowsToast = `$ErrorActionPreference = 'Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
$t = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$x = $t.GetElementsByTagName('text')
$x.Item(0).AppendChild($t.CreateTextNode($env:AGENTSSH_TITLE)) | Out-Null
$x.Item(1).AppendChild($t.CreateTextNode($env:AGENTSSH_BODY)) | Out-Null
if ($env:AGENTSSH_LINK) { $t.DocumentElement.SetAttribute('activationType', 'protocol'); $t.DocumentElement.SetAttribute('launch', $env:AGENTSSH_LINK) }
$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show([Windows.UI.Notifications.ToastNotification]::new($t))`
