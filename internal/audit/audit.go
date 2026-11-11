// Package audit appends one JSON line per action. Command output is never
// written here (it lives in the out/ directory and expires after 7 days).
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Entry struct {
	Time       time.Time `json:"time"`
	ID         int       `json:"id,omitempty"`
	Kind       string    `json:"kind"` // run|job|get|put|admin|approve
	Agent      string    `json:"agent,omitempty"`
	Cwd        string    `json:"cwd,omitempty"`
	Repo       string    `json:"repo,omitempty"`
	Host       string    `json:"host,omitempty"`
	Cmd        string    `json:"cmd"`
	Level      string    `json:"level,omitempty"`
	Decision   string    `json:"decision"` // allow|ask|approved|denied|forbidden|blocked|timeout|error
	CodeOK     *bool     `json:"code_ok,omitempty"`
	Auth       string    `json:"auth,omitempty"` // code|os|passphrase|none
	Exit       *int      `json:"exit,omitempty"`
	DurationMs int64     `json:"duration_ms,omitempty"`
	Bytes      int64     `json:"bytes,omitempty"`
	Note       string    `json:"note,omitempty"`
}

type Log struct {
	mu   sync.Mutex
	Path string
}

const maxField = 64 << 10

// clip cuts s to maxField bytes at a rune boundary and marks the cut.
func clip(s string) string {
	if len(s) <= maxField {
		return s
	}
	return strings.ToValidUTF8(s[:maxField], "") + "…"
}

func (l *Log) Write(e Entry) error {
	e.Cmd, e.Note = clip(e.Cmd), clip(e.Note)
	e.Agent, e.Cwd, e.Repo, e.Host = clip(e.Agent), clip(e.Cwd), clip(e.Repo), clip(e.Host)
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(l.Path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(l.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(b, '\n'))
	return err
}
