// Package policy classifies shell commands deterministically into risk levels
// and decides what to do with them under a host profile.
package policy

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

type Level int

const (
	Read Level = iota
	Mutate
	Destructive
	Forbidden
)

var levelNames = []string{"read", "mutate", "destructive", "forbidden"}

func (l Level) String() string {
	if l < 0 || int(l) >= len(levelNames) {
		return fmt.Sprintf("level(%d)", int(l))
	}
	return levelNames[l]
}

func ParseLevel(s string) (Level, error) {
	for i, n := range levelNames {
		if n == s {
			return Level(i), nil
		}
	}
	return 0, fmt.Errorf("unknown level %q", s)
}

func (l Level) MarshalText() ([]byte, error) { return []byte(l.String()), nil }
func (l *Level) UnmarshalText(b []byte) (err error) {
	*l, err = ParseLevel(string(b))
	return err
}

// Reason explains why part of a command got its level. Start/End are byte
// offsets into the original command, used to highlight it during approval.
type Reason struct {
	Level Level  `json:"level"`
	Text  string `json:"text"`
	Start int    `json:"start"`
	End   int    `json:"end"`
}

type Result struct {
	Level   Level    `json:"level"`
	Reasons []Reason `json:"reasons"`
}

type Rule struct {
	Level Level    `toml:"level"`
	Match []string `toml:"match"`
}

type pattern struct {
	level Level
	text  string
	re    *regexp.Regexp
}

type Engine struct{ rules []pattern }

//go:embed rules.toml
var defaultRules string

// New builds an engine from the embedded default rules, with extra rules
// taking priority over them.
func New(extra []Rule) (*Engine, error) {
	var def struct{ Rule []Rule }
	if _, err := toml.Decode(defaultRules, &def); err != nil {
		return nil, err
	}
	e := &Engine{}
	for _, r := range append(extra, def.Rule...) {
		for _, m := range r.Match {
			e.rules = append(e.rules, pattern{r.Level, m, compile(m)})
		}
	}
	return e, nil
}

// Load builds an engine with the user's rules.toml (if it exists) on top of the defaults.
func Load(path string) (*Engine, error) {
	var user struct{ Rule []Rule }
	if _, err := toml.DecodeFile(path, &user); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return New(user.Rule)
}

// compile turns a glob-ish pattern into an anchored regexp: "*" matches
// anything and trailing arguments are always allowed.
func compile(p string) *regexp.Regexp {
	q := strings.ReplaceAll(regexp.QuoteMeta(p), `\*`, `.*`)
	return regexp.MustCompile(`(?s)^` + q + `( .*)?$`)
}

// Match reports whether a command line matches any of the given patterns.
func Match(patterns []string, line string) bool {
	for _, p := range patterns {
		if compile(p).MatchString(line) {
			return true
		}
	}
	return false
}

func (e *Engine) lookup(line string) (Level, string, bool) {
	for _, r := range e.rules {
		if r.re.MatchString(line) {
			return r.level, r.text, true
		}
	}
	return Mutate, "", false
}

// Profiles, from most to least restrictive.
const (
	ProfileReadonly = "readonly"
	ProfileStandard = "standard"
	ProfileFull     = "full"
)

var profileRank = map[string]int{ProfileReadonly: 0, ProfileStandard: 1, ProfileFull: 2}

func ValidProfile(p string) bool { _, ok := profileRank[p]; return ok }

// Stricter returns the more restrictive of two profiles. Empty means "no limit".
func Stricter(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" || profileRank[a] <= profileRank[b] {
		return a
	}
	return b
}

type Action int

const (
	Run     Action = iota // run right away
	Ask                   // run, but the agent hook should ask the user first (soft layer)
	Approve               // needs out-of-band approval through the daemon
	Block
)

func (a Action) String() string { return [...]string{"run", "ask", "approve", "block"}[a] }

// Decide maps a level to an action under a host profile (spec 4.3).
func Decide(l Level, profile string) Action {
	switch {
	case l == Forbidden:
		return Block
	case l == Read:
		return Run
	case profile == ProfileReadonly:
		return Block
	case l == Destructive:
		return Approve
	case profile == ProfileFull:
		return Run
	default:
		return Ask
	}
}
