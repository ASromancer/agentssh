package daemon

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// ReadOutput returns a stored output, optionally limited to a line range "a:b" (1-based, inclusive) and filtered by a regexp (with line numbers).
func ReadOutput(id int, grep, rng string) (string, error) {
	b, err := os.ReadFile(OutPath(id))
	if err != nil {
		return "", fmt.Errorf("no output for id %d (outputs are kept 7 days)", id)
	}
	lines := strings.SplitAfter(string(b), "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	from, to := 1, len(lines)
	if rng != "" {
		a, z, ok := strings.Cut(rng, ":")
		if !ok {
			return "", errors.New("range must look like a:b")
		}
		if a != "" {
			from, _ = strconv.Atoi(a)
		}
		if z != "" {
			to, _ = strconv.Atoi(z)
		}
		from, to = max(from, 1), min(to, len(lines))
	}
	var re *regexp.Regexp
	if grep != "" {
		if re, err = regexp.Compile(grep); err != nil {
			return "", fmt.Errorf("bad grep: %v", err)
		}
	}
	var out strings.Builder
	for i := from; i <= to; i++ {
		l := strings.TrimSuffix(lines[i-1], "\n")
		if re == nil {
			out.WriteString(l + "\n")
		} else if re.MatchString(l) {
			fmt.Fprintf(&out, "%d: %s\n", i, l)
		}
	}
	return out.String(), nil
}
