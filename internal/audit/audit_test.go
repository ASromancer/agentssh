package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestWriteTruncates(t *testing.T) {
	l := &Log{Path: filepath.Join(t.TempDir(), "a.jsonl")}
	// 3-byte runes so the cut lands mid-rune
	big := strings.Repeat("€", 40000)
	if err := l.Write(Entry{Kind: "run", Cmd: big, Note: big, Decision: "allow"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(l.Path)
	var e Entry
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{e.Cmd, e.Note} {
		if !strings.HasSuffix(s, "…") || len(s) > maxField+3 || !utf8.ValidString(s) {
			t.Fatalf("not clipped: len=%d", len(s))
		}
	}
	if err := l.Write(Entry{Kind: "run", Cmd: "ls"}); err != nil {
		t.Fatal(err)
	}
}
