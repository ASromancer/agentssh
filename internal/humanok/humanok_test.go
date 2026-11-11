package humanok

import (
	"context"
	"encoding/xml"
	"errors"
	"strings"
	"testing"
)

func TestFake(t *testing.T) {
	f := &Fake{Allow: true}
	if err := f.Confirm(context.Background(), "a"); err != nil {
		t.Fatal(err)
	}
	f.Allow = false
	if err := f.Confirm(context.Background(), "b"); !errors.Is(err, ErrDenied) {
		t.Fatalf("got %v", err)
	}
	if got := strings.Join(f.Msgs(), ","); got != "a,b" {
		t.Fatalf("msgs %q", got)
	}
}

func TestPolicyXML(t *testing.T) {
	var p struct {
		Action struct {
			ID       string `xml:"id,attr"`
			Message  string `xml:"message"`
			Defaults struct {
				Active string `xml:"allow_active"`
			} `xml:"defaults"`
			Owner struct {
				Key   string `xml:"key,attr"`
				Value string `xml:",chardata"`
			} `xml:"annotate"`
		} `xml:"action"`
	}
	if err := xml.Unmarshal([]byte(PolicyXML("alice")), &p); err != nil {
		t.Fatal(err)
	}
	if p.Action.ID != ActionID || p.Action.Defaults.Active != "auth_self" || !strings.Contains(p.Action.Message, "$(message)") ||
		p.Action.Owner.Key != "org.freedesktop.policykit.owner" || p.Action.Owner.Value != "unix-user:alice" {
		t.Fatalf("%+v", p.Action)
	}
}
