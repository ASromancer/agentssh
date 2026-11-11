package vault

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "vault.bin")
	k := NewKey()
	in := &Data{Keys: map[string][]byte{"web1": []byte("PEM")}, ConfigHash: "abc"}
	if err := Save(p, k, nil, in); err != nil {
		t.Fatal(err)
	}
	if s, err := Salt(p); err != nil || s != nil {
		t.Fatalf("salt=%v err=%v", s, err)
	}
	out, err := Open(p, k)
	if err != nil || string(out.Keys["web1"]) != "PEM" || out.ConfigHash != "abc" {
		t.Fatalf("got %+v %v", out, err)
	}
	if _, err := Open(p, NewKey()); err != ErrBadKey {
		t.Fatalf("wrong key: %v", err)
	}
	out.Wipe()
	if len(out.Keys) != 0 {
		t.Fatal("wipe")
	}
}

func TestPassphrase(t *testing.T) {
	p := filepath.Join(t.TempDir(), "vault.bin")
	salt := NewSalt()
	if err := Save(p, DeriveKey([]byte("pw"), salt), salt, &Data{}); err != nil {
		t.Fatal(err)
	}
	s, _ := Salt(p)
	if _, err := Open(p, DeriveKey([]byte("pw"), s)); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(p, DeriveKey([]byte("nope"), s)); err != ErrBadKey {
		t.Fatalf("wrong passphrase: %v", err)
	}
}

func TestCreateNeverReplaces(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.bin")
	k := NewKey()
	if err := Create(p, k, nil, &Data{}); err != nil {
		t.Fatal(err)
	}
	if err := Create(p, NewKey(), nil, &Data{}); !errors.Is(err, os.ErrExist) {
		t.Fatalf("second create: %v", err)
	}
	if _, err := Open(p, k); err != nil {
		t.Fatalf("original vault damaged: %v", err)
	}
}
