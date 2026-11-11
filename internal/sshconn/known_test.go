package sshconn

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestKnown(t *testing.T) {
	f := filepath.Join(t.TempDir(), "known_hosts")
	if Known(f, "10.0.0.5:22") {
		t.Fatal("missing file counts as unknown")
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, _ := ssh.NewPublicKey(pub)
	if err := Trust(f, "10.0.0.5:1611", k); err != nil {
		t.Fatal(err)
	}
	if !Known(f, "10.0.0.5:1611") || Known(f, "10.0.0.5:22") || Known(f, "10.0.0.6:1611") {
		t.Fatal("Known mismatch")
	}
}
