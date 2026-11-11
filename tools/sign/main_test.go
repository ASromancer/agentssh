package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestSignVerifyRoundtrip(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 7
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	f := filepath.Join(t.TempDir(), "SHA256SUMS")
	if err := os.WriteFile(f, []byte("abc  file\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := signFile(f, base64.StdEncoding.EncodeToString(seed)); err != nil {
		t.Fatal(err)
	}
	if err := verifyFile(f, pub); err != nil {
		t.Fatal(err)
	}
	other := make([]byte, ed25519.SeedSize)
	otherPub := ed25519.NewKeyFromSeed(other).Public().(ed25519.PublicKey)
	if verifyFile(f, otherPub) == nil {
		t.Fatal("verified with the wrong key")
	}
	if signFile(f, "bad") == nil {
		t.Fatal("accepted a bad key")
	}
}
