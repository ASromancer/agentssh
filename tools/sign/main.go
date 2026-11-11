// Command sign writes FILE.sig: base64(ed25519 signature of FILE) + newline.
// The key comes from OSTIARY_SIGNING_KEY (base64 of the 32-byte seed).
// With -verify it instead checks FILE.sig against the public key embedded in the binary.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/ASromancer/ostiary/internal/update"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "sign:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 2 && args[0] == "-verify" {
		return verifyFile(args[1], update.PublicKey())
	}
	if len(args) != 1 {
		return fmt.Errorf("usage: sign [-verify] FILE")
	}
	return signFile(args[0], os.Getenv("OSTIARY_SIGNING_KEY"))
}

func signFile(path, keyB64 string) error {
	seed, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil || len(seed) != ed25519.SeedSize {
		return fmt.Errorf("OSTIARY_SIGNING_KEY must be base64 of a %d-byte seed", ed25519.SeedSize)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), data)
	return os.WriteFile(path+".sig", []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644)
}

func verifyFile(path string, pub ed25519.PublicKey) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(path + ".sig")
	if err != nil {
		return err
	}
	return update.Verify(data, sig, pub)
}
