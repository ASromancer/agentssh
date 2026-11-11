// Command sign writes FILE.sig: base64(ed25519 signature of FILE) + newline.
// The key comes from OSTIARY_SIGNING_KEY (base64 of the 32-byte seed).
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "sign:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("usage: sign FILE")
	}
	seed, err := base64.StdEncoding.DecodeString(os.Getenv("OSTIARY_SIGNING_KEY"))
	if err != nil || len(seed) != ed25519.SeedSize {
		return fmt.Errorf("OSTIARY_SIGNING_KEY must be base64 of a %d-byte seed", ed25519.SeedSize)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		return err
	}
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), data)
	return os.WriteFile(os.Args[1]+".sig", []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644)
}
