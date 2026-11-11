// Command brandgen writes ostiary.ico and ostiary.icns for the installers.
// Usage: go run ./tools/brandgen -out DIR
package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"

	"github.com/ASromancer/ostiary/internal/brand"
)

func main() {
	out := flag.String("out", ".", "output directory")
	flag.Parse()
	if err := os.MkdirAll(*out, 0o755); err != nil {
		log.Fatal(err)
	}
	for name, b := range map[string][]byte{
		"ostiary.ico":  brand.ICO(16, 32, 48, 64, 128, 256),
		"ostiary.icns": brand.ICNS(),
	} {
		if err := os.WriteFile(filepath.Join(*out, name), b, 0o644); err != nil {
			log.Fatal(err)
		}
	}
}
