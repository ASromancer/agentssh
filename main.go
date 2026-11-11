// Command ostiary lets AI agents run commands on servers over SSH without
// ever seeing private keys, with deterministic policy, approvals and audit.
package main

import (
	"os"

	"github.com/ASromancer/ostiary/internal/cli"
)

func main() { os.Exit(cli.Main(os.Args[1:])) }
