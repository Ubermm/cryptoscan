// Command cryptoscan is the CLI entrypoint for the cryptoscan cryptographic
// estate scanner.
package main

import (
	"os"

	"github.com/cryptoscan/cryptoscan/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
