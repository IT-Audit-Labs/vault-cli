// vault-cli — Offline decryptor for CisoView Vault export packs.
//
// Export packs are encrypted with AES-256-GCM using an Argon2id-derived key.
// Wire format: salt(16 bytes) | iv(12 bytes) | ciphertext
// Argon2id params: m=19456 (19MB), t=3, p=1, hashLen=32
//
// Usage:
//
//	vault-cli decrypt export.zip.enc -o ./output/
//	vault-cli decrypt export.zip.enc                   # extracts to current dir
package main

import (
	"fmt"
	"os"

	"github.com/IT-Audit-Labs/vault-cli/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
