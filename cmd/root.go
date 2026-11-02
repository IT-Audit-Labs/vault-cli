// Package cmd implements the CLI commands for vault-cli.
package cmd

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/IT-Audit-Labs/vault-cli/crypto"
	"golang.org/x/term"
)

func Execute() error {
	if len(os.Args) < 2 {
		printUsage()
		return nil
	}

	switch os.Args[1] {
	case "decrypt":
		return runDecrypt()
	case "version":
		fmt.Println("vault-cli v0.1.0")
		return nil
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		return fmt.Errorf("unknown command: %s\nRun 'vault-cli help' for usage", os.Args[1])
	}
}

func printUsage() {
	fmt.Print(`vault-cli — Offline decryptor for CisoView Vault export packs.

Usage:
  vault-cli decrypt <file.enc> [-o output_dir]
  vault-cli version
  vault-cli help

Commands:
  decrypt    Decrypt an encrypted export pack (.enc file)
  version    Print version
  help       Show this help

Decrypt options:
  -o, --output   Output directory (default: current directory)

Examples:
  vault-cli decrypt export-2026-04-23.zip.enc
  vault-cli decrypt export-2026-04-23.zip.enc -o ./recovery/

Wire format: salt(16) | iv(12) | ciphertext(AES-256-GCM)
Key derivation: Argon2id (m=19456, t=3, p=1)
`)
}

func runDecrypt() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("missing input file\nUsage: vault-cli decrypt <file.enc> [-o output_dir]")
	}

	inputFile := os.Args[2]
	outputDir := "."

	// Parse flags
	for i := 3; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-o", "--output":
			if i+1 >= len(os.Args) {
				return fmt.Errorf("-o requires an output directory")
			}
			outputDir = os.Args[i+1]
			i++
		default:
			return fmt.Errorf("unknown flag: %s", os.Args[i])
		}
	}

	// Read encrypted file
	data, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("cannot read file: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Encrypted file: %s (%d bytes)\n", inputFile, len(data))

	// Read passphrase securely (no echo)
	passphrase, err := readPassphrase()
	if err != nil {
		return fmt.Errorf("failed to read passphrase: %w", err)
	}

	// Decrypt
	fmt.Fprintf(os.Stderr, "Deriving key (Argon2id, m=%dKB)... ", crypto.Argon2idMemory)
	zipData, err := crypto.DecryptExport(data, passphrase)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "done.")

	// Verify it's a ZIP
	if len(zipData) < 4 || string(zipData[:2]) != "PK" {
		// Not a ZIP — write raw decrypted output
		outPath := filepath.Join(outputDir, strings.TrimSuffix(filepath.Base(inputFile), ".enc"))
		if err := os.MkdirAll(outputDir, 0o755); err != nil {
			return fmt.Errorf("cannot create output directory: %w", err)
		}
		if err := os.WriteFile(outPath, zipData, 0o600); err != nil {
			return fmt.Errorf("cannot write output: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Decrypted to: %s\n", outPath)
		return nil
	}

	// Extract ZIP
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("cannot create output directory: %w", err)
	}

	reader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return fmt.Errorf("cannot read ZIP: %w", err)
	}

	extracted := 0
	for _, f := range reader.File {
		if err := extractZipFile(f, outputDir); err != nil {
			return fmt.Errorf("failed to extract %s: %w", f.Name, err)
		}
		extracted++
	}

	fmt.Fprintf(os.Stderr, "Extracted %d files to: %s\n", extracted, outputDir)
	return nil
}

func readPassphrase() (string, error) {
	fmt.Fprint(os.Stderr, "Passphrase: ")

	// Check if stdin is a terminal
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		pw, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr) // newline after hidden input
		if err != nil {
			return "", err
		}
		return string(pw), nil
	}

	// Piped input — read line
	var buf [4096]byte
	n, err := os.Stdin.Read(buf[:])
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimRight(string(buf[:n]), "\r\n"), nil
}

func extractZipFile(f *zip.File, outputDir string) error {
	// Security: prevent zip slip (path traversal)
	destPath := filepath.Join(outputDir, f.Name)
	relativePath, err := filepath.Rel(outputDir, destPath)
	if err != nil || !filepath.IsLocal(relativePath) {
		return fmt.Errorf("illegal file path: %s", f.Name)
	}

	if f.FileInfo().IsDir() {
		return os.MkdirAll(destPath, 0o755)
	}

	// Create parent dirs
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return err
	}

	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode()|0o600)
	if err != nil {
		return err
	}
	defer out.Close()

	// Limit extraction size (100MB per file — prevents zip bombs)
	_, err = io.Copy(out, io.LimitReader(rc, 100*1024*1024))
	return err
}
