package cmd

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	vaultcrypto "github.com/IT-Audit-Labs/vault-cli/crypto"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func zipEntry(t *testing.T, name string) *zip.File {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	entry, err := writer.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = entry.Write([]byte("local recovery fixture")); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := zip.NewReader(bytes.NewReader(buffer.Bytes()), int64(buffer.Len()))
	if err != nil {
		t.Fatal(err)
	}
	return reader.File[0]
}

func TestExtractZipFileDestination(t *testing.T) {
	for _, tc := range []struct {
		name, output, entry string
		reject              bool
	}{
		{"default directory", ".", "nested/item.txt", false},
		{"relative directory", "recovered", "nested/item.txt", false},
		{"traversal", "recovered", "../escape.txt", true},
		{"sibling prefix", "recovered", "../recovered-other/escape.txt", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			err := extractZipFile(zipEntry(t, tc.entry), tc.output)
			if tc.reject {
				if err == nil {
					t.Fatal("expected path rejection")
				}
				if _, err := os.Stat("escape.txt"); !os.IsNotExist(err) {
					t.Fatal("unexpected escaped output")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(filepath.Join(tc.output, tc.entry))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != "local recovery fixture" {
				t.Fatalf("wrong recovered contents: %q", got)
			}
		})
	}
}

func TestCLIRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("builds CLI integration binary")
	}
	root := t.TempDir()
	binary := filepath.Join(root, "vault-cli")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	if output, err := exec.Command("go", "build", "-o", binary, "..").CombinedOutput(); err != nil {
		t.Fatalf("build: %v: %s", err, output)
	}
	var zipBytes bytes.Buffer
	writer := zip.NewWriter(&zipBytes)
	file, err := writer.Create("nested/recovered.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.Write([]byte("synthetic export contents")); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	salt := []byte("0123456789abcdef")
	iv := []byte("0123456789ab")
	block, err := aes.NewCipher(vaultcrypto.DeriveKey("synthetic-passphrase", salt))
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	encrypted := append(append(append([]byte{}, salt...), iv...), gcm.Seal(nil, iv, zipBytes.Bytes(), nil)...)
	archive := filepath.Join(root, "synthetic.enc")
	if err = os.WriteFile(archive, encrypted, 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, passphrase string
		reject           bool
	}{
		{"valid recovery", "synthetic-passphrase", false},
		{"wrong passphrase", "incorrect", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outputDir := t.TempDir()
			command := exec.Command(binary, "decrypt", archive)
			command.Dir = outputDir
			command.Stdin = strings.NewReader(tc.passphrase + "\n")
			output, err := command.CombinedOutput()
			if tc.reject {
				if err == nil {
					t.Fatal("wrong passphrase accepted")
				}
				entries, readErr := os.ReadDir(outputDir)
				if readErr != nil || len(entries) != 0 {
					t.Fatal("rejected recovery created output")
				}
				return
			}
			if err != nil {
				t.Fatalf("CLI recovery: %v: %s", err, output)
			}
			recovered, err := os.ReadFile(filepath.Join(outputDir, "nested/recovered.txt"))
			if err != nil {
				t.Fatal(err)
			}
			if string(recovered) != "synthetic export contents" {
				t.Fatalf("wrong recovered contents: %q", recovered)
			}
		})
	}
}
