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
			err := extractZipFile(zipEntry(t, tc.entry), extractionRoot(t, tc.output))
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

func TestExtractZipFileRejectsSymlinkEscape(t *testing.T) {
	for _, kind := range []string{"directory", "file"} {
		t.Run(kind, func(t *testing.T) {
			output := t.TempDir()
			outside := t.TempDir()
			victim := filepath.Join(outside, "item.txt")
			if err := os.WriteFile(victim, []byte("must remain unchanged"), 0600); err != nil {
				t.Fatal(err)
			}
			target, link, entry := outside, filepath.Join(output, "nested"), "nested/item.txt"
			if kind == "file" {
				target, link, entry = victim, filepath.Join(output, "linked.txt"), "linked.txt"
			}
			if err := os.Symlink(target, link); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}
			if err := extractZipFile(zipEntry(t, entry), extractionRoot(t, output)); err == nil {
				t.Error("symlink escape accepted")
			}
			got, err := os.ReadFile(victim)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != "must remain unchanged" {
				t.Error("outside file was overwritten")
			}
		})
	}
}

func extractionRoot(t *testing.T, path string) *os.Root {
	t.Helper()
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root
}

func TestExtractZipFileAllowsInternalSymlink(t *testing.T) {
	output := t.TempDir()
	if err := os.Mkdir(filepath.Join(output, "actual"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("actual", filepath.Join(output, "alias")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := extractZipFile(zipEntry(t, "alias/item.txt"), extractionRoot(t, output)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(output, "actual/item.txt"))
	if err != nil || string(data) != "local recovery fixture" {
		t.Fatalf("internal symlink recovery failed: %v", err)
	}
}

func TestExtractZipDirectoryRejectsSymlinkEscape(t *testing.T) {
	output, outside := t.TempDir(), t.TempDir()
	if err := os.Symlink(outside, filepath.Join(output, "nested")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	entry := zipEntry(t, "unused")
	entry.Name = "nested/newdir/"
	if err := extractZipFile(entry, extractionRoot(t, output)); err == nil {
		t.Fatal("directory symlink escape accepted")
	}
	if _, err := os.Stat(filepath.Join(outside, "newdir")); !os.IsNotExist(err) {
		t.Fatal("outside directory created")
	}
}

func TestExtractZipFilePreservesOrdinaryOverwriteAndMetadata(t *testing.T) {
	output := t.TempDir()
	dest := filepath.Join(output, "item.txt")
	if err := os.WriteFile(dest, []byte("old contents"), 0600); err != nil {
		t.Fatal(err)
	}
	entry := zipEntry(t, "item.txt")
	entry.SetMode(os.ModeSymlink | 0755)
	if err := extractZipFile(entry, extractionRoot(t, output)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatal("archive metadata created a non-regular file")
	}
	data, err := os.ReadFile(dest)
	if err != nil || string(data) != "local recovery fixture" {
		t.Fatalf("overwrite failed: %v", err)
	}
}

func TestExtractZipFileRejectsAbsoluteInternalSymlink(t *testing.T) {
	output := t.TempDir()
	inside := filepath.Join(output, "actual")
	if err := os.Mkdir(inside, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(inside, filepath.Join(output, "alias")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := extractZipFile(zipEntry(t, "alias/item.txt"), extractionRoot(t, output)); err == nil {
		t.Fatal("absolute symlink accepted")
	}
	if _, err := os.Stat(filepath.Join(inside, "item.txt")); !os.IsNotExist(err) {
		t.Fatal("file created through absolute symlink")
	}
}
