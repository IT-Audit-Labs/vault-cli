package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"testing"

	"golang.org/x/crypto/argon2"
)

// encrypt mirrors the Worker's encryptZipWithKey for test fixtures.
func encrypt(plaintext []byte, passphrase string) []byte {
	salt := make([]byte, SaltLength)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}

	key := argon2.IDKey(
		[]byte(passphrase),
		salt,
		Argon2idIterations,
		Argon2idMemory,
		Argon2idParallelism,
		Argon2idKeyLength,
	)

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	iv := make([]byte, IVLength)
	if _, err := rand.Read(iv); err != nil {
		panic(err)
	}

	ciphertext := gcm.Seal(nil, iv, plaintext, nil)

	// Wire format: salt | iv | ciphertext
	out := make([]byte, 0, SaltLength+IVLength+len(ciphertext))
	out = append(out, salt...)
	out = append(out, iv...)
	out = append(out, ciphertext...)
	return out
}

func TestDecryptExport_RoundTrip(t *testing.T) {
	plaintext := []byte("PK\x03\x04 this is a fake ZIP content for testing")
	passphrase := "correct-horse-battery-staple"

	encrypted := encrypt(plaintext, passphrase)
	decrypted, err := DecryptExport(encrypted, passphrase)
	if err != nil {
		t.Fatalf("DecryptExport failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("decrypted content does not match original")
	}
}

func TestDecryptExport_WrongPassphrase(t *testing.T) {
	plaintext := []byte("secret data")
	encrypted := encrypt(plaintext, "correct-passphrase")

	_, err := DecryptExport(encrypted, "wrong-passphrase")
	if err == nil {
		t.Fatal("expected error with wrong passphrase")
	}
}

func TestDecryptExport_EmptyPassphrase(t *testing.T) {
	_, err := DecryptExport(make([]byte, MinFileSize), "")
	if err == nil {
		t.Fatal("expected error with empty passphrase")
	}
}

func TestDecryptExport_FileTooSmall(t *testing.T) {
	_, err := DecryptExport(make([]byte, 10), "passphrase")
	if err == nil {
		t.Fatal("expected error for file too small")
	}
}

func TestDecryptExport_CorruptedData(t *testing.T) {
	encrypted := encrypt([]byte("data"), "passphrase")
	// Flip a byte in the ciphertext
	encrypted[len(encrypted)-5] ^= 0xFF

	_, err := DecryptExport(encrypted, "passphrase")
	if err == nil {
		t.Fatal("expected error for corrupted data")
	}
}

func TestDeriveKey_Deterministic(t *testing.T) {
	salt := []byte("1234567890123456") // 16 bytes
	key1 := DeriveKey("passphrase", salt)
	key2 := DeriveKey("passphrase", salt)

	if !bytes.Equal(key1, key2) {
		t.Fatal("same passphrase + salt should produce same key")
	}
}

func TestDeriveKey_DifferentSalt(t *testing.T) {
	salt1 := []byte("1234567890123456")
	salt2 := []byte("6543210987654321")

	key1 := DeriveKey("passphrase", salt1)
	key2 := DeriveKey("passphrase", salt2)

	if bytes.Equal(key1, key2) {
		t.Fatal("different salts should produce different keys")
	}
}

func TestDeriveKey_Length(t *testing.T) {
	salt := []byte("1234567890123456")
	key := DeriveKey("passphrase", salt)

	if len(key) != Argon2idKeyLength {
		t.Fatalf("expected key length %d, got %d", Argon2idKeyLength, len(key))
	}
}

// Pins the export key format across dependency upgrades, not just a round trip
// where both encryption and decryption could change together.
func TestDeriveKey_ExportCompatibility(t *testing.T) {
	got := DeriveKey("local-test-passphrase", []byte("0123456789abcdef"))
	want := "73ba82699e9ef36a4b93352ed15517191400abc5b2fa420aa1ff204fc6b83091"
	if fmt.Sprintf("%x", got) != want {
		t.Fatalf("export key mismatch: %x", got)
	}
}
