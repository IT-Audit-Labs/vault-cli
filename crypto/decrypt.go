// Package crypto implements the offline decryption of CisoView Vault export packs.
//
// Wire format: salt(16) | iv(12) | ciphertext
// Key derivation: Argon2id with m=19456, t=3, p=1, hashLen=32
// Encryption: AES-256-GCM
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	// Argon2id parameters — MUST match the Worker's export-zip-service.ts
	Argon2idMemory      = 19456 // 19MB
	Argon2idIterations  = 3
	Argon2idParallelism = 1
	Argon2idKeyLength   = 32 // AES-256

	SaltLength = 16
	IVLength   = 12

	// Minimum file size: salt + iv + at least 1 byte of ciphertext + 16 byte GCM tag
	MinFileSize = SaltLength + IVLength + 1 + 16
)

// DecryptExport decrypts a CisoView Vault export pack.
//
// The input is the raw bytes of the .enc file. The passphrase is the one
// the user set when creating the export pack in the Vault UI.
//
// Returns the decrypted ZIP bytes on success.
func DecryptExport(encryptedData []byte, passphrase string) ([]byte, error) {
	if len(encryptedData) < MinFileSize {
		return nil, fmt.Errorf("file too small (%d bytes), minimum is %d", len(encryptedData), MinFileSize)
	}

	if passphrase == "" {
		return nil, errors.New("passphrase cannot be empty")
	}

	// Parse wire format: salt(16) | iv(12) | ciphertext
	salt := encryptedData[:SaltLength]
	iv := encryptedData[SaltLength : SaltLength+IVLength]
	ciphertext := encryptedData[SaltLength+IVLength:]

	// Derive key with Argon2id
	key := DeriveKey(passphrase, salt)

	// Decrypt with AES-256-GCM
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed — wrong passphrase or corrupted file: %w", err)
	}

	return plaintext, nil
}

// DeriveKey derives a 32-byte AES-256 key from a passphrase and salt using Argon2id.
// Parameters match the CisoView Vault Worker exactly.
func DeriveKey(passphrase string, salt []byte) []byte {
	return argon2.IDKey(
		[]byte(passphrase),
		salt,
		Argon2idIterations,
		Argon2idMemory,
		Argon2idParallelism,
		Argon2idKeyLength,
	)
}
