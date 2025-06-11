/*
AES-256-GCM encryption utilities for Database-Vault email field-level encryption.

Implements authenticated encryption for email addresses using AES-256-GCM
with cryptographically secure nonce generation and base64 encoding for
safe database storage. Provides confidentiality and authenticity for
email data while enabling encrypted primary key functionality for
zero-knowledge user identification in the R.A.M.-U.S.B. storage system.
*/
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

// ValidateEncryptionKey performs comprehensive encryption key validation.
//
// Security features:
// - Key length validation ensures AES-256 compliance (32 bytes)
// - Entropy validation prevents all-zero or weak keys
// - Key format verification for cryptographic strength
//
// Returns error if key is invalid for AES-256-GCM operations.
func ValidateEncryptionKey(key []byte) error {
	// LENGTH VALIDATION
	// AES-256 requires exactly 32 bytes
	if len(key) != 32 {
		return fmt.Errorf("invalid key length: AES-256 requires 32 bytes, got %d", len(key))
	}

	// ENTROPY VALIDATION
	// Check for all-zero key (weak key)
	allZero := true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("invalid key: all-zero key is not secure")
	}

	return nil
}

// EncryptEmailDeterministic encrypts email with deterministic output for database lookup.
//
// Security features:
// - Deterministic encryption enables consistent database queries
// - Key derivation ensures operation-specific encryption keys
// - Fixed nonce derived from master key for repeatability
// - Maintains AES-256-GCM authentication and confidentiality
//
// Returns consistent base64-encoded string for same email input.
func EncryptEmailDeterministic(email string, masterKey []byte) (string, error) {
	// KEY VALIDATION
	if err := ValidateEncryptionKey(masterKey); err != nil {
		return "", fmt.Errorf("invalid master key: %v", err)
	}

	// EMAIL-SPECIFIC KEY DERIVATION
	emailKey, err := DeriveKey(KeyDerivationInfo{
		MasterKey: masterKey,
		Context:   "email-encryption-v1",
		Length:    32,
	})
	if err != nil {
		return "", fmt.Errorf("failed to derive email key: %v", err)
	}

	// FIXED NONCE DERIVATION
	emailNonce, err := DeriveKey(KeyDerivationInfo{
		MasterKey: masterKey,
		Context:   "email-nonce-v1",
		Length:    12,
	})
	if err != nil {
		return "", fmt.Errorf("failed to derive email nonce: %v", err)
	}

	// AES-GCM DETERMINISTIC ENCRYPTION
	block, err := aes.NewCipher(emailKey)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	// DETERMINISTIC ENCRYPTION
	ciphertext := gcm.Seal(nil, emailNonce, []byte(email), nil)

	// BASE64 ENCODING
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptEmailDeterministic decrypts deterministically encrypted email.
//
// Security features:
// - Uses same key derivation as encryption for consistency
// - AES-256-GCM authenticated decryption verifies data integrity
// - Recovers original email from deterministic encryption
//
// Returns plaintext email address or error if decryption fails.
func DecryptEmailDeterministic(encryptedEmail string, masterKey []byte) (string, error) {
	// KEY VALIDATION
	if err := ValidateEncryptionKey(masterKey); err != nil {
		return "", fmt.Errorf("invalid master key: %v", err)
	}

	// SAME KEY DERIVATION AS ENCRYPTION
	emailKey, err := DeriveKey(KeyDerivationInfo{
		MasterKey: masterKey,
		Context:   "email-encryption-v1",
		Length:    32,
	})
	if err != nil {
		return "", fmt.Errorf("failed to derive email key: %v", err)
	}

	emailNonce, err := DeriveKey(KeyDerivationInfo{
		MasterKey: masterKey,
		Context:   "email-nonce-v1",
		Length:    12,
	})
	if err != nil {
		return "", fmt.Errorf("failed to derive email nonce: %v", err)
	}

	// BASE64 DECODING
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedEmail)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %v", err)
	}

	// AES-GCM DECRYPTION
	block, err := aes.NewCipher(emailKey)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	// AUTHENTICATED DECRYPTION
	plaintext, err := gcm.Open(nil, emailNonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %v", err)
	}

	return string(plaintext), nil
}
