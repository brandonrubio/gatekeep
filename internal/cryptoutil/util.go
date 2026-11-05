// Package cryptoutil holds small, auditable crypto helpers built on the Go standard library only.
package cryptoutil

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func B64e(b []byte) string          { return base64.RawURLEncoding.EncodeToString(b) }
func B64d(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func RandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // the OS CSPRNG failing is unrecoverable
	}
	return b
}

func RandomToken(n int) string { return B64e(RandomBytes(n)) }

// NewID returns a random RFC 4122 version-4 UUID string.
func NewID() string {
	b := RandomBytes(16)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func SHA256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// Pseudonym derives a stable, non-reversible identifier (keyed HMAC) for analytics systems.
func Pseudonym(value string, key []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(value))
	return hex.EncodeToString(m.Sum(nil))[:32]
}
