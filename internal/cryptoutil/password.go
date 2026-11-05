package cryptoutil

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"strconv"
	"strings"
)

// PBKDF2Iterations follows OWASP guidance for PBKDF2-HMAC-SHA256. Tests lower it for speed.
var PBKDF2Iterations = 600_000

// pbkdf2 derives a single 32-byte block (RFC 8018). Implemented locally to keep the module dependency-free.
func pbkdf2(password, salt []byte, iter int) []byte {
	prf := hmac.New(sha256.New, password)
	prf.Write(salt)
	prf.Write([]byte{0, 0, 0, 1})
	u := prf.Sum(nil)
	t := append([]byte(nil), u...)
	for i := 1; i < iter; i++ {
		prf.Reset()
		prf.Write(u)
		u = prf.Sum(nil)
		for j := range t {
			t[j] ^= u[j]
		}
	}
	return t
}

func HashPassword(pw string) string {
	salt := RandomBytes(16)
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", PBKDF2Iterations, B64e(salt), B64e(pbkdf2([]byte(pw), salt, PBKDF2Iterations)))
}

func VerifyPassword(pw, stored string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 {
		return false
	}
	salt, e1 := B64d(parts[2])
	want, e2 := B64d(parts[3])
	if e1 != nil || e2 != nil {
		return false
	}
	return subtle.ConstantTimeCompare(pbkdf2([]byte(pw), salt, iter), want) == 1
}
