package cryptoutil

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // HMAC-SHA1 is what RFC 6238/4226 specify; it is not used as a collision-resistant hash
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"time"
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func NewTOTPSecret() string { return b32.EncodeToString(RandomBytes(20)) }

// TOTPCodeDigits implements RFC 6238 / RFC 4226 dynamic truncation.
func TOTPCodeDigits(secret string, counter uint64, digits int) string {
	key, err := b32.DecodeString(secret)
	if err != nil {
		return ""
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	m := hmac.New(sha1.New, key)
	m.Write(buf[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	n := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, n%mod)
}

func TOTPCode(secret string, counter uint64) string { return TOTPCodeDigits(secret, counter, 6) }

// TOTPVerify accepts +/-1 time step and rejects any counter <= lastCounter (replay protection).
func TOTPVerify(secret, code string, now time.Time, lastCounter int64) (int64, bool) {
	c := now.Unix() / 30
	for cand := c - 1; cand <= c+1; cand++ {
		if cand > lastCounter && subtle.ConstantTimeCompare([]byte(TOTPCode(secret, uint64(cand))), []byte(code)) == 1 {
			return cand, true
		}
	}
	return -1, false
}
