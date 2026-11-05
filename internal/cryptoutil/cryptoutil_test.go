package cryptoutil

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

func TestTOTPRFC6238Vector(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	if got := TOTPCodeDigits(secret, 59/30, 8); got != "94287082" {
		t.Fatalf("got %s, want 94287082", got)
	}
}

func TestTOTPReplayRejected(t *testing.T) {
	secret := NewTOTPSecret()
	now := time.Unix(100*30, 0)
	c, ok := TOTPVerify(secret, TOTPCode(secret, 100), now, -1)
	if !ok || c != 100 {
		t.Fatalf("first use should verify, got %d %v", c, ok)
	}
	if _, ok := TOTPVerify(secret, TOTPCode(secret, 100), now, c); ok {
		t.Fatal("replayed code accepted")
	}
}

func TestPasswordHashing(t *testing.T) {
	PBKDF2Iterations = 1000
	h := HashPassword("correct horse battery")
	if !VerifyPassword("correct horse battery", h) || VerifyPassword("wrong", h) {
		t.Fatal("password verification wrong")
	}
	if h == HashPassword("correct horse battery") {
		t.Fatal("salts must differ")
	}
	if VerifyPassword("x", "garbage") {
		t.Fatal("malformed hash accepted")
	}
}

func TestHS256RejectsNoneAlgTamperAndUnknownKid(t *testing.T) {
	keys := map[string][]byte{"k1": []byte("0123456789abcdef0123456789abcdef")}
	tok, _ := SignHS256(map[string]any{"sub": "u"}, "k1", keys["k1"])
	if _, err := VerifyHS256(tok, keys); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	none := B64e([]byte(`{"alg":"none","kid":"k1"}`)) + "." + parts[1] + "."
	if _, err := VerifyHS256(none, keys); err != ErrBadAlg {
		t.Fatalf("alg=none: got %v", err)
	}
	tampered := parts[0] + "." + B64e([]byte(`{"sub":"admin"}`)) + "." + parts[2]
	if _, err := VerifyHS256(tampered, keys); err != ErrBadSignature {
		t.Fatalf("tamper: got %v", err)
	}
	if _, err := VerifyHS256(tok, map[string][]byte{"other": keys["k1"]}); err != ErrUnknownKid {
		t.Fatalf("kid: got %v", err)
	}
}

func TestRS256RoundTripAndAlgConfusion(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := JWKS{Keys: []JWK{PublicJWK("r1", &key.PublicKey)}}
	now := time.Unix(1000, 0)
	tok, _ := SignRS256(map[string]any{"iss": "i", "aud": "a", "exp": 2000}, "r1", key)
	var out map[string]any
	if err := VerifyRS256Claims(tok, jwks, "i", "a", now, &out); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		iss, aud string
		now      time.Time
		want     JWTError
	}{
		"wrong aud": {"i", "b", now, ErrBadAudience},
		"wrong iss": {"x", "a", now, ErrBadIssuer},
		"expired":   {"i", "a", time.Unix(2001, 0), ErrExpired},
	} {
		if err := VerifyRS256Claims(tok, jwks, c.iss, c.aud, c.now, &out); err != c.want {
			t.Errorf("%s: got %v want %v", name, err, c.want)
		}
	}
	parts := strings.Split(tok, ".")
	hs := B64e([]byte(`{"alg":"HS256","kid":"r1"}`)) + "." + parts[1] + "." + parts[2]
	if _, err := VerifyRS256(hs, jwks); err != ErrBadAlg {
		t.Fatalf("alg confusion: got %v", err)
	}
	forged := parts[0] + "." + B64e([]byte(`{"iss":"i","aud":"a","exp":2000,"sub":"attacker"}`)) + "." + parts[2]
	if _, err := VerifyRS256(forged, jwks); err != ErrBadSignature {
		t.Fatalf("tamper: got %v", err)
	}
}
