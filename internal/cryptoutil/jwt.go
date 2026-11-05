package cryptoutil

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"strings"
	"time"
)

// JWTError is a stable, comparable error code.
type JWTError string

func (e JWTError) Error() string { return string(e) }

const (
	ErrMalformed    JWTError = "malformed"
	ErrBadAlg       JWTError = "bad_alg"
	ErrUnknownKid   JWTError = "unknown_kid"
	ErrBadSignature JWTError = "bad_signature"
	ErrBadIssuer    JWTError = "bad_iss"
	ErrBadAudience  JWTError = "bad_aud"
	ErrExpired      JWTError = "expired"
)

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ,omitempty"`
	Kid string `json:"kid,omitempty"`
}

func encode(alg, kid string, payload any, sign func([]byte) ([]byte, error)) (string, error) {
	hb, err := json.Marshal(header{Alg: alg, Typ: "JWT", Kid: kid})
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	in := B64e(hb) + "." + B64e(pb)
	sig, err := sign([]byte(in))
	if err != nil {
		return "", err
	}
	return in + "." + B64e(sig), nil
}

func split(token string) (hdr header, signingInput string, payload, sig []byte, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return hdr, "", nil, nil, ErrMalformed
	}
	hb, e1 := B64d(parts[0])
	pb, e2 := B64d(parts[1])
	sb, e3 := B64d(parts[2])
	if e1 != nil || e2 != nil || e3 != nil || json.Unmarshal(hb, &hdr) != nil {
		return hdr, "", nil, nil, ErrMalformed
	}
	return hdr, parts[0] + "." + parts[1], pb, sb, nil
}

// ---- HS256 (internal API tokens; kid-based key rotation) ----

func SignHS256(payload any, kid string, key []byte) (string, error) {
	return encode("HS256", kid, payload, func(in []byte) ([]byte, error) {
		m := hmac.New(sha256.New, key)
		m.Write(in)
		return m.Sum(nil), nil
	})
}

// VerifyHS256 pins the algorithm (blocks alg=none / downgrades) and returns the payload JSON.
func VerifyHS256(token string, keys map[string][]byte) ([]byte, error) {
	hdr, in, payload, sig, err := split(token)
	if err != nil {
		return nil, err
	}
	if hdr.Alg != "HS256" {
		return nil, ErrBadAlg
	}
	key, ok := keys[hdr.Kid]
	if !ok {
		return nil, ErrUnknownKid
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(in))
	if !hmac.Equal(m.Sum(nil), sig) {
		return nil, ErrBadSignature
	}
	return payload, nil
}

// ---- RS256 + JWKS (OIDC ID tokens: relying parties verify with public keys only) ----

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func PublicJWK(kid string, pub *rsa.PublicKey) JWK {
	return JWK{Kty: "RSA", Use: "sig", Alg: "RS256", Kid: kid,
		N: B64e(pub.N.Bytes()), E: B64e(big.NewInt(int64(pub.E)).Bytes())}
}

func SignRS256(payload any, kid string, key *rsa.PrivateKey) (string, error) {
	return encode("RS256", kid, payload, func(in []byte) ([]byte, error) {
		d := sha256.Sum256(in)
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, d[:])
	})
}

// VerifyRS256 checks the signature against the public JWKS only. alg is pinned to RS256, which blocks
// the classic "relabel as HS256 and sign with the public key" confusion attack.
func VerifyRS256(token string, jwks JWKS) ([]byte, error) {
	hdr, in, payload, sig, err := split(token)
	if err != nil {
		return nil, err
	}
	if hdr.Alg != "RS256" {
		return nil, ErrBadAlg
	}
	var jwk *JWK
	for i := range jwks.Keys {
		if jwks.Keys[i].Kid == hdr.Kid && jwks.Keys[i].Kty == "RSA" {
			jwk = &jwks.Keys[i]
			break
		}
	}
	if jwk == nil {
		return nil, ErrUnknownKid
	}
	nb, e1 := B64d(jwk.N)
	eb, e2 := B64d(jwk.E)
	if e1 != nil || e2 != nil {
		return nil, ErrMalformed
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(new(big.Int).SetBytes(eb).Int64())}
	d := sha256.Sum256([]byte(in))
	if rsa.VerifyPKCS1v15(pub, crypto.SHA256, d[:], sig) != nil {
		return nil, ErrBadSignature
	}
	return payload, nil
}

type registered struct {
	Iss string `json:"iss"`
	Aud string `json:"aud"`
	Exp int64  `json:"exp"`
}

// CheckRegistered validates iss, aud and exp on an already signature-verified payload.
func CheckRegistered(payload []byte, iss, aud string, now time.Time) error {
	var r registered
	if err := json.Unmarshal(payload, &r); err != nil {
		return ErrMalformed
	}
	switch {
	case r.Iss != iss:
		return ErrBadIssuer
	case r.Aud != aud:
		return ErrBadAudience
	case now.Unix() >= r.Exp:
		return ErrExpired
	}
	return nil
}

// VerifyRS256Claims is the relying-party convenience: signature + iss/aud/exp, then decode into out.
func VerifyRS256Claims(token string, jwks JWKS, iss, aud string, now time.Time, out any) error {
	payload, err := VerifyRS256(token, jwks)
	if err != nil {
		return err
	}
	if err := CheckRegistered(payload, iss, aud, now); err != nil {
		return err
	}
	return json.Unmarshal(payload, out)
}
