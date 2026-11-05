// Command oidc-demo plays a relying party against the OIDC provider, then replays classic attacks:
//
//	go run ./cmd/oidc-demo
//
// The "RP" only knows the issuer. It discovers endpoints, verifies ID tokens with the PUBLIC JWKS and never
// holds a secret.
package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/brandonrubio/gatekeep/internal/cryptoutil"
	"github.com/brandonrubio/gatekeep/internal/fixture"
	"github.com/brandonrubio/gatekeep/internal/oidc"
)

const (
	clientID = "demo-spa"
	redirect = "https://app.example.test/callback"
)

func h(t string) { fmt.Printf("\n=== %s\n", t) }

func query(raw, key string) string {
	u, _ := url.Parse(raw)
	return u.Query().Get(key)
}

func main() {
	e := fixture.NewEnv()
	e.OIDC.RegisterClient(clientID, "Demo SPA", []string{redirect})
	ada := e.NewUser(fixture.UserOpts{Email: "ada@example.com"})
	session := e.Login(ada, fixture.IP) // the user logs in at the IdP

	h("1. Discovery + JWKS (all the RP needs; no shared secret)")
	disc := e.OIDC.Discovery()
	jwks := e.OIDC.JWKS()
	fmt.Println("issuer:", disc["issuer"], "| PKCE methods:", disc["code_challenge_methods_supported"])
	b, _ := json.Marshal(jwks.Keys[0])
	var fields map[string]any
	_ = json.Unmarshal(b, &fields)
	_, hasD := fields["d"]
	fmt.Println("JWKS key has private exponent 'd':", hasD)

	start := func(over map[string]string) (map[string]string, string) {
		verifier := cryptoutil.RandomToken(48)
		p := map[string]string{"client_id": clientID, "redirect_uri": redirect, "response_type": "code",
			"scope": "openid email profile", "state": cryptoutil.RandomToken(8), "nonce": cryptoutil.RandomToken(8),
			"code_challenge": oidc.PKCEChallenge(verifier), "code_challenge_method": "S256"}
		for k, v := range over {
			p[k] = v
		}
		return p, verifier
	}
	exchange := func(code, verifier string, over map[string]string) (*oidc.TokenResponse, error) {
		p := map[string]string{"grant_type": "authorization_code", "code": code, "client_id": clientID,
			"redirect_uri": redirect, "code_verifier": verifier}
		for k, v := range over {
			p[k] = v
		}
		return e.OIDC.Token(p)
	}

	h("2. Authorization Code + PKCE")
	p, verifier := start(nil)
	loc, err := e.OIDC.Authorize(p, session.AccessToken)
	must(err)
	fmt.Println("state echoed:", query(loc, "state") == p["state"])
	tok, err := exchange(query(loc, "code"), verifier, nil)
	must(err)
	var claims oidc.IDClaims
	must(cryptoutil.VerifyRS256Claims(tok.IDToken, jwks, disc["issuer"].(string), clientID, e.Clock.Now(), &claims))
	fmt.Printf("ID token verified via JWKS. nonce matches: %v | acr: %s | amr: %v | email: %s\n",
		claims.Nonce == p["nonce"], claims.ACR, claims.AMR, claims.Email)
	info, _ := e.OIDC.UserInfo(tok.AccessToken, fixture.IP)
	fmt.Println("userinfo:", info)

	h("3. Attacks")
	attempt := func(label string, err error) {
		if err == nil {
			fmt.Printf("  [!!] %s: ACCEPTED\n", label)
			return
		}
		fmt.Printf("  [ok] %s: rejected (%v)\n", label, err)
	}
	p, verifier = start(nil)
	loc, err = e.OIDC.Authorize(p, session.AccessToken)
	must(err)
	code := query(loc, "code")
	_, err = exchange(code, cryptoutil.RandomToken(48), nil)
	attempt("intercepted code, attacker has no PKCE verifier", err)
	_, err = e.OIDC.Authorize(first(start(map[string]string{"redirect_uri": "https://evil.example/cb"})), session.AccessToken)
	attempt("open redirect to evil.example", err)
	_, err = e.OIDC.Authorize(first(start(map[string]string{"code_challenge_method": "plain"})), session.AccessToken)
	attempt("PKCE downgrade to 'plain'", err)
	_, err = e.OIDC.Authorize(first(start(map[string]string{"response_type": "token"})), session.AccessToken)
	attempt("implicit flow (response_type=token)", err)
	var other oidc.IDClaims
	attempt("ID token for a different client (aud)",
		cryptoutil.VerifyRS256Claims(tok.IDToken, jwks, disc["issuer"].(string), "other-app", e.Clock.Now(), &other))
	parts := strings.Split(tok.IDToken, ".")
	hs := cryptoutil.B64e([]byte(`{"alg":"HS256","kid":"x"}`)) + "." + parts[1] + "." + parts[2]
	attempt("alg downgrade to HS256",
		cryptoutil.VerifyRS256Claims(hs, jwks, disc["issuer"].(string), clientID, e.Clock.Now(), &other))
	_, err = exchange(code, verifier, nil) // the legitimate exchange still works: failures didn't burn the code
	must(err)
	_, err = exchange(code, verifier, nil)
	attempt("authorization code replay", err)
	fmt.Println("  session after replay ->", e.Gateway.Authorize(tok.AccessToken, "profile:read", fixture.IP, ada.ID).Reasons)

	h("4. Key rotation without breaking existing tokens")
	kid := e.OIDC.RotateKeys()
	fmt.Println("new kid:", kid, "| keys in JWKS:", len(e.OIDC.JWKS().Keys),
		"| old ID token still verifies:",
		cryptoutil.VerifyRS256Claims(tok.IDToken, e.OIDC.JWKS(), disc["issuer"].(string), clientID, e.Clock.Now(), &other) == nil)
}

func first(p map[string]string, _ string) map[string]string { return p }

func must(err error) {
	if err != nil {
		panic(err)
	}
}
