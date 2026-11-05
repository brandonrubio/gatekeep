package oidc_test

import (
	"crypto/sha256"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/brandonrubio/gatekeep/internal/cryptoutil"
	"github.com/brandonrubio/gatekeep/internal/fixture"
	"github.com/brandonrubio/gatekeep/internal/identity"
	"github.com/brandonrubio/gatekeep/internal/oidc"
	"github.com/brandonrubio/gatekeep/internal/policy"
)

const (
	clientID = "spa-1"
	redirect = "https://app.example.test/callback"
)

type rig struct {
	t        *testing.T
	e        *fixture.Env
	user     *fixture.User
	access   string
	refresh  string
	verifier string
}

func newRig(t *testing.T) *rig {
	e := fixture.NewEnv()
	e.OIDC.RegisterClient(clientID, "Demo SPA", []string{redirect})
	u := e.NewUser(fixture.UserOpts{})
	s := e.Login(u, fixture.IP)
	return &rig{t: t, e: e, user: u, access: s.AccessToken, refresh: s.RefreshToken}
}

// params builds an authorize request; override with k,v pairs ("" deletes the key).
func (r *rig) params(kv ...string) map[string]string {
	r.verifier = cryptoutil.RandomToken(48)
	p := map[string]string{"client_id": clientID, "redirect_uri": redirect, "response_type": "code",
		"scope": "openid email profile", "state": "st-123", "nonce": "n-456",
		"code_challenge": oidc.PKCEChallenge(r.verifier), "code_challenge_method": "S256"}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "" {
			delete(p, kv[i])
		} else {
			p[kv[i]] = kv[i+1]
		}
	}
	return p
}

func query(raw, key string) string {
	u, _ := url.Parse(raw)
	return u.Query().Get(key)
}

func (r *rig) code(kv ...string) string {
	r.t.Helper()
	loc, err := r.e.OIDC.Authorize(r.params(kv...), r.access)
	if err != nil {
		r.t.Fatalf("authorize: %v", err)
	}
	return query(loc, "code")
}

func (r *rig) exchange(code string, kv ...string) (*oidc.TokenResponse, error) {
	p := map[string]string{"grant_type": "authorization_code", "code": code, "client_id": clientID,
		"redirect_uri": redirect, "code_verifier": r.verifier}
	for i := 0; i+1 < len(kv); i += 2 {
		p[kv[i]] = kv[i+1]
	}
	return r.e.OIDC.Token(p)
}

func (r *rig) mustTokens(code string) *oidc.TokenResponse {
	r.t.Helper()
	tok, err := r.exchange(code)
	if err != nil {
		r.t.Fatalf("token: %v", err)
	}
	return tok
}

func (r *rig) verify(idToken string) (oidc.IDClaims, error) {
	var c oidc.IDClaims
	err := cryptoutil.VerifyRS256Claims(idToken, r.e.OIDC.JWKS(), r.e.OIDC.Issuer, clientID, r.e.Clock.Now(), &c)
	return c, err
}

func oidcCode(t *testing.T, err error) *oidc.Error {
	t.Helper()
	var oe *oidc.Error
	if !errors.As(err, &oe) {
		t.Fatalf("expected *oidc.Error, got %v", err)
	}
	return oe
}

func TestFullFlowAndIDTokenValidation(t *testing.T) {
	r := newRig(t)
	loc, err := r.e.OIDC.Authorize(r.params(), r.access)
	if err != nil || !strings.HasPrefix(loc, redirect) || query(loc, "state") != "st-123" {
		t.Fatalf("authorize: %q %v", loc, err)
	}
	tok := r.mustTokens(query(loc, "code"))
	c, err := r.verify(tok.IDToken)
	if err != nil {
		t.Fatal(err)
	}
	if c.Sub != r.user.ID || c.Nonce != "n-456" || c.ACR != "2" || strings.Join(c.AMR, ",") != "pwd,otp" || c.Email != "a@example.com" {
		t.Fatalf("unexpected claims %+v", c)
	}
	h := sha256.Sum256([]byte(tok.AccessToken))
	if c.AtHash != cryptoutil.B64e(h[:16]) {
		t.Fatal("at_hash mismatch")
	}
}

func TestScopeControlsClaims(t *testing.T) {
	r := newRig(t)
	tok := r.mustTokens(r.code("scope", "openid"))
	c, _ := r.verify(tok.IDToken)
	if c.Email != "" || c.Name != "" {
		t.Fatalf("claims leaked beyond scope: %+v", c)
	}
	info, err := r.e.OIDC.UserInfo(tok.AccessToken, fixture.IP)
	if err != nil || len(info) != 1 || info["sub"] != r.user.ID {
		t.Fatalf("userinfo %v %v", info, err)
	}
}

func TestOfflineAccessIssuesRefreshToken(t *testing.T) {
	r := newRig(t)
	with := r.mustTokens(r.code("scope", "openid email offline_access"))
	if with.RefreshToken == "" {
		t.Fatal("expected a refresh token")
	}
	if _, err := r.e.OIDC.Token(map[string]string{"grant_type": "refresh_token", "refresh_token": with.RefreshToken}); err != nil {
		t.Fatal(err)
	}
	if r.mustTokens(r.code("scope", "openid")).RefreshToken != "" {
		t.Fatal("refresh token issued without offline_access")
	}
}

func TestJWKSExposesNoPrivateMaterialAndDiscoveryIsSafe(t *testing.T) {
	r := newRig(t)
	for _, k := range r.e.OIDC.JWKS().Keys {
		if k.Kty != "RSA" || k.Alg != "RS256" || k.N == "" || k.E == "" {
			t.Fatalf("bad jwk %+v", k)
		}
	}
	d := r.e.OIDC.Discovery()
	if got := d["code_challenge_methods_supported"].([]string); len(got) != 1 || got[0] != "S256" {
		t.Fatalf("PKCE methods %v", got)
	}
	if got := d["response_types_supported"].([]string); len(got) != 1 || got[0] != "code" {
		t.Fatalf("response types %v", got)
	}
}

func TestWrongPKCEVerifierRejectedAndCodeNotBurned(t *testing.T) {
	r := newRig(t)
	code := r.code()
	_, err := r.exchange(code, "code_verifier", cryptoutil.RandomToken(48))
	if oidcCode(t, err).Code != "invalid_grant" {
		t.Fatal("expected invalid_grant")
	}
	if _, err := r.exchange(code); err != nil { // the legitimate client still succeeds
		t.Fatal(err)
	}
}

func TestPKCERequiredAndPlainRejected(t *testing.T) {
	r := newRig(t)
	for _, kv := range [][]string{{"code_challenge", ""}, {"code_challenge_method", "plain"}, {"code_challenge_method", ""}} {
		_, err := r.e.OIDC.Authorize(r.params(kv...), r.access)
		if oe := oidcCode(t, err); oe.Code != "invalid_request" || !oe.Redirect {
			t.Fatalf("%v: %+v", kv, oe)
		}
	}
}

func TestNonceRequired(t *testing.T) {
	r := newRig(t)
	if _, err := r.e.OIDC.Authorize(r.params("nonce", ""), r.access); err == nil {
		t.Fatal("authorize without nonce succeeded")
	}
}

func TestUnregisteredRedirectNeverRedirects(t *testing.T) {
	r := newRig(t)
	for _, ru := range []string{"https://evil.example/cb", redirect + "/", redirect + "?x=1", redirect + "#"} {
		_, err := r.e.OIDC.Authorize(r.params("redirect_uri", ru), r.access)
		if oe := oidcCode(t, err); oe.Redirect {
			t.Fatalf("%s: would redirect to an unregistered URI", ru)
		}
	}
	_, err := r.e.OIDC.Authorize(r.params("client_id", "nope"), r.access)
	if oidcCode(t, err).Redirect {
		t.Fatal("unknown client must not redirect")
	}
}

func TestTokenEndpointBindsClientAndRedirect(t *testing.T) {
	r := newRig(t)
	r.e.OIDC.RegisterClient("other", "Other", []string{redirect})
	code := r.code()
	for _, kv := range [][]string{{"redirect_uri", "https://app.example.test/other"}, {"client_id", "other"}} {
		if _, err := r.exchange(code, kv...); err == nil {
			t.Fatalf("exchange with %v succeeded", kv)
		}
	}
}

func TestErrorsRedirectWithState(t *testing.T) {
	r := newRig(t)
	_, err := r.e.OIDC.Authorize(r.params("response_type", "token"), r.access) // implicit flow refused
	oe := oidcCode(t, err)
	loc := oe.Location()
	if query(loc, "error") != "unsupported_response_type" || query(loc, "state") != "st-123" {
		t.Fatalf("location %s", loc)
	}
}

func TestBadScopes(t *testing.T) {
	r := newRig(t)
	for _, s := range []string{"email", "openid admin"} {
		_, err := r.e.OIDC.Authorize(r.params("scope", s), r.access)
		if oidcCode(t, err).Code != "invalid_scope" {
			t.Fatalf("scope %q accepted", s)
		}
	}
}

func TestCodeReplayRevokesSession(t *testing.T) {
	r := newRig(t)
	code := r.code()
	tok := r.mustTokens(code)
	if !r.e.Gateway.Authorize(tok.AccessToken, "profile:read", fixture.IP, r.user.ID).Allowed() {
		t.Fatal("token should work before replay")
	}
	if _, err := r.exchange(code); err == nil { // attacker replays the code
		t.Fatal("code replay accepted")
	}
	d := r.e.Gateway.Authorize(tok.AccessToken, "profile:read", fixture.IP, r.user.ID)
	if d.Effect != policy.Deny || d.Reasons[0] != "session_revoked" {
		t.Fatalf("decision %+v", d)
	}
}

func TestCodeExpiresAndIsStoredHashed(t *testing.T) {
	r := newRig(t)
	code := r.code()
	if _, plain := r.e.Store.Codes[code]; plain {
		t.Fatal("authorization code stored in plaintext")
	}
	r.e.Clock.Advance(61 * time.Second)
	if _, err := r.exchange(code); err == nil {
		t.Fatal("expired code accepted")
	}
}

func TestLoginRequiredWithoutValidSession(t *testing.T) {
	r := newRig(t)
	_, err := r.e.OIDC.Authorize(r.params(), "garbage")
	if oidcCode(t, err).Code != "login_required" {
		t.Fatal("expected login_required")
	}
}

func TestMaxAgeForcesReauthentication(t *testing.T) {
	r := newRig(t)
	r.e.Clock.Advance(100 * time.Second)
	fresh, err := r.e.IDP.Refresh(r.refresh)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.e.OIDC.Authorize(r.params("max_age", "60"), fresh.AccessToken)
	if oidcCode(t, err).Code != "login_required" {
		t.Fatal("expected login_required")
	}
}

func TestACRValuesRequiresMFABackedSession(t *testing.T) {
	r := newRig(t)
	u := r.e.NewUser(fixture.UserOpts{Email: "nomfa@example.com", NoMFA: true})
	s, _ := r.e.IDP.Login(identityLogin(u))
	_, err := r.e.OIDC.Authorize(r.params("acr_values", "2"), s.AccessToken)
	if oidcCode(t, err).Code != "unmet_authentication_requirements" {
		t.Fatal("expected unmet_authentication_requirements")
	}
	if _, err := r.e.OIDC.Authorize(r.params("acr_values", "1"), s.AccessToken); err != nil {
		t.Fatalf("aal1 should satisfy acr_values=1: %v", err)
	}
}

func TestIDTokenAttacksRejected(t *testing.T) {
	r := newRig(t)
	tok := r.mustTokens(r.code()).IDToken
	jwks, iss, now := r.e.OIDC.JWKS(), r.e.OIDC.Issuer, r.e.Clock.Now()
	var c oidc.IDClaims
	checks := map[string]struct {
		err  error
		want cryptoutil.JWTError
	}{
		"wrong audience": {cryptoutil.VerifyRS256Claims(tok, jwks, iss, "other-client", now, &c), cryptoutil.ErrBadAudience},
		"wrong issuer":   {cryptoutil.VerifyRS256Claims(tok, jwks, "https://evil.example", clientID, now, &c), cryptoutil.ErrBadIssuer},
		"expired":        {cryptoutil.VerifyRS256Claims(tok, jwks, iss, clientID, now.Add(6*time.Minute), &c), cryptoutil.ErrExpired},
	}
	for name, ch := range checks {
		if ch.err != ch.want {
			t.Errorf("%s: got %v want %v", name, ch.err, ch.want)
		}
	}
	parts := strings.Split(tok, ".")
	hs := cryptoutil.B64e([]byte(`{"alg":"HS256","kid":"x"}`)) + "." + parts[1] + "." + parts[2]
	if err := cryptoutil.VerifyRS256Claims(hs, jwks, iss, clientID, now, &c); err != cryptoutil.ErrBadAlg {
		t.Errorf("alg confusion: got %v", err)
	}
	forged := parts[0] + "." + cryptoutil.B64e([]byte(`{"iss":"`+iss+`","aud":"`+clientID+`","exp":9999999999,"sub":"attacker"}`)) + "." + parts[2]
	if err := cryptoutil.VerifyRS256Claims(forged, jwks, iss, clientID, now, &c); err != cryptoutil.ErrBadSignature {
		t.Errorf("tampered payload: got %v", err)
	}
}

func TestKeyRotationKeepsOldTokensValid(t *testing.T) {
	r := newRig(t)
	old := r.mustTokens(r.code()).IDToken
	r.e.OIDC.RotateKeys()
	fresh := r.mustTokens(r.code()).IDToken
	if n := len(r.e.OIDC.JWKS().Keys); n != 2 {
		t.Fatalf("expected 2 keys in JWKS, got %d", n)
	}
	for _, tok := range []string{old, fresh} {
		if _, err := r.verify(tok); err != nil {
			t.Fatal(err)
		}
	}
}

func TestUserInfoStillSubjectToZeroTrust(t *testing.T) {
	r := newRig(t)
	tok := r.mustTokens(r.code())
	if _, err := r.e.OIDC.UserInfo(r.access, fixture.IP); err == nil { // plain API token carries no openid scope
		t.Fatal("non-openid token accepted at /userinfo")
	}
	if _, err := r.e.OIDC.UserInfo(tok.AccessToken, fixture.IP); err != nil {
		t.Fatal(err)
	}
	r.e.IDP.SetStatus(r.user.ID, "suspended")
	if _, err := r.e.OIDC.UserInfo(tok.AccessToken, fixture.IP); err == nil {
		t.Fatal("suspended user still served")
	}
}

func identityLogin(u *fixture.User) identity.LoginRequest {
	return identity.LoginRequest{Email: u.Email, Password: fixture.Password, DeviceID: u.DeviceID, IP: fixture.IP}
}
