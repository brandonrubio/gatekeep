// Package oidc is an OpenID Connect provider: Authorization Code flow with mandatory PKCE (S256),
// RS256 ID tokens, JWKS, discovery.
//
// Security posture (OAuth 2.0 Security BCP / OAuth 2.1 direction):
//   - public clients only; PKCE S256 REQUIRED (no plain, no implicit flow, no ROPC)
//   - exact-match redirect URIs; a bad client/redirect_uri is shown as an error and NEVER redirected to
//   - authorization codes: 256-bit, stored hashed, single use, 60s TTL, bound to client + redirect_uri + challenge
//   - code reuse is treated as theft: the session behind the code is revoked
//   - ID tokens are RS256 with a rotating kid; relying parties verify with the public JWKS only
//   - max_age / acr_values are honoured; /userinfo is authorised by the same zero-trust gateway
package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yourname/zt-ciam/internal/audit"
	"github.com/yourname/zt-ciam/internal/clock"
	"github.com/yourname/zt-ciam/internal/cryptoutil"
	"github.com/yourname/zt-ciam/internal/gateway"
	"github.com/yourname/zt-ciam/internal/identity"
	"github.com/yourname/zt-ciam/internal/store"
)

const (
	CodeTTL    = 60 * time.Second
	IDTokenTTL = 5 * time.Minute
)

var (
	validScopes = map[string]bool{"openid": true, "profile": true, "email": true, "offline_access": true}
	verifierRE  = regexp.MustCompile(`^[A-Za-z0-9\-._~]{43,128}$`)
)

// Error is an OAuth error. Redirect=false means the request itself is untrustworthy: render an error page
// and do NOT redirect.
type Error struct {
	Code, Description string
	Redirect          bool
	State, RedirectURI string
}

func (e *Error) Error() string { return e.Code }

// Location builds the error redirect URL (only valid when Redirect is true).
func (e *Error) Location() string {
	q := map[string]string{"error": e.Code, "error_description": e.Description}
	if e.State != "" {
		q["state"] = e.State
	}
	return addQuery(e.RedirectURI, q)
}

func addQuery(raw string, params map[string]string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	u.RawQuery, u.Fragment = q.Encode(), ""
	return u.String()
}

// PKCEChallenge computes the S256 code challenge for a verifier.
func PKCEChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return cryptoutil.B64e(h[:])
}

// IDClaims are the ID token claims.
type IDClaims struct {
	Iss      string   `json:"iss"`
	Sub      string   `json:"sub"`
	Aud      string   `json:"aud"`
	Iat      int64    `json:"iat"`
	Exp      int64    `json:"exp"`
	AuthTime int64    `json:"auth_time"`
	Nonce    string   `json:"nonce"`
	ACR      string   `json:"acr"`
	AMR      []string `json:"amr"`
	Sid      string   `json:"sid"`
	AtHash   string   `json:"at_hash"`
	Email    string   `json:"email,omitempty"`
	Name     string   `json:"name,omitempty"`
}

type TokenResponse struct {
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

var (
	cacheMu   sync.Mutex
	cachedKey *rsa.PrivateKey
	cachedKid string
)

type Provider struct {
	Issuer string

	st    *store.Store
	idp   *identity.Service
	gw    *gateway.Gateway
	audit *audit.Log
	clk   clock.Clock

	keys      map[string]*rsa.PrivateKey
	kids      []string // publication order
	activeKid string
}

func New(st *store.Store, idp *identity.Service, gw *gateway.Gateway, a *audit.Log, clk clock.Clock, issuer string) *Provider {
	return &Provider{Issuer: issuer, st: st, idp: idp, gw: gw, audit: a, clk: clk, keys: map[string]*rsa.PrivateKey{}}
}

// ---- key management ----

func (p *Provider) ensureKey() {
	if p.activeKid != "" {
		return
	}
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if cachedKey == nil { // key generation is slow; processes (and tests) share the first key
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		cachedKey, cachedKid = k, "k-"+cryptoutil.RandomToken(4)
	}
	p.keys[cachedKid], p.activeKid, p.kids = cachedKey, cachedKid, []string{cachedKid}
}

// RotateKeys mints a new signing key. Old public keys stay in the JWKS so in-flight tokens still verify.
func (p *Provider) RotateKeys() string {
	p.ensureKey()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	kid := "k-" + cryptoutil.RandomToken(4)
	p.keys[kid], p.activeKid, p.kids = k, kid, append(p.kids, kid)
	return kid
}

func (p *Provider) JWKS() cryptoutil.JWKS { // public parts only
	p.ensureKey()
	out := cryptoutil.JWKS{}
	for _, kid := range p.kids {
		out.Keys = append(out.Keys, cryptoutil.PublicJWK(kid, &p.keys[kid].PublicKey))
	}
	return out
}

func (p *Provider) Discovery() map[string]any {
	i := p.Issuer
	scopes := make([]string, 0, len(validScopes))
	for s := range validScopes {
		scopes = append(scopes, s)
	}
	sort.Strings(scopes)
	return map[string]any{
		"issuer": i, "authorization_endpoint": i + "/authorize", "token_endpoint": i + "/token",
		"userinfo_endpoint": i + "/userinfo", "jwks_uri": i + "/jwks.json",
		"response_types_supported":                []string{"code"},
		"grant_types_supported":                   []string{"authorization_code", "refresh_token"},
		"subject_types_supported":                 []string{"public"},
		"id_token_signing_alg_values_supported":   []string{"RS256"},
		"code_challenge_methods_supported":        []string{"S256"},
		"token_endpoint_auth_methods_supported":   []string{"none"},
		"scopes_supported":                        scopes,
		"claims_supported": []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "at_hash", "sid", "email", "name"},
	}
}

// ---- client registry ----

func (p *Provider) RegisterClient(id, name string, redirectURIs []string) {
	p.st.Clients[id] = &store.OIDCClient{ID: id, Name: name, RedirectURIs: redirectURIs}
}

// ---- /authorize ----

// Authorize returns the redirect URL carrying the code. accessToken identifies the authenticated end-user
// session (a real deployment would render a login page and use a session cookie here).
func (p *Provider) Authorize(params map[string]string, accessToken string) (string, error) {
	client := p.st.Clients[params["client_id"]]
	if client == nil {
		return "", &Error{Code: "unauthorized_client", Description: "unknown client"}
	}
	ru, state := params["redirect_uri"], params["state"]
	registered := false
	for _, r := range client.RedirectURIs {
		registered = registered || r == ru // exact string match only
	}
	if !registered {
		return "", &Error{Code: "invalid_request", Description: "redirect_uri not registered"}
	}
	fail := func(code, desc string) error {
		p.audit.Append(client.ID, "oidc_authorize", "code", "deny", map[string]any{"error": code})
		return &Error{Code: code, Description: desc, Redirect: true, State: state, RedirectURI: ru}
	}

	if params["response_type"] != "code" {
		return "", fail("unsupported_response_type", "only response_type=code")
	}
	scopes := strings.Fields(params["scope"])
	hasOpenID := false
	for _, s := range scopes {
		if !validScopes[s] {
			return "", fail("invalid_scope", "unknown scope")
		}
		hasOpenID = hasOpenID || s == "openid"
	}
	if !hasOpenID {
		return "", fail("invalid_scope", "scope must include openid")
	}
	if params["code_challenge"] == "" || params["code_challenge_method"] != "S256" {
		return "", fail("invalid_request", "PKCE with code_challenge_method=S256 is required")
	}
	if params["nonce"] == "" {
		return "", fail("invalid_request", "nonce is required")
	}

	claims, why := p.gw.SessionClaims(accessToken)
	if why != "" {
		return "", fail("login_required", why)
	}
	now := p.clk.Now()
	if v := params["max_age"]; v != "" {
		maxAge, err := strconv.Atoi(v)
		if err != nil {
			return "", fail("invalid_request", "max_age must be an integer")
		}
		if now.Sub(time.Unix(claims.AuthTime, 0)) > time.Duration(maxAge)*time.Second {
			return "", fail("login_required", "authentication is older than max_age")
		}
	}
	if v := strings.Fields(params["acr_values"]); len(v) > 0 {
		want, err := strconv.Atoi(v[0])
		if err != nil {
			return "", fail("invalid_request", "acr_values must be numeric")
		}
		if claims.ACR < want {
			return "", fail("unmet_authentication_requirements", "requested assurance level not met; step up first")
		}
	}

	code := cryptoutil.RandomToken(32)
	sort.Strings(scopes)
	h := cryptoutil.SHA256Hex(code) // only the hash is stored
	p.st.Codes[h] = &store.AuthCode{Hash: h, ClientID: client.ID, UserID: claims.Sub, SID: claims.Sid, RedirectURI: ru,
		Challenge: params["code_challenge"], Nonce: params["nonce"], Scope: strings.Join(scopes, " "),
		AuthTime: time.Unix(claims.AuthTime, 0), ACR: claims.ACR, AMR: claims.AMR, ExpiresAt: now.Add(CodeTTL)}
	p.audit.Append(claims.Sub, "oidc_authorize", client.ID, "ok", map[string]any{"scope": scopes})
	out := map[string]string{"code": code}
	if state != "" {
		out["state"] = state
	}
	return addQuery(ru, out), nil
}

// ---- /token ----

func (p *Provider) Token(params map[string]string) (*TokenResponse, error) {
	bad := func(desc string) error { return &Error{Code: "invalid_grant", Description: desc} }
	switch params["grant_type"] {
	case "refresh_token":
		t, err := p.idp.Refresh(params["refresh_token"])
		if err != nil {
			return nil, bad("refresh token rejected")
		}
		return &TokenResponse{TokenType: "Bearer", ExpiresIn: 300, AccessToken: t.AccessToken, RefreshToken: t.RefreshToken}, nil
	case "authorization_code":
	default:
		return nil, &Error{Code: "unsupported_grant_type"}
	}

	row := p.st.Codes[cryptoutil.SHA256Hex(params["code"])]
	if row == nil {
		return nil, bad("unknown code")
	}
	if row.Used {
		// RFC 6749 §4.1.2: a replayed code means someone else may hold tokens from it -> kill the session.
		p.idp.Logout(row.SID)
		p.audit.Append(row.UserID, "oidc_token", row.ClientID, "deny", map[string]any{"why": "code_reuse_session_revoked"})
		return nil, bad("code already used")
	}
	if row.ClientID != params["client_id"] || row.RedirectURI != params["redirect_uri"] {
		return nil, bad("client or redirect_uri mismatch")
	}
	now := p.clk.Now()
	if !row.ExpiresAt.After(now) {
		return nil, bad("code expired")
	}
	verifier := params["code_verifier"]
	if !verifierRE.MatchString(verifier) || subtle.ConstantTimeCompare([]byte(PKCEChallenge(verifier)), []byte(row.Challenge)) != 1 {
		p.audit.Append(row.UserID, "oidc_token", row.ClientID, "deny", map[string]any{"why": "pkce_mismatch"})
		return nil, bad("PKCE verification failed") // code is NOT consumed: a thief without the verifier can't burn it
	}
	row.Used = true

	scopes := map[string]bool{}
	for _, s := range strings.Fields(row.Scope) {
		scopes[s] = true
	}
	u := p.idp.User(row.UserID)
	tokens, err := p.idp.Issue(u, row.SID, scopes["offline_access"], row.Scope)
	if err != nil {
		return nil, err
	}
	at := sha256.Sum256([]byte(tokens.AccessToken))
	idc := IDClaims{Iss: p.Issuer, Sub: u.ID, Aud: row.ClientID, Iat: now.Unix(), Exp: now.Add(IDTokenTTL).Unix(),
		AuthTime: row.AuthTime.Unix(), Nonce: row.Nonce, ACR: strconv.Itoa(row.ACR), AMR: row.AMR, Sid: row.SID,
		AtHash: cryptoutil.B64e(at[:16])}
	if scopes["email"] {
		idc.Email = u.Email
	}
	if scopes["profile"] {
		idc.Name = u.Name
	}
	p.ensureKey()
	idt, err := cryptoutil.SignRS256(idc, p.activeKid, p.keys[p.activeKid])
	if err != nil {
		return nil, err
	}
	p.audit.Append(u.ID, "oidc_token", row.ClientID, "ok", map[string]any{"scope": row.Scope})
	return &TokenResponse{TokenType: "Bearer", ExpiresIn: 300, Scope: row.Scope, AccessToken: tokens.AccessToken,
		RefreshToken: tokens.RefreshToken, IDToken: idt}, nil
}

// ---- /userinfo ----

func (p *Provider) UserInfo(accessToken, ip string) (map[string]any, error) {
	claims, why := p.gw.SessionClaims(accessToken)
	scopes := map[string]bool{}
	if claims != nil {
		for _, s := range strings.Fields(claims.Scope) {
			scopes[s] = true
		}
	}
	if why != "" || !scopes["openid"] {
		if why == "" {
			why = "token was not issued for openid"
		}
		return nil, &Error{Code: "invalid_token", Description: why}
	}
	// Zero trust applies to the OIDC resource too: posture, risk, session and user state are all re-checked.
	if d := p.gw.Authorize(accessToken, "profile:read", ip, claims.Sub); !d.Allowed() {
		return nil, &Error{Code: "insufficient_access", Description: strings.Join(d.Reasons, ",")}
	}
	u := p.idp.User(claims.Sub)
	out := map[string]any{"sub": u.ID}
	if scopes["email"] {
		out["email"] = u.Email
	}
	if scopes["profile"] {
		out["name"], out["region"] = u.Name, u.Region
	}
	return out, nil
}
