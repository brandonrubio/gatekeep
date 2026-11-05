package httpapi_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/brandonrubio/gatekeep/internal/cryptoutil"
	"github.com/brandonrubio/gatekeep/internal/fixture"
	"github.com/brandonrubio/gatekeep/internal/httpapi"
	"github.com/brandonrubio/gatekeep/internal/oidc"
)

const redirect = "https://app.example.test/callback"

func do(t *testing.T, c *http.Client, method, url string, body io.Reader, hdr map[string]string) (int, http.Header, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, b
}

func TestEndToEndOverHTTP(t *testing.T) {
	e := fixture.NewEnv()
	e.OIDC.RegisterClient("spa-1", "SPA", []string{redirect})
	u := e.NewUser(fixture.UserOpts{})
	srv := httptest.NewServer(httpapi.New(e.App))
	defer srv.Close()
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// login (JSON) with MFA
	login, _ := json.Marshal(map[string]string{"email": u.Email, "password": fixture.Password, "device_id": u.DeviceID,
		"ip": fixture.IP, "otp": e.OTP(u.Secret)})
	code, _, body := do(t, noRedirect, "POST", srv.URL+"/login", bytes.NewReader(login), map[string]string{"Content-Type": "application/json"})
	var sess struct {
		Status      string `json:"status"`
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(body, &sess)
	if code != 200 || sess.Status != "ok" {
		t.Fatalf("login %d %s", code, body)
	}
	auth := map[string]string{"Authorization": "Bearer " + sess.AccessToken, "X-Client-IP": fixture.IP}

	// zero-trust resource decisions map to status codes
	for path, want := range map[string]int{
		"/resource/profile:read?target=" + u.ID:   200,
		"/resource/payment:read?target=" + u.ID:   200,
		"/resource/profile:read?target=other":     403,
		"/resource/admin:export":                  403,
	} {
		if got, _, b := do(t, noRedirect, "GET", srv.URL+path, nil, auth); got != want {
			t.Errorf("%s: %d (%s), want %d", path, got, b, want)
		}
	}
	if got, _, _ := do(t, noRedirect, "GET", srv.URL+"/resource/profile:read?target="+u.ID, nil, nil); got != 403 {
		t.Errorf("no token: %d", got)
	}

	// OIDC: discovery, JWKS, authorize (302), token (form), userinfo
	var disc map[string]any
	_, _, b := do(t, noRedirect, "GET", srv.URL+"/.well-known/openid-configuration", nil, nil)
	_ = json.Unmarshal(b, &disc)
	var jwks cryptoutil.JWKS
	_, _, b = do(t, noRedirect, "GET", srv.URL+"/jwks.json", nil, nil)
	_ = json.Unmarshal(b, &jwks)
	if disc["issuer"] != fixture.Issuer || len(jwks.Keys) == 0 {
		t.Fatalf("discovery/jwks wrong: %v %v", disc["issuer"], jwks)
	}

	verifier := cryptoutil.RandomToken(48)
	q := url.Values{"client_id": {"spa-1"}, "redirect_uri": {redirect}, "response_type": {"code"}, "scope": {"openid email"},
		"state": {"s"}, "nonce": {"n"}, "code_challenge": {oidc.PKCEChallenge(verifier)}, "code_challenge_method": {"S256"}}
	code, hdr, _ := do(t, noRedirect, "GET", srv.URL+"/authorize?"+q.Encode(), nil, auth)
	if code != 302 {
		t.Fatalf("authorize: %d", code)
	}
	loc, _ := url.Parse(hdr.Get("Location"))
	form := url.Values{"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")}, "client_id": {"spa-1"},
		"redirect_uri": {redirect}, "code_verifier": {verifier}}
	code, _, b = do(t, noRedirect, "POST", srv.URL+"/token", strings.NewReader(form.Encode()),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	var tok oidc.TokenResponse
	_ = json.Unmarshal(b, &tok)
	if code != 200 || tok.IDToken == "" {
		t.Fatalf("token: %d %s", code, b)
	}
	var claims oidc.IDClaims
	if err := cryptoutil.VerifyRS256Claims(tok.IDToken, jwks, fixture.Issuer, "spa-1", e.Clock.Now(), &claims); err != nil || claims.Sub != u.ID {
		t.Fatalf("id token: %v %+v", err, claims)
	}
	code, _, b = do(t, noRedirect, "GET", srv.URL+"/userinfo", nil, map[string]string{"Authorization": "Bearer " + tok.AccessToken, "X-Client-IP": fixture.IP})
	if code != 200 || !strings.Contains(string(b), "a@example.com") {
		t.Fatalf("userinfo: %d %s", code, b)
	}

	// an unregistered redirect_uri is a 400 page, never a redirect
	q.Set("redirect_uri", "https://evil.test/cb")
	if code, hdr, _ := do(t, noRedirect, "GET", srv.URL+"/authorize?"+q.Encode(), nil, auth); code != 400 || hdr.Get("Location") != "" {
		t.Fatalf("evil redirect: %d %q", code, hdr.Get("Location"))
	}
	// wrong password -> 401
	bad, _ := json.Marshal(map[string]string{"email": u.Email, "password": "nope-nope-nope"})
	if code, _, _ := do(t, noRedirect, "POST", srv.URL+"/login", bytes.NewReader(bad), nil); code != 401 {
		t.Fatalf("bad login: %d", code)
	}
}
