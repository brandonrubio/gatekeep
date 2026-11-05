// Package httpapi is the network edge (the PEP's front door). A single mutex serialises requests, standing in
// for database transactions around the in-memory store.
package httpapi

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/brandonrubio/gatekeep/internal/app"
	"github.com/brandonrubio/gatekeep/internal/identity"
	"github.com/brandonrubio/gatekeep/internal/oidc"
	"github.com/brandonrubio/gatekeep/internal/policy"
)

type Server struct {
	a  *app.App
	mu sync.Mutex
}

// New returns the HTTP handler for the whole platform.
func New(a *app.App) http.Handler {
	s := &Server{a: a}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /register", s.locked(s.register))
	mux.HandleFunc("POST /login", s.locked(s.login))
	mux.HandleFunc("POST /refresh", s.locked(s.refresh))
	mux.HandleFunc("GET /resource/{name}", s.locked(s.resource))
	// OpenID Connect
	mux.HandleFunc("GET /.well-known/openid-configuration", s.locked(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, a.OIDC.Discovery())
	}))
	mux.HandleFunc("GET /jwks.json", s.locked(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, a.OIDC.JWKS())
	}))
	mux.HandleFunc("GET /authorize", s.locked(s.authorize))
	mux.HandleFunc("POST /token", s.locked(s.token))
	mux.HandleFunc("GET /userinfo", s.locked(s.userinfo))
	return mux
}

func (s *Server) locked(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		h(w, r)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func bearer(r *http.Request) string { return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") }

// clientIP trusts X-Client-IP so demos can simulate networks; in production take it from a trusted proxy only.
func clientIP(r *http.Request) string {
	if v := r.Header.Get("X-Client-IP"); v != "" {
		return v
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func fail(w http.ResponseWriter, err error) {
	var ie identity.Error
	var oe *oidc.Error
	switch {
	case errors.As(err, &ie):
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": string(ie)})
	case errors.As(err, &oe):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": oe.Code, "error_description": oe.Description})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
	}
}

func badRequest(w http.ResponseWriter) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Email, Password, Name, Region string
		Consents                      map[string]bool
	}
	if json.NewDecoder(r.Body).Decode(&b) != nil || b.Email == "" {
		badRequest(w)
		return
	}
	if b.Region == "" {
		b.Region = "EU"
	}
	id, err := s.a.IDP.Register(b.Email, b.Password, b.Name, b.Region, b.Consents, "")
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		DeviceID string `json:"device_id"`
		IP       string `json:"ip"`
		OTP      string `json:"otp"`
	}
	if json.NewDecoder(r.Body).Decode(&b) != nil {
		badRequest(w)
		return
	}
	if b.IP == "" {
		b.IP = clientIP(r)
	}
	res, err := s.a.IDP.Login(identity.LoginRequest{Email: b.Email, Password: b.Password, DeviceID: b.DeviceID, IP: b.IP, OTP: b.OTP})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) refresh(w http.ResponseWriter, r *http.Request) {
	var b struct {
		RefreshToken string `json:"refresh_token"`
	}
	if json.NewDecoder(r.Body).Decode(&b) != nil {
		badRequest(w)
		return
	}
	t, err := s.a.IDP.Refresh(b.RefreshToken)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// GET /resource/{name}?target=<user id>   Authorization: Bearer <jwt>
func (s *Server) resource(w http.ResponseWriter, r *http.Request) {
	d := s.a.Gateway.Authorize(bearer(r), r.PathValue("name"), clientIP(r), r.URL.Query().Get("target"))
	code := map[string]int{policy.Allow: http.StatusOK, policy.StepUp: http.StatusUnauthorized, policy.Deny: http.StatusForbidden}[d.Effect]
	writeJSON(w, code, d)
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	params := map[string]string{}
	for k, v := range r.URL.Query() {
		params[k] = v[0]
	}
	loc, err := s.a.OIDC.Authorize(params, bearer(r))
	var oe *oidc.Error
	switch {
	case err == nil:
		w.Header().Set("Location", loc)
		w.WriteHeader(http.StatusFound)
	case errors.As(err, &oe) && oe.Redirect:
		w.Header().Set("Location", oe.Location())
		w.WriteHeader(http.StatusFound)
	default: // untrustworthy client/redirect_uri: show an error, never redirect
		fail(w, err)
	}
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	params := map[string]string{}
	if strings.Contains(r.Header.Get("Content-Type"), "json") {
		if json.NewDecoder(r.Body).Decode(&params) != nil {
			badRequest(w)
			return
		}
	} else { // application/x-www-form-urlencoded, the OAuth standard
		if r.ParseForm() != nil {
			badRequest(w)
			return
		}
		for k, v := range r.PostForm {
			params[k] = v[0]
		}
	}
	tok, err := s.a.OIDC.Token(params)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tok)
}

func (s *Server) userinfo(w http.ResponseWriter, r *http.Request) {
	info, err := s.a.OIDC.UserInfo(bearer(r), clientIP(r))
	var oe *oidc.Error
	if errors.As(err, &oe) {
		code := http.StatusForbidden
		if oe.Code == "invalid_token" {
			code = http.StatusUnauthorized
		}
		writeJSON(w, code, map[string]string{"error": oe.Code})
		return
	}
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}
