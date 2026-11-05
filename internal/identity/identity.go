// Package identity is the Customer Identity & Access Management service and system of record for identities.
package identity

import (
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/brandonrubio/gatekeep/internal/audit"
	"github.com/brandonrubio/gatekeep/internal/clock"
	"github.com/brandonrubio/gatekeep/internal/cryptoutil"
	"github.com/brandonrubio/gatekeep/internal/device"
	"github.com/brandonrubio/gatekeep/internal/store"
)

const (
	Issuer     = "ztciam-idp"
	Audience   = "ztciam-api"
	AccessTTL  = 5 * time.Minute
	RefreshTTL = 7 * 24 * time.Hour
	LockAfter  = 5
	LockFor    = 15 * time.Minute
)

var ConsentPurposes = []string{"marketing", "analytics"}

var commonPasswords = map[string]bool{
	"password1234": true, "123456789012": true, "qwertyuiop12": true, "letmein12345": true,
}

// Error is a stable error code that never leaks which factor failed.
type Error string

func (e Error) Error() string { return string(e) }

const (
	ErrInvalidEmail       Error = "invalid_email"
	ErrWeakPassword       Error = "weak_password"
	ErrEmailTaken         Error = "email_taken"
	ErrUnknownPurpose     Error = "unknown_purpose"
	ErrInvalidCredentials Error = "invalid_credentials"
	ErrAccountLocked      Error = "account_locked"
	ErrRiskDenied         Error = "risk_denied"
	ErrInvalidOTP         Error = "invalid_otp"
	ErrMFANotEnrolled     Error = "mfa_not_enrolled"
	ErrInvalidRefresh     Error = "invalid_refresh"
	ErrRefreshReuse       Error = "refresh_reuse_detected"
)

// AccessClaims are the claims of an internal API access token.
type AccessClaims struct {
	Iss      string   `json:"iss"`
	Aud      string   `json:"aud"`
	Sub      string   `json:"sub"`
	Sid      string   `json:"sid"`
	Did      string   `json:"did"`
	Role     string   `json:"role"`
	ACR      int      `json:"acr"`
	AMR      []string `json:"amr"`
	Risk     int      `json:"risk"`
	IPP      string   `json:"ipp"`
	AuthTime int64    `json:"auth_time"`
	Iat      int64    `json:"iat"`
	Exp      int64    `json:"exp"`
	Jti      string   `json:"jti"`
	Scope    string   `json:"scope,omitempty"`
}

type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type LoginRequest struct {
	Email, Password, DeviceID, IP, OTP string
}

type LoginResult struct {
	Status string `json:"status"` // ok | mfa_required
	Tokens
}

// Snapshot is the read model the sync pipeline consumes.
type Snapshot struct {
	ID, Email, Name, Region, Status string
	Version                         int
	CreatedAt                       time.Time
	Consents                        map[string]bool
}

type Service struct {
	st        *store.Store
	devices   *device.Registry
	audit     *audit.Log
	clk       clock.Clock
	keys      map[string][]byte
	activeKid string
}

func New(st *store.Store, devices *device.Registry, a *audit.Log, clk clock.Clock, keys map[string][]byte, activeKid string) *Service {
	return &Service{st: st, devices: devices, audit: a, clk: clk, keys: keys, activeKid: activeKid}
}

var (
	dummyOnce sync.Once
	dummy     string
)

func dummyHash() string {
	dummyOnce.Do(func() { dummy = cryptoutil.HashPassword("dummy-password-for-timing") })
	return dummy
}

func IPPrefix(ip string) string {
	p := strings.Split(ip, ".")
	if len(p) > 3 {
		p = p[:3]
	}
	return strings.Join(p, ".")
}

// ---------- registration & profile ----------

func (s *Service) Register(email, password, name, region string, consents map[string]bool, role string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if !strings.Contains(email, "@") {
		return "", ErrInvalidEmail
	}
	if len(password) < 12 || commonPasswords[strings.ToLower(password)] {
		return "", ErrWeakPassword
	}
	if _, taken := s.st.EmailIndex[email]; taken {
		return "", ErrEmailTaken
	}
	if role == "" {
		role = "customer"
	}
	id, now := cryptoutil.NewID(), s.clk.Now()
	s.st.Users[id] = &store.User{ID: id, Email: email, Name: name, PWHash: cryptoutil.HashPassword(password),
		Role: role, Status: "active", Region: region, CreatedAt: now, MFALastCounter: -1}
	s.st.EmailIndex[email] = id
	s.st.UserOrder = append(s.st.UserOrder, id)
	s.st.Consents[id] = map[string]bool{}
	for _, p := range ConsentPurposes { // consent is explicit opt-in: default denied
		s.st.Consents[id][p] = consents[p]
	}
	s.emit(id, "user.created") // state change + outbox event happen together (transactional outbox)
	s.audit.Append(id, "register", "user", "ok", nil)
	return id, nil
}

func (s *Service) UpdateProfile(uid string, name, region *string) {
	u := s.st.Users[uid]
	if u == nil || u.Status == "deleted" {
		return
	}
	if name != nil {
		u.Name = *name
	}
	if region != nil {
		u.Region = *region
	}
	s.emit(uid, "user.updated")
}

func (s *Service) SetConsent(uid, purpose string, granted bool) error {
	known := false
	for _, p := range ConsentPurposes {
		known = known || p == purpose
	}
	if !known {
		return ErrUnknownPurpose
	}
	s.st.Consents[uid][purpose] = granted
	s.emit(uid, "consent.changed")
	decision := "withdrawn"
	if granted {
		decision = "granted"
	}
	s.audit.Append(uid, "consent", purpose, decision, nil)
	return nil
}

// EraseUser implements the right to erasure: scrub PII, kill sessions, keep a tombstone so downstream converges.
func (s *Service) EraseUser(uid string) {
	u := s.st.Users[uid]
	if u == nil {
		return
	}
	delete(s.st.EmailIndex, u.Email)
	u.Email, u.Name, u.PWHash, u.MFASecret, u.MFAEnabled, u.Status, u.LastIPPrefix = "", "", "", "", false, "deleted", ""
	for p := range s.st.Consents[uid] {
		s.st.Consents[uid][p] = false
	}
	for _, sess := range s.st.Sessions {
		if sess.UserID == uid {
			sess.Revoked = true
		}
	}
	for h, rt := range s.st.Refresh {
		if rt.UserID == uid {
			delete(s.st.Refresh, h)
		}
	}
	for id, d := range s.st.Devices {
		if d.UserID == uid {
			delete(s.st.Devices, id)
		}
	}
	s.emit(uid, "user.erased")
	s.audit.Append(uid, "erase", "user", "ok", nil)
}

func (s *Service) SetStatus(uid, status string) {
	u := s.st.Users[uid]
	if u == nil || u.Status == "deleted" {
		return
	}
	u.Status = status
	if status != "active" {
		for _, sess := range s.st.Sessions {
			if sess.UserID == uid {
				sess.Revoked = true
			}
		}
	}
	s.emit(uid, "user.status")
}

// ---------- MFA ----------

func (s *Service) MFAEnroll(uid string) string {
	secret := cryptoutil.NewTOTPSecret()
	u := s.st.Users[uid]
	u.MFASecret, u.MFAEnabled = secret, false
	return secret
}

func (s *Service) MFAConfirm(uid, code string) error {
	u := s.st.Users[uid]
	if u == nil || u.MFASecret == "" {
		return ErrInvalidOTP
	}
	c, ok := cryptoutil.TOTPVerify(u.MFASecret, code, s.clk.Now(), u.MFALastCounter)
	if !ok {
		return ErrInvalidOTP
	}
	u.MFAEnabled, u.MFALastCounter = true, c
	s.audit.Append(uid, "mfa_enroll", "user", "ok", nil)
	return nil
}

// ---------- authentication ----------

func (s *Service) Login(req LoginRequest) (LoginResult, error) {
	now := s.clk.Now()
	u := s.userByEmail(req.Email)
	if u == nil || u.Status != "active" {
		cryptoutil.VerifyPassword(req.Password, dummyHash()) // equalise timing: no user enumeration
		s.audit.Append(req.Email, "login", "session", "deny", map[string]any{"why": "invalid_credentials"})
		return LoginResult{}, ErrInvalidCredentials
	}
	if u.LockedUntil.After(now) {
		s.audit.Append(u.ID, "login", "session", "deny", map[string]any{"why": "locked"})
		return LoginResult{}, ErrAccountLocked
	}
	if !cryptoutil.VerifyPassword(req.Password, u.PWHash) {
		s.fail(u)
		return LoginResult{}, ErrInvalidCredentials
	}
	risk := s.risk(u, req.DeviceID, req.IP)
	if risk >= 70 {
		s.audit.Append(u.ID, "login", "session", "deny", map[string]any{"why": "risk", "risk": risk})
		return LoginResult{}, ErrRiskDenied
	}
	amr, acr, last := []string{"pwd"}, 1, u.MFALastCounter
	if u.MFAEnabled {
		if req.OTP == "" {
			return LoginResult{Status: "mfa_required"}, nil
		}
		c, ok := cryptoutil.TOTPVerify(u.MFASecret, req.OTP, now, u.MFALastCounter)
		if !ok {
			s.fail(u)
			return LoginResult{}, ErrInvalidOTP
		}
		last, amr, acr = c, append(amr, "otp"), 2
	}
	sid := cryptoutil.NewID()
	u.FailedAttempts, u.LockedUntil, u.LastIPPrefix, u.MFALastCounter = 0, time.Time{}, IPPrefix(req.IP), last
	s.st.Sessions[sid] = &store.Session{SID: sid, UserID: u.ID, DeviceID: req.DeviceID, ACR: acr, AMR: amr,
		AuthTime: now, IPPrefix: IPPrefix(req.IP), Risk: risk}
	s.audit.Append(u.ID, "login", "session", "ok", map[string]any{"acr": acr, "risk": risk})
	t, err := s.Issue(u, sid, true, "")
	return LoginResult{Status: "ok", Tokens: t}, err
}

// StepUp raises the assurance level of a live session after a successful OTP challenge.
func (s *Service) StepUp(c *AccessClaims, otp string) (Tokens, error) {
	u := s.st.Users[c.Sub]
	if u == nil || !u.MFAEnabled {
		return Tokens{}, ErrMFANotEnrolled
	}
	counter, ok := cryptoutil.TOTPVerify(u.MFASecret, otp, s.clk.Now(), u.MFALastCounter)
	if !ok {
		s.fail(u)
		return Tokens{}, ErrInvalidOTP
	}
	u.MFALastCounter = counter
	sess := s.st.Sessions[c.Sid]
	sess.ACR, sess.AMR, sess.AuthTime = 2, []string{"pwd", "otp"}, s.clk.Now()
	s.audit.Append(u.ID, "step_up", "session", "ok", nil)
	return s.Issue(u, c.Sid, false, c.Scope)
}

// Refresh rotates refresh tokens; replay of a used token revokes the whole session (theft detection).
func (s *Service) Refresh(token string) (Tokens, error) {
	now := s.clk.Now()
	rt := s.st.Refresh[cryptoutil.SHA256Hex(token)]
	if rt == nil {
		return Tokens{}, ErrInvalidRefresh
	}
	sess := s.st.Sessions[rt.SID]
	if rt.Used {
		if sess != nil {
			sess.Revoked = true
		}
		s.audit.Append(rt.UserID, "refresh", "session", "deny", map[string]any{"why": "reuse_detected"})
		return Tokens{}, ErrRefreshReuse
	}
	u := s.st.Users[rt.UserID]
	if !rt.ExpiresAt.After(now) || sess == nil || sess.Revoked || u == nil || u.Status != "active" {
		return Tokens{}, ErrInvalidRefresh
	}
	rt.Used = true
	return s.Issue(u, rt.SID, true, rt.Scope)
}

func (s *Service) Logout(sid string) {
	if sess := s.st.Sessions[sid]; sess != nil {
		sess.Revoked = true
	}
}

// Issue mints an access token (and optionally a rotating refresh token) for a session.
func (s *Service) Issue(u *store.User, sid string, withRefresh bool, scope string) (Tokens, error) {
	now, sess := s.clk.Now(), s.st.Sessions[sid]
	claims := AccessClaims{Iss: Issuer, Aud: Audience, Sub: u.ID, Sid: sid, Did: sess.DeviceID, Role: u.Role,
		ACR: sess.ACR, AMR: sess.AMR, Risk: sess.Risk, IPP: sess.IPPrefix, AuthTime: sess.AuthTime.Unix(),
		Iat: now.Unix(), Exp: now.Add(AccessTTL).Unix(), Jti: cryptoutil.RandomToken(8), Scope: scope}
	at, err := cryptoutil.SignHS256(claims, s.activeKid, s.keys[s.activeKid])
	if err != nil {
		return Tokens{}, err
	}
	out := Tokens{AccessToken: at}
	if withRefresh {
		rt := cryptoutil.RandomToken(32)
		s.st.Refresh[cryptoutil.SHA256Hex(rt)] = &store.RefreshToken{Hash: cryptoutil.SHA256Hex(rt), SID: sid,
			UserID: u.ID, Scope: scope, ExpiresAt: now.Add(RefreshTTL)}
		out.RefreshToken = rt
	}
	return out, nil
}

// ParseAccessToken verifies signature, issuer, audience and expiry of an internal access token.
func ParseAccessToken(token string, keys map[string][]byte, now time.Time) (*AccessClaims, error) {
	payload, err := cryptoutil.VerifyHS256(token, keys)
	if err != nil {
		return nil, err
	}
	if err := cryptoutil.CheckRegistered(payload, Issuer, Audience, now); err != nil {
		return nil, err
	}
	var c AccessClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, cryptoutil.ErrMalformed
	}
	return &c, nil
}

// ---------- source-of-truth read model for the sync pipeline ----------

func (s *Service) User(uid string) *store.User { return s.st.Users[uid] }

func (s *Service) Snapshot(uid string) *Snapshot {
	u := s.st.Users[uid]
	if u == nil {
		return nil
	}
	c := map[string]bool{}
	for k, v := range s.st.Consents[uid] {
		c[k] = v
	}
	return &Snapshot{ID: u.ID, Email: u.Email, Name: u.Name, Region: u.Region, Status: u.Status,
		Version: u.Version, CreatedAt: u.CreatedAt, Consents: c}
}

func (s *Service) AllUserIDs() []string { return append([]string(nil), s.st.UserOrder...) }

// ---------- internals ----------

func (s *Service) emit(uid, typ string) {
	u := s.st.Users[uid]
	u.Version++
	s.st.Outbox = append(s.st.Outbox, store.OutboxEvent{ID: len(s.st.Outbox) + 1, AggregateID: uid, Type: typ,
		Version: u.Version, CreatedAt: s.clk.Now()})
}

func (s *Service) userByEmail(email string) *store.User {
	id, ok := s.st.EmailIndex[strings.ToLower(strings.TrimSpace(email))]
	if !ok {
		return nil
	}
	return s.st.Users[id]
}

func (s *Service) fail(u *store.User) {
	u.FailedAttempts++
	if u.FailedAttempts >= LockAfter {
		u.LockedUntil = s.clk.Now().Add(LockFor)
	}
	s.audit.Append(u.ID, "login", "session", "deny", map[string]any{"why": "bad_credential", "failures": u.FailedAttempts})
}

func (s *Service) risk(u *store.User, deviceID, ip string) int {
	risk := 0
	if !s.devices.IsEnrolled(u.ID, deviceID) {
		risk += 30
	}
	if u.LastIPPrefix != "" && u.LastIPPrefix != IPPrefix(ip) {
		risk += 20
	}
	if u.FailedAttempts >= 3 {
		risk += 25
	}
	return risk
}
