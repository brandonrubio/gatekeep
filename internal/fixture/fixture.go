// Package fixture holds helpers shared by tests and the demo programs. It panics on setup errors.
package fixture

import (
	"time"

	"github.com/brandonrubio/gatekeep/internal/app"
	"github.com/brandonrubio/gatekeep/internal/clock"
	"github.com/brandonrubio/gatekeep/internal/cryptoutil"
	"github.com/brandonrubio/gatekeep/internal/device"
	"github.com/brandonrubio/gatekeep/internal/identity"
	"github.com/brandonrubio/gatekeep/internal/store"
)

const (
	Password = "correct horse battery"
	IP       = "203.0.113.5"
	Issuer   = "https://idp.example.test"
)

var GoodPosture = store.Posture{Managed: true, DiskEncrypted: true, OSPatched: true, ScreenLock: true}

// Env is an app wired to a controllable clock.
type Env struct {
	*app.App
	Clock *clock.Fake
}

func NewEnv() *Env {
	cryptoutil.PBKDF2Iterations = 1000 // fast hashing for tests/demos only
	clk := clock.NewFake()
	return &Env{App: app.New(clk, Issuer, []byte("dev-only-signing-key-rotate-me-32b")), Clock: clk}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func (e *Env) OTP(secret string) string {
	return cryptoutil.TOTPCode(secret, uint64(e.Clock.Now().Unix()/30))
}

type User struct {
	ID, Email, DeviceID, Secret string
	DeviceKey                   []byte
}

type UserOpts struct {
	Email    string
	Role     string
	Posture  *store.Posture
	Consents map[string]bool
	NoMFA    bool
}

// NewUser registers a user with an enrolled device (signed posture) and, unless NoMFA, confirmed TOTP.
func (e *Env) NewUser(o UserOpts) *User {
	if o.Email == "" {
		o.Email = "a@example.com"
	}
	posture := GoodPosture
	if o.Posture != nil {
		posture = *o.Posture
	}
	id, err := e.IDP.Register(o.Email, Password, "Test", "EU", o.Consents, o.Role)
	must(err)
	did, key := e.Devices.Enroll(id, "laptop")
	e.Devices.ReportPosture(did, posture, device.SignPosture(key, posture))
	u := &User{ID: id, Email: o.Email, DeviceID: did, DeviceKey: key}
	if !o.NoMFA {
		u.Secret = e.IDP.MFAEnroll(id)
		must(e.IDP.MFAConfirm(id, e.OTP(u.Secret)))
		e.Clock.Advance(30 * time.Second) // the next TOTP window: confirm consumed the previous counter
	}
	return u
}

// Login logs the user in (with a fresh OTP if enrolled) and panics on failure.
func (e *Env) Login(u *User, ip string) identity.LoginResult {
	otp := ""
	if u.Secret != "" {
		otp = e.OTP(u.Secret)
	}
	r, err := e.IDP.Login(identity.LoginRequest{Email: u.Email, Password: Password, DeviceID: u.DeviceID, IP: ip, OTP: otp})
	must(err)
	return r
}
