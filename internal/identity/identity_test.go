package identity_test

import (
	"errors"
	"testing"
	"time"

	"github.com/yourname/zt-ciam/internal/fixture"
	"github.com/yourname/zt-ciam/internal/identity"
)

func wantErr(t *testing.T, err error, want identity.Error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("got error %v, want %v", err, want)
	}
}

func TestWeakPasswordAndDuplicateEmail(t *testing.T) {
	e := fixture.NewEnv()
	_, err := e.IDP.Register("a@x.com", "short", "", "EU", nil, "")
	wantErr(t, err, identity.ErrWeakPassword)
	if _, err := e.IDP.Register("a@x.com", fixture.Password, "", "EU", nil, ""); err != nil {
		t.Fatal(err)
	}
	_, err = e.IDP.Register("A@X.com", fixture.Password, "", "EU", nil, "")
	wantErr(t, err, identity.ErrEmailTaken)
}

func TestMFARequiredThenAAL2(t *testing.T) {
	e := fixture.NewEnv()
	u := e.NewUser(fixture.UserOpts{})
	r, err := e.IDP.Login(identity.LoginRequest{Email: u.Email, Password: fixture.Password, DeviceID: u.DeviceID, IP: fixture.IP})
	if err != nil || r.Status != "mfa_required" {
		t.Fatalf("got %+v %v", r, err)
	}
	if r := e.Login(u, fixture.IP); r.Status != "ok" || r.AccessToken == "" {
		t.Fatalf("login failed: %+v", r)
	}
}

func TestOTPCannotBeReplayed(t *testing.T) {
	e := fixture.NewEnv()
	u := e.NewUser(fixture.UserOpts{})
	req := identity.LoginRequest{Email: u.Email, Password: fixture.Password, DeviceID: u.DeviceID, IP: fixture.IP, OTP: e.OTP(u.Secret)}
	if _, err := e.IDP.Login(req); err != nil {
		t.Fatal(err)
	}
	_, err := e.IDP.Login(req)
	wantErr(t, err, identity.ErrInvalidOTP)
}

func TestLockoutAfterRepeatedFailures(t *testing.T) {
	e := fixture.NewEnv()
	if _, err := e.IDP.Register("b@x.com", fixture.Password, "", "EU", nil, ""); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		_, err := e.IDP.Login(identity.LoginRequest{Email: "b@x.com", Password: "wrong-password-xx"})
		wantErr(t, err, identity.ErrInvalidCredentials)
	}
	_, err := e.IDP.Login(identity.LoginRequest{Email: "b@x.com", Password: fixture.Password})
	wantErr(t, err, identity.ErrAccountLocked)
	e.Clock.Advance(16 * time.Minute)
	if r, err := e.IDP.Login(identity.LoginRequest{Email: "b@x.com", Password: fixture.Password}); err != nil || r.Status != "ok" {
		t.Fatalf("login after lockout expiry: %+v %v", r, err)
	}
}

func TestUnknownUserIndistinguishable(t *testing.T) {
	e := fixture.NewEnv()
	_, err := e.IDP.Login(identity.LoginRequest{Email: "nobody@x.com", Password: fixture.Password})
	wantErr(t, err, identity.ErrInvalidCredentials)
}

func TestRefreshRotationAndReuseDetection(t *testing.T) {
	e := fixture.NewEnv()
	if _, err := e.IDP.Register("c@x.com", fixture.Password, "", "EU", nil, ""); err != nil {
		t.Fatal(err)
	}
	r1, _ := e.IDP.Login(identity.LoginRequest{Email: "c@x.com", Password: fixture.Password})
	r2, err := e.IDP.Refresh(r1.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.IDP.Refresh(r1.RefreshToken) // attacker replays the stolen, already-used token
	wantErr(t, err, identity.ErrRefreshReuse)
	_, err = e.IDP.Refresh(r2.RefreshToken) // the whole session family is burned, including the legit new token
	wantErr(t, err, identity.ErrInvalidRefresh)
}

func TestNewDeviceNewNetworkAndFailuresDenied(t *testing.T) {
	e := fixture.NewEnv()
	if _, err := e.IDP.Register("d@x.com", fixture.Password, "", "EU", nil, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.IDP.Login(identity.LoginRequest{Email: "d@x.com", Password: fixture.Password, IP: "198.51.100.1"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		_, _ = e.IDP.Login(identity.LoginRequest{Email: "d@x.com", Password: "bad-password-xxx", IP: "198.51.100.1"})
	}
	// new device (30) + new network (20) + recent failures (25) = 75 -> denied
	_, err := e.IDP.Login(identity.LoginRequest{Email: "d@x.com", Password: fixture.Password, IP: "192.0.2.9"})
	wantErr(t, err, identity.ErrRiskDenied)
}

func TestAuditChainDetectsTampering(t *testing.T) {
	e := fixture.NewEnv()
	_, _ = e.IDP.Register("e@x.com", fixture.Password, "", "EU", nil, "")
	_, _ = e.IDP.Login(identity.LoginRequest{Email: "e@x.com", Password: fixture.Password})
	if ok, _ := e.Audit.Verify(); !ok {
		t.Fatal("fresh chain should verify")
	}
	e.Store.Audit[0].Decision = "tampered"
	if ok, seq := e.Audit.Verify(); ok || seq != 1 {
		t.Fatalf("tampering not detected: ok=%v seq=%d", ok, seq)
	}
}
