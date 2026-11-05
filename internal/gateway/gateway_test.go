package gateway_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/brandonrubio/gatekeep/internal/device"
	"github.com/brandonrubio/gatekeep/internal/fixture"
	"github.com/brandonrubio/gatekeep/internal/identity"
	"github.com/brandonrubio/gatekeep/internal/policy"
)

const ip = fixture.IP

func session(t *testing.T, e *fixture.Env, o fixture.UserOpts) (*fixture.User, identity.LoginResult) {
	t.Helper()
	u := e.NewUser(o)
	return u, e.Login(u, ip)
}

func reasons(t *testing.T, e *fixture.Env, tok, res, ipAddr, target string, wantEffect string) []string {
	t.Helper()
	d := e.Gateway.Authorize(tok, res, ipAddr, target)
	if d.Effect != wantEffect {
		t.Fatalf("%s: effect %s (%v), want %s", res, d.Effect, d.Reasons, wantEffect)
	}
	return d.Reasons
}

func has(rs []string, want string) bool {
	for _, r := range rs {
		if r == want {
			return true
		}
	}
	return false
}

func TestDefaultDenyUnknownResourceAndGarbageToken(t *testing.T) {
	e := fixture.NewEnv()
	u, s := session(t, e, fixture.UserOpts{})
	reasons(t, e, s.AccessToken, "nope:thing", ip, u.ID, policy.Deny)
	reasons(t, e, "garbage", "profile:read", ip, "", policy.Deny)
}

func TestOwnerAllowedOthersDenied(t *testing.T) {
	e := fixture.NewEnv()
	u, s := session(t, e, fixture.UserOpts{})
	reasons(t, e, s.AccessToken, "profile:read", ip, u.ID, policy.Allow)
	if r := reasons(t, e, s.AccessToken, "profile:read", ip, "someone-else", policy.Deny); !has(r, "ownership_violation") {
		t.Fatalf("reasons %v", r)
	}
}

func TestSensitiveResourceNeedsMFA(t *testing.T) {
	e := fixture.NewEnv()
	u := e.NewUser(fixture.UserOpts{NoMFA: true})
	s, _ := e.IDP.Login(identity.LoginRequest{Email: u.Email, Password: fixture.Password, DeviceID: u.DeviceID, IP: ip})
	r := reasons(t, e, s.AccessToken, "payment:read", ip, u.ID, policy.StepUp)
	if !reflect.DeepEqual(r, []string{"mfa_required"}) {
		t.Fatalf("reasons %v", r)
	}
}

func TestRecentAuthRequiredThenStepUpSucceeds(t *testing.T) {
	e := fixture.NewEnv()
	u, s := session(t, e, fixture.UserOpts{})
	reasons(t, e, s.AccessToken, "payment:read", ip, u.ID, policy.Allow)
	e.Clock.Advance(1000 * time.Second) // older than payment:read's 15 minute auth window
	tok, err := e.IDP.Refresh(s.RefreshToken) // a refresh does NOT refresh auth_time
	if err != nil {
		t.Fatal(err)
	}
	r := reasons(t, e, tok.AccessToken, "payment:read", ip, u.ID, policy.StepUp)
	if !reflect.DeepEqual(r, []string{"recent_auth_required"}) {
		t.Fatalf("reasons %v", r)
	}
	claims, _ := identity.ParseAccessToken(tok.AccessToken, e.Keys, e.Clock.Now())
	e.Clock.Advance(30 * time.Second) // fresh TOTP window: the previous code was consumed
	stepped, err := e.IDP.StepUp(claims, e.OTP(u.Secret))
	if err != nil {
		t.Fatal(err)
	}
	reasons(t, e, stepped.AccessToken, "payment:read", ip, u.ID, policy.Allow)
}

func TestNonCompliantDeviceBlocksPayment(t *testing.T) {
	e := fixture.NewEnv()
	bad := fixture.GoodPosture
	bad.DiskEncrypted = false
	u, s := session(t, e, fixture.UserOpts{Posture: &bad})
	if r := reasons(t, e, s.AccessToken, "payment:read", ip, u.ID, policy.Deny); !has(r, "device_not_compliant") {
		t.Fatalf("reasons %v", r)
	}
}

func TestForgedPostureRejected(t *testing.T) {
	e := fixture.NewEnv()
	bad := fixture.GoodPosture
	bad.OSPatched = false
	u, s := session(t, e, fixture.UserOpts{Posture: &bad})
	if e.Devices.ReportPosture(u.DeviceID, fixture.GoodPosture, device.SignPosture([]byte("attacker-key"), fixture.GoodPosture)) {
		t.Fatal("forged posture accepted")
	}
	if r := reasons(t, e, s.AccessToken, "payment:read", ip, u.ID, policy.Deny); !has(r, "device_not_compliant") {
		t.Fatalf("reasons %v", r)
	}
}

func TestStalePostureDenied(t *testing.T) {
	e := fixture.NewEnv()
	u, s := session(t, e, fixture.UserOpts{})
	e.Clock.Advance(61 * time.Minute)
	tok, _ := e.IDP.Refresh(s.RefreshToken)
	if r := reasons(t, e, tok.AccessToken, "payment:read", ip, u.ID, policy.Deny); !has(r, "stale_device_posture") {
		t.Fatalf("reasons %v", r)
	}
}

func TestSuspensionRevokesValidToken(t *testing.T) {
	e := fixture.NewEnv()
	u, s := session(t, e, fixture.UserOpts{})
	reasons(t, e, s.AccessToken, "profile:read", ip, u.ID, policy.Allow)
	e.IDP.SetStatus(u.ID, "suspended")
	reasons(t, e, s.AccessToken, "profile:read", ip, u.ID, policy.Deny) // valid, unexpired JWT still refused
}

func TestExpiredTokenDenied(t *testing.T) {
	e := fixture.NewEnv()
	u, s := session(t, e, fixture.UserOpts{})
	e.Clock.Advance(6 * time.Minute)
	if r := reasons(t, e, s.AccessToken, "profile:read", ip, u.ID, policy.Deny); !has(r, "token_expired") {
		t.Fatalf("reasons %v", r)
	}
}

func TestNetworkDriftRaisesRisk(t *testing.T) {
	e := fixture.NewEnv()
	u, s := session(t, e, fixture.UserOpts{})
	reasons(t, e, s.AccessToken, "profile:update", "198.51.100.77", u.ID, policy.Allow) // risk 20 <= 40
	if r := reasons(t, e, s.AccessToken, "payment:read", "198.51.100.77", u.ID, policy.Deny); !has(r, "risk_too_high") {
		t.Fatalf("reasons %v", r)
	}
}

func TestSupportNeedsJITGrant(t *testing.T) {
	e := fixture.NewEnv()
	cust := e.NewUser(fixture.UserOpts{Email: "cust@example.com"})
	agent := e.NewUser(fixture.UserOpts{Email: "agent@example.com", Role: "support"})
	s := e.Login(agent, ip)
	if r := reasons(t, e, s.AccessToken, "support:customer", ip, cust.ID, policy.Deny); !has(r, "no_jit_grant") {
		t.Fatalf("reasons %v", r)
	}
	e.Gateway.GrantAccess(agent.ID, cust.ID, "support:customer", "case #4411", 100*time.Second)
	reasons(t, e, s.AccessToken, "support:customer", ip, cust.ID, policy.Allow)
	e.Clock.Advance(101 * time.Second) // grant expires (token still valid: 5 min TTL)
	if r := reasons(t, e, s.AccessToken, "support:customer", ip, cust.ID, policy.Deny); !has(r, "no_jit_grant") {
		t.Fatalf("reasons %v", r)
	}
}

func TestSupportCannotActOnSelf(t *testing.T) {
	e := fixture.NewEnv()
	agent := e.NewUser(fixture.UserOpts{Email: "agent@example.com", Role: "support"})
	s := e.Login(agent, ip)
	e.Gateway.GrantAccess(agent.ID, agent.ID, "support:customer", "self", time.Hour)
	if r := reasons(t, e, s.AccessToken, "support:customer", ip, agent.ID, policy.Deny); !has(r, "ownership_violation") {
		t.Fatalf("reasons %v", r)
	}
}

func TestAdminExportNeedsCorpNetwork(t *testing.T) {
	e := fixture.NewEnv()
	admin, s := session(t, e, fixture.UserOpts{Email: "root@example.com", Role: "admin"})
	_ = admin
	if r := reasons(t, e, s.AccessToken, "admin:export", ip, "", policy.Deny); !has(r, "not_on_corporate_network") {
		t.Fatalf("reasons %v", r)
	}
}

func TestEveryDecisionIsAudited(t *testing.T) {
	e := fixture.NewEnv()
	u, s := session(t, e, fixture.UserOpts{})
	count := func() int {
		n := 0
		for _, r := range e.Store.Audit {
			if r.Action == "access" {
				n++
			}
		}
		return n
	}
	before := count()
	e.Gateway.Authorize(s.AccessToken, "profile:read", ip, u.ID)
	e.Gateway.Authorize("junk", "profile:read", ip, "")
	if count()-before != 2 {
		t.Fatalf("expected 2 audit rows, got %d", count()-before)
	}
}
