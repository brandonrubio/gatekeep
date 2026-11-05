// Command demo walks through identity, zero-trust access control, and the sync pipeline:  go run ./cmd/demo
package main

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/brandonrubio/gatekeep/internal/cryptoutil"
	"github.com/brandonrubio/gatekeep/internal/device"
	"github.com/brandonrubio/gatekeep/internal/fixture"
	"github.com/brandonrubio/gatekeep/internal/identity"
	"github.com/brandonrubio/gatekeep/internal/syncer"
)

func h(t string) { fmt.Printf("\n=== %s\n", t) }

func main() {
	e := fixture.NewEnv()
	ip := fixture.IP

	h("1. CIAM: register with explicit consent, enroll device + MFA")
	ada := e.NewUser(fixture.UserOpts{Email: "ada@example.com", Consents: map[string]bool{"marketing": true}})
	res, _ := e.IDP.Login(identity.LoginRequest{Email: ada.Email, Password: fixture.Password, DeviceID: ada.DeviceID, IP: ip})
	fmt.Println("login without OTP ->", res.Status)
	tok := e.Login(ada, ip)
	fmt.Println("login with OTP -> ok, acr=2")

	h("2. Zero trust: every request is evaluated (default deny)")
	for _, c := range []struct{ res, target, ip string }{
		{"profile:read", ada.ID, ip}, {"payment:read", ada.ID, ip}, {"profile:read", "someone-else", ip},
		{"payment:read", ada.ID, "198.51.100.9"}, {"admin:export", "", ip},
	} {
		d := e.Gateway.Authorize(tok.AccessToken, c.res, c.ip, c.target)
		who := c.target
		if c.target == ada.ID {
			who = "self"
		}
		fmt.Printf("%-14s target=%-13s ip=%-13s -> %-8s %v\n", c.res, who, c.ip, d.Effect, d.Reasons)
	}

	h("3. Posture degrades (disk encryption turned off) -> access shrinks without a new login")
	bad := fixture.GoodPosture
	bad.DiskEncrypted = false
	e.Devices.ReportPosture(ada.DeviceID, bad, device.SignPosture(ada.DeviceKey, bad))
	fmt.Println("payment:read ->", e.Gateway.Authorize(tok.AccessToken, "payment:read", ip, ada.ID).Reasons)
	e.Devices.ReportPosture(ada.DeviceID, fixture.GoodPosture, device.SignPosture(ada.DeviceKey, fixture.GoodPosture))

	h("4. Stolen refresh token replayed -> whole session revoked")
	stolen := tok.RefreshToken
	_, _ = e.IDP.Refresh(stolen)
	_, err := e.IDP.Refresh(stolen)
	fmt.Println("replay ->", err)
	fmt.Println("original access token now ->", e.Gateway.Authorize(tok.AccessToken, "profile:read", ip, ada.ID).Reasons)

	h("5. Sync: identity changes flow to CRM / marketing / warehouse (consent-aware, minimised)")
	bob := e.NewUser(fixture.UserOpts{Email: "bob@example.com", NoMFA: true, Consents: map[string]bool{"analytics": true}})
	crm := e.Sync.Targets["crm"]
	crm.FailRemaining = 2
	fmt.Println("run 1 (CRM flaky):", e.Sync.RunOnce())
	e.Clock.Advance(5 * time.Second)
	fmt.Println("run 2:", e.Sync.RunOnce())
	e.Clock.Advance(10 * time.Second)
	fmt.Println("run 3:", e.Sync.RunOnce())
	for _, r := range e.Sync.Targets["marketing"].Live() {
		fmt.Println("marketing sees:", r.Data)
	}
	_, hasPseudonym := e.Sync.Targets["warehouse"].Live()[cryptoutil.Pseudonym(bob.ID, e.Sync.Secret)]
	fmt.Println("warehouse keys are pseudonyms:", hasPseudonym)

	h("6. Drift: corrupt a target, reconcile, repair")
	crm.Store[ada.ID].Data["email"] = "corrupted@evil.test"
	fmt.Printf("drift: stale=%v\n", e.Sync.Reconcile(false)["crm"].Stale)
	e.Sync.Reconcile(true)
	fmt.Println("after repair clean:", e.Sync.Reconcile(false)["crm"].Clean())

	h("7. Right to erasure propagates everywhere")
	e.IDP.EraseUser(ada.ID)
	e.Sync.RunOnce()
	leaked := false
	for name, t := range e.Sync.Targets {
		fmt.Printf("%s: %d live records\n", name, len(t.Live()))
		leaked = leaked || strings.Contains(fmt.Sprint(storeDump(t.Store)), "ada@example.com")
	}
	fmt.Println("PII left for Ada:", leaked, "| errors.Is check:", errors.Is(err, identity.ErrRefreshReuse))

	h("8. Audit log")
	ok, _ := e.Audit.Verify()
	fmt.Println("rows:", len(e.Store.Audit), "| chain valid:", ok)
}

func storeDump(m map[string]*syncer.Record) []map[string]any {
	var out []map[string]any
	for _, r := range m {
		out = append(out, r.Data)
	}
	return out
}
