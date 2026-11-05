// Package policy is the policy decision point (PDP): declarative, default-deny, evaluated on EVERY request.
//
// Each resource lists the conditions that must hold. Failures are classed as hard denials or "step_up"
// (fixable by re-authenticating with a stronger factor).
package policy

import (
	"strings"
	"time"

	"github.com/brandonrubio/gatekeep/internal/device"
	"github.com/brandonrubio/gatekeep/internal/identity"
)

const (
	Allow  = "allow"
	Deny   = "deny"
	StepUp = "step_up"

	CorpNetPrefix = "10."
	MaxPostureAge = time.Hour
)

type OwnerMode int

const (
	OwnerAny       OwnerMode = iota
	OwnerRequired            // subject must be the target user
	OwnerForbidden           // subject must NOT be the target user (e.g. support acting on a customer)
)

type Rule struct {
	Roles      []string
	Owner      OwnerMode
	MinACR     int           // authentication assurance level required (2 = MFA)
	MaxRisk    int           // 0 = unlimited
	Device     string        // "" | registered | compliant | managed
	MaxAuthAge time.Duration // 0 = unlimited
	Network    string        // "" | corp
	NeedGrant  bool          // requires a live just-in-time grant
}

var Policies = map[string]Rule{
	"profile:read":     {Roles: []string{"customer"}, Owner: OwnerRequired, MinACR: 1, MaxRisk: 60},
	"profile:update":   {Roles: []string{"customer"}, Owner: OwnerRequired, MinACR: 1, MaxRisk: 40, Device: "registered"},
	"consent:update":   {Roles: []string{"customer"}, Owner: OwnerRequired, MinACR: 1, MaxRisk: 40, Device: "registered"},
	"payment:read":     {Roles: []string{"customer"}, Owner: OwnerRequired, MinACR: 2, MaxRisk: 10, Device: "compliant", MaxAuthAge: 15 * time.Minute},
	"support:customer": {Roles: []string{"support"}, Owner: OwnerForbidden, MinACR: 2, MaxRisk: 10, Device: "managed", NeedGrant: true, MaxAuthAge: time.Hour},
	"admin:export":     {Roles: []string{"admin"}, MinACR: 2, MaxRisk: 20, Device: "managed", Network: "corp", MaxAuthAge: 5 * time.Minute},
}

type Decision struct {
	Effect  string   `json:"effect"`
	Reasons []string `json:"reasons"`
}

func (d Decision) Allowed() bool { return d.Effect == Allow }

// Context is everything the PDP may consider about one request.
type Context struct {
	Claims     *identity.AccessClaims
	Now        time.Time
	IP         string
	IPPrefix   string
	TargetUser string
	Posture    *device.PostureView
	Grant      bool
}

type Engine struct{ Policies map[string]Rule }

func NewEngine() *Engine { return &Engine{Policies: Policies} }

func deviceOK(level string, p *device.PostureView) (bool, string) {
	if p == nil {
		return false, "no_device_posture"
	}
	if p.Age > MaxPostureAge {
		return false, "stale_device_posture"
	}
	if level == "registered" {
		return true, ""
	}
	if !(p.DiskEncrypted && p.OSPatched && p.ScreenLock) {
		return false, "device_not_compliant"
	}
	if level == "managed" && !p.Managed {
		return false, "device_not_managed"
	}
	return true, ""
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func (e *Engine) Decide(resource string, c Context) Decision {
	rule, ok := e.Policies[resource]
	if !ok {
		return Decision{Deny, []string{"unknown_resource"}} // default deny
	}
	var hard, soft []string
	if !contains(rule.Roles, c.Claims.Role) {
		hard = append(hard, "role_not_permitted")
	}
	isOwner := c.TargetUser != "" && c.Claims.Sub == c.TargetUser
	if (rule.Owner == OwnerRequired && !isOwner) || (rule.Owner == OwnerForbidden && isOwner) {
		hard = append(hard, "ownership_violation")
	}
	risk := c.Claims.Risk
	if c.IPPrefix != c.Claims.IPP {
		risk += 20 // session-to-network binding drift raises risk
	}
	if rule.MaxRisk > 0 && risk > rule.MaxRisk {
		hard = append(hard, "risk_too_high")
	}
	if rule.Device != "" {
		if ok, why := deviceOK(rule.Device, c.Posture); !ok {
			hard = append(hard, why)
		}
	}
	if rule.Network == "corp" && !strings.HasPrefix(c.IP, CorpNetPrefix) {
		hard = append(hard, "not_on_corporate_network")
	}
	if rule.NeedGrant && !c.Grant {
		hard = append(hard, "no_jit_grant")
	}
	if c.Claims.ACR < rule.MinACR {
		soft = append(soft, "mfa_required")
	}
	if rule.MaxAuthAge > 0 && c.Now.Sub(time.Unix(c.Claims.AuthTime, 0)) > rule.MaxAuthAge {
		soft = append(soft, "recent_auth_required")
	}
	switch {
	case len(hard) > 0:
		return Decision{Deny, append(hard, soft...)}
	case len(soft) > 0:
		return Decision{StepUp, soft}
	}
	return Decision{Allow, []string{"policy_satisfied"}}
}
