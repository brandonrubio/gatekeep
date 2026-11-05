// Package gateway is the policy enforcement point (PEP). Nothing is trusted because of where it came from:
// every call re-validates the token, the live session, the user's status, device posture, and policy.
package gateway

import (
	"time"

	"github.com/brandonrubio/gatekeep/internal/audit"
	"github.com/brandonrubio/gatekeep/internal/clock"
	"github.com/brandonrubio/gatekeep/internal/device"
	"github.com/brandonrubio/gatekeep/internal/identity"
	"github.com/brandonrubio/gatekeep/internal/policy"
	"github.com/brandonrubio/gatekeep/internal/store"
)

type Gateway struct {
	st      *store.Store
	devices *device.Registry
	audit   *audit.Log
	clk     clock.Clock
	keys    map[string][]byte
	pdp     *policy.Engine
}

func New(st *store.Store, d *device.Registry, a *audit.Log, clk clock.Clock, keys map[string][]byte) *Gateway {
	return &Gateway{st: st, devices: d, audit: a, clk: clk, keys: keys, pdp: policy.NewEngine()}
}

// GrantAccess creates a just-in-time, time-boxed, reason-bound grant (e.g. for a support case).
func (g *Gateway) GrantAccess(grantee, subject, resource, reason string, ttl time.Duration) {
	g.st.Grants = append(g.st.Grants, store.Grant{Grantee: grantee, Subject: subject, Resource: resource,
		Reason: reason, ExpiresAt: g.clk.Now().Add(ttl)})
	g.audit.Append(grantee, "grant", resource, "ok", map[string]any{"subject": subject, "reason": reason, "ttl": ttl.Seconds()})
}

// SessionClaims validates the token AND the live session AND the user's status.
// It returns the claims (when parseable) and a deny reason ("" when everything is fine).
func (g *Gateway) SessionClaims(token string) (*identity.AccessClaims, string) {
	c, err := identity.ParseAccessToken(token, g.keys, g.clk.Now())
	if err != nil {
		return nil, "token_" + err.Error()
	}
	if s := g.st.Sessions[c.Sid]; s == nil || s.Revoked {
		return c, "session_revoked"
	}
	if u := g.st.Users[c.Sub]; u == nil || u.Status != "active" {
		return c, "user_inactive"
	}
	return c, ""
}

func (g *Gateway) Authorize(token, resource, ip, targetUser string) policy.Decision {
	now := g.clk.Now()
	c, why := g.SessionClaims(token)
	if why != "" {
		return g.done(c, resource, policy.Decision{Effect: policy.Deny, Reasons: []string{why}}, ip, targetUser)
	}
	grant := false
	if targetUser != "" {
		for _, gr := range g.st.Grants {
			if gr.Grantee == c.Sub && gr.Subject == targetUser && gr.Resource == resource && gr.ExpiresAt.After(now) {
				grant = true
			}
		}
	}
	d := g.pdp.Decide(resource, policy.Context{Claims: c, Now: now, IP: ip, IPPrefix: identity.IPPrefix(ip),
		TargetUser: targetUser, Posture: g.devices.GetPosture(c.Sub, c.Did), Grant: grant})
	return g.done(c, resource, d, ip, targetUser)
}

func (g *Gateway) done(c *identity.AccessClaims, resource string, d policy.Decision, ip, target string) policy.Decision {
	actor := "anonymous"
	if c != nil {
		actor = c.Sub
	}
	g.audit.Append(actor, "access", resource, d.Effect, map[string]any{"reasons": d.Reasons, "ip": ip, "target": target})
	return d
}
