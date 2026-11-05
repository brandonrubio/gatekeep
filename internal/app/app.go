// Package app wires the services together.
package app

import (
	"github.com/brandonrubio/gatekeep/internal/audit"
	"github.com/brandonrubio/gatekeep/internal/clock"
	"github.com/brandonrubio/gatekeep/internal/device"
	"github.com/brandonrubio/gatekeep/internal/gateway"
	"github.com/brandonrubio/gatekeep/internal/identity"
	"github.com/brandonrubio/gatekeep/internal/oidc"
	"github.com/brandonrubio/gatekeep/internal/store"
	"github.com/brandonrubio/gatekeep/internal/syncer"
)

type App struct {
	Store   *store.Store
	Clock   clock.Clock
	Audit   *audit.Log
	Devices *device.Registry
	IDP     *identity.Service
	Gateway *gateway.Gateway
	OIDC    *oidc.Provider
	Sync    *syncer.Pipeline
	Keys    map[string][]byte
}

// New builds an app. signingKey signs internal access tokens (HS256); generate it from a secret store in production.
func New(clk clock.Clock, issuer string, signingKey []byte) *App {
	keys := map[string][]byte{"k1": signingKey}
	st := store.New()
	au, dev := audit.New(st, clk), device.New(st, clk)
	idp := identity.New(st, dev, au, clk, keys, "k1")
	gw := gateway.New(st, dev, au, clk, keys)
	return &App{Store: st, Clock: clk, Audit: au, Devices: dev, IDP: idp, Gateway: gw, Keys: keys,
		OIDC: oidc.New(st, idp, gw, au, clk, issuer), Sync: syncer.New(st, idp, clk)}
}
