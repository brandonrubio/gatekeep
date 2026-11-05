package syncer_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/yourname/zt-ciam/internal/cryptoutil"
	"github.com/yourname/zt-ciam/internal/fixture"
	"github.com/yourname/zt-ciam/internal/syncer"
)

// dump renders every key and value a target holds, so "no PII left" assertions can actually fail.
func dump(t *syncer.Target) string {
	var b strings.Builder
	for k, r := range t.Store {
		fmt.Fprintf(&b, "%s=%v;", k, r.Data)
	}
	return b.String()
}

func register(t *testing.T, e *fixture.Env, email, name string, consents map[string]bool) string {
	t.Helper()
	id, err := e.IDP.Register(email, fixture.Password, name, "EU", consents, "")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestConsentDrivesWhatEachSystemSees(t *testing.T) {
	e := fixture.NewEnv()
	id := register(t, e, "a@x.com", "Ann", map[string]bool{"marketing": true})
	e.Sync.RunOnce()
	if e.Sync.Targets["crm"].Live()[id].Data["email"] != "a@x.com" {
		t.Fatal("CRM should hold the customer")
	}
	m := e.Sync.Targets["marketing"].Live()[id].Data
	if len(m) != 2 || m["email"] != "a@x.com" || m["region"] != "EU" {
		t.Fatalf("marketing minimisation failed: %v", m)
	}
	if n := len(e.Sync.Targets["warehouse"].Live()); n != 0 {
		t.Fatalf("no analytics consent, warehouse has %d rows", n)
	}
}

func TestWarehouseIsPseudonymous(t *testing.T) {
	e := fixture.NewEnv()
	id := register(t, e, "a@x.com", "Ann", map[string]bool{"analytics": true})
	e.Sync.RunOnce()
	wh := e.Sync.Targets["warehouse"]
	pid := cryptoutil.Pseudonym(id, e.Sync.Secret)
	rec, ok := wh.Live()[pid]
	if !ok || len(wh.Live()) != 1 {
		t.Fatalf("expected exactly the pseudonymous row, got %v", wh.Live())
	}
	if _, hasEmail := rec.Data["email"]; hasEmail || strings.Contains(dump(wh), id) {
		t.Fatal("warehouse leaks direct identifiers")
	}
}

func TestConsentWithdrawalPropagates(t *testing.T) {
	e := fixture.NewEnv()
	id := register(t, e, "a@x.com", "Ann", map[string]bool{"marketing": true})
	e.Sync.RunOnce()
	if err := e.IDP.SetConsent(id, "marketing", false); err != nil {
		t.Fatal(err)
	}
	e.Sync.RunOnce()
	if _, ok := e.Sync.Targets["marketing"].Live()[id]; ok {
		t.Fatal("withdrawn consent still in marketing")
	}
	if _, ok := e.Sync.Targets["crm"].Live()[id]; !ok {
		t.Fatal("CRM record should remain")
	}
}

func TestErasurePropagatesAndLeavesNoPII(t *testing.T) {
	e := fixture.NewEnv()
	id := register(t, e, "a@x.com", "Ann", map[string]bool{"marketing": true, "analytics": true})
	e.Sync.RunOnce()
	e.IDP.EraseUser(id)
	e.Sync.RunOnce()
	for name, tgt := range e.Sync.Targets {
		d := dump(tgt)
		if len(tgt.Live()) != 0 || strings.Contains(d, "a@x.com") || strings.Contains(d, "Ann") {
			t.Fatalf("%s still holds data after erasure: %v", name, d)
		}
	}
	if d := e.Sync.Reconcile(false)["crm"]; len(d.Unexpected) != 0 {
		t.Fatalf("reconcile: %+v", d)
	}
}

func TestDuplicatesAndOutOfOrderConverge(t *testing.T) {
	e := fixture.NewEnv()
	id := register(t, e, "a@x.com", "v1", nil)
	for _, n := range []string{"v2", "v3"} {
		name := n
		e.IDP.UpdateProfile(id, &name, nil)
	}
	snap := e.IDP.Snapshot(id)
	crm := e.Sync.Targets["crm"]
	for ev := len(e.Store.Outbox); ev >= 1; ev-- { // deliver newest first
		if _, err := crm.Apply(ev, id, snap.Version, map[string]any{"name": "v3"}); err != nil {
			t.Fatal(err)
		}
	}
	if res, _ := crm.Apply(len(e.Store.Outbox), id, snap.Version, map[string]any{"name": "stale"}); res != "duplicate" {
		t.Fatalf("redelivery should be a duplicate, got %s", res)
	}
	e.Sync.RunOnce()
	if crm.Live()[id].Data["name"] != "v3" {
		t.Fatalf("did not converge: %v", crm.Live()[id].Data)
	}
}

func TestRetryBackoffThenSuccess(t *testing.T) {
	e := fixture.NewEnv()
	register(t, e, "a@x.com", "", nil)
	e.Sync.Targets["crm"].FailRemaining = 2
	if s := e.Sync.RunOnce(); s["retry"] != 1 {
		t.Fatalf("first run: %v", s)
	}
	if s := e.Sync.RunOnce(); s["retry"] != 0 { // still backing off: nothing attempted
		t.Fatalf("backoff ignored: %v", s)
	}
	e.Clock.Advance(5 * time.Second)
	if s := e.Sync.RunOnce(); s["retry"] != 1 {
		t.Fatalf("second attempt: %v", s)
	}
	e.Clock.Advance(10 * time.Second)
	if s := e.Sync.RunOnce(); s["applied"] != 1 {
		t.Fatalf("recovery: %v", s)
	}
	if lag := e.Sync.Lag(); lag != 0 {
		t.Fatalf("lag %d", lag)
	}
}

func TestDeadLetterAndReplay(t *testing.T) {
	e := fixture.NewEnv()
	id := register(t, e, "a@x.com", "", nil)
	crm := e.Sync.Targets["crm"]
	crm.FailRemaining = 1 << 30 // prolonged outage
	for i := 0; i < 8; i++ {
		e.Sync.RunOnce()
		e.Clock.Advance(time.Minute)
	}
	dl := e.Sync.DeadLetters()
	if len(dl) != 1 || dl[0].Target != "crm" {
		t.Fatalf("dead letters %+v", dl)
	}
	if _, ok := crm.Live()[id]; ok {
		t.Fatal("record delivered during outage")
	}
	crm.FailRemaining = 0 // outage over
	if n := e.Sync.ReplayDead(); n != 1 {
		t.Fatalf("replayed %d", n)
	}
	e.Sync.RunOnce()
	if _, ok := crm.Live()[id]; !ok || len(e.Sync.DeadLetters()) != 0 {
		t.Fatal("replay did not recover")
	}
}

func TestOneOutageDoesNotBlockOtherTargets(t *testing.T) {
	e := fixture.NewEnv()
	id := register(t, e, "a@x.com", "", map[string]bool{"marketing": true})
	e.Sync.Targets["crm"].FailRemaining = 99
	e.Sync.RunOnce()
	if _, ok := e.Sync.Targets["marketing"].Live()[id]; !ok {
		t.Fatal("marketing blocked by CRM outage")
	}
	if _, ok := e.Sync.Targets["crm"].Live()[id]; ok {
		t.Fatal("CRM should still be down")
	}
}

func TestReconcileDetectsAndRepairsDrift(t *testing.T) {
	e := fixture.NewEnv()
	a := register(t, e, "a@x.com", "Ann", map[string]bool{"marketing": true})
	b := register(t, e, "b@x.com", "Bob", map[string]bool{"marketing": true})
	e.Sync.RunOnce()
	crm, mkt := e.Sync.Targets["crm"], e.Sync.Targets["marketing"]
	delete(crm.Store, a)                               // lost write
	crm.Store[b].Data["name"] = "tampered"             // silent corruption
	mkt.Store["ghost"] = &syncer.Record{Version: 1, Data: map[string]any{"email": "ghost@x.com"}} // restored-from-backup orphan

	rep := e.Sync.Reconcile(false)
	if len(rep["crm"].Missing) != 1 || rep["crm"].Missing[0] != a || len(rep["crm"].Stale) != 1 || rep["crm"].Stale[0] != b {
		t.Fatalf("crm drift %+v", rep["crm"])
	}
	if len(rep["marketing"].Orphaned) != 1 || rep["marketing"].Orphaned[0] != "ghost" {
		t.Fatalf("marketing drift %+v", rep["marketing"])
	}
	e.Sync.Reconcile(true)
	for name, d := range e.Sync.Reconcile(false) {
		if !d.Clean() {
			t.Fatalf("%s still drifting after repair: %+v", name, d)
		}
	}
}
