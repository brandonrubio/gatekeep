// Package syncer is the identity -> downstream sync pipeline.
//
// Design:
//   - Transactional outbox: the identity service writes a thin event together with the state change.
//   - The relay delivers at-least-once; targets are idempotent (event-id dedupe + monotonic aggregate versions),
//     so duplicates and out-of-order delivery converge to the right state.
//   - Events carry no PII. The relay reads the *current* source snapshot at delivery time, so erased data can
//     never be replayed from a queue.
//   - Per-target transforms apply data minimisation and consent: marketing only sees opted-in users, the
//     warehouse only sees pseudonymous IDs for analytics-consented users.
//   - Retry with exponential backoff -> dead-letter queue -> operator replay. Reconciliation detects and repairs drift.
package syncer

import (
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/brandonrubio/gatekeep/internal/clock"
	"github.com/brandonrubio/gatekeep/internal/cryptoutil"
	"github.com/brandonrubio/gatekeep/internal/identity"
	"github.com/brandonrubio/gatekeep/internal/store"
)

// TransientError marks a retryable downstream failure.
type TransientError struct{ Target string }

func (e TransientError) Error() string { return e.Target + " unavailable" }

// Record is a downstream row. Data == nil is a PII-free tombstone (version only) so late, older events
// cannot resurrect deleted data.
type Record struct {
	Version int
	Data    map[string]any
}

// Target simulates a downstream system.
type Target struct {
	Name          string
	Store         map[string]*Record
	FailRemaining int // fault injection: the next N applies fail
	applied       map[int]bool
}

func newTarget(name string) *Target {
	return &Target{Name: name, Store: map[string]*Record{}, applied: map[int]bool{}}
}

// Apply is idempotent: duplicates and stale versions are no-ops.
func (t *Target) Apply(eventID int, key string, version int, data map[string]any) (string, error) {
	if t.FailRemaining > 0 {
		t.FailRemaining--
		return "", TransientError{t.Name}
	}
	if t.applied[eventID] {
		return "duplicate", nil
	}
	t.applied[eventID] = true
	if cur, ok := t.Store[key]; ok && cur.Version >= version {
		return "stale", nil
	}
	t.Store[key] = &Record{Version: version, Data: data}
	return "applied", nil
}

// Live returns the records that hold data (tombstones excluded).
func (t *Target) Live() map[string]*Record {
	out := map[string]*Record{}
	for k, r := range t.Store {
		if r.Data != nil {
			out[k] = r
		}
	}
	return out
}

// ---- transforms: snapshot -> (key, data); nil data means "must not exist downstream" ----

type Transform func(s *identity.Snapshot, secret []byte) (string, map[string]any)

func toCRM(s *identity.Snapshot, _ []byte) (string, map[string]any) {
	if s.Status == "deleted" {
		return s.ID, nil
	}
	return s.ID, map[string]any{"email": s.Email, "name": s.Name, "region": s.Region, "status": s.Status}
}

func toMarketing(s *identity.Snapshot, _ []byte) (string, map[string]any) {
	if s.Status != "active" || !s.Consents["marketing"] {
		return s.ID, nil // suppressed: no consent -> must not exist downstream
	}
	return s.ID, map[string]any{"email": s.Email, "region": s.Region}
}

func toWarehouse(s *identity.Snapshot, secret []byte) (string, map[string]any) {
	pid := cryptoutil.Pseudonym(s.ID, secret) // no raw identifiers in analytics
	if s.Status != "active" || !s.Consents["analytics"] {
		return pid, nil
	}
	return pid, map[string]any{"region": s.Region, "signup_month": int(s.CreatedAt.Unix() / (30 * 86400))}
}

type Stats map[string]int

type Pipeline struct {
	Targets     map[string]*Target
	Secret      []byte
	MaxAttempts int
	BaseBackoff time.Duration

	st         *store.Store
	idp        *identity.Service
	clk        clock.Clock
	order      []string
	transforms map[string]Transform
}

func New(st *store.Store, idp *identity.Service, clk clock.Clock) *Pipeline {
	order := []string{"crm", "marketing", "warehouse"}
	p := &Pipeline{Targets: map[string]*Target{}, Secret: []byte("warehouse-pseudonym-key"), MaxAttempts: 4,
		BaseBackoff: 2 * time.Second, st: st, idp: idp, clk: clk, order: order,
		transforms: map[string]Transform{"crm": toCRM, "marketing": toMarketing, "warehouse": toWarehouse}}
	for _, n := range order {
		p.Targets[n] = newTarget(n)
	}
	return p
}

// RunOnce attempts every pending delivery that is due.
func (p *Pipeline) RunOnce() Stats {
	now, stats := p.clk.Now(), Stats{}
	for _, ev := range p.st.Outbox {
		for _, name := range p.order {
			key := store.DeliveryKey{EventID: ev.ID, Target: name}
			d := p.st.Deliveries[key]
			if d == nil {
				d = &store.Delivery{EventID: ev.ID, Target: name, Status: "pending"}
				p.st.Deliveries[key] = d
			}
			if d.Status != "pending" || d.NextAttemptAt.After(now) {
				continue
			}
			snap := p.idp.Snapshot(ev.AggregateID)
			k, data := p.transforms[name](snap, p.Secret)
			res, err := p.Targets[name].Apply(ev.ID, k, snap.Version, data)
			d.Attempts++
			if err != nil {
				d.LastError = err.Error()
				if d.Attempts >= p.MaxAttempts {
					d.Status = "dead"
					stats["dead"]++
				} else {
					d.NextAttemptAt = now.Add(p.BaseBackoff * time.Duration(1<<uint(d.Attempts)))
					stats["retry"]++
				}
				continue
			}
			d.Status, d.LastError = "done", ""
			stats[res]++
		}
	}
	return stats
}

func (p *Pipeline) DeadLetters() []store.Delivery {
	var out []store.Delivery
	for _, d := range p.st.Deliveries {
		if d.Status == "dead" {
			out = append(out, *d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EventID < out[j].EventID })
	return out
}

// ReplayDead puts dead-lettered deliveries back in the queue (after the operator fixed the cause).
func (p *Pipeline) ReplayDead() int {
	n := 0
	for _, d := range p.st.Deliveries {
		if d.Status == "dead" {
			d.Status, d.Attempts, d.NextAttemptAt = "pending", 0, time.Time{}
			n++
		}
	}
	return n
}

// Lag is the number of deliveries not yet confirmed: a key health metric to alert on.
func (p *Pipeline) Lag() int {
	done := 0
	for _, d := range p.st.Deliveries {
		if d.Status == "done" {
			done++
		}
	}
	return len(p.st.Outbox)*len(p.order) - done
}

// Drift lists how a target deviates from what the source says it should contain.
type Drift struct {
	Missing, Stale, Unexpected, Orphaned []string
}

func (d *Drift) Clean() bool {
	return len(d.Missing)+len(d.Stale)+len(d.Unexpected)+len(d.Orphaned) == 0
}

// Reconcile compares every target with the expected state and optionally repairs it. It catches lost writes,
// silent corruption and backup-restore resurrections that an event stream alone cannot.
func (p *Pipeline) Reconcile(repair bool) map[string]*Drift {
	report := map[string]*Drift{}
	for _, name := range p.order {
		t, drift := p.Targets[name], &Drift{}
		expected := map[string]*Record{}
		for _, uid := range p.idp.AllUserIDs() {
			snap := p.idp.Snapshot(uid)
			key, data := p.transforms[name](snap, p.Secret)
			expected[key] = &Record{Version: snap.Version, Data: data}
			cur := t.Store[key]
			switch {
			case data != nil && cur == nil:
				drift.Missing = append(drift.Missing, key)
			case data != nil && !reflect.DeepEqual(cur.Data, data):
				drift.Stale = append(drift.Stale, key)
			case data == nil && cur != nil && cur.Data != nil:
				drift.Unexpected = append(drift.Unexpected, key) // present although consent/policy says it must not be
			}
		}
		for k := range t.Store {
			if _, ok := expected[k]; !ok {
				drift.Orphaned = append(drift.Orphaned, k)
			}
		}
		sort.Strings(drift.Orphaned)
		report[name] = drift
		if repair {
			for _, group := range [][]string{drift.Missing, drift.Stale, drift.Unexpected} {
				for _, k := range group {
					t.Store[k] = &Record{Version: expected[k].Version, Data: expected[k].Data}
				}
			}
			for _, k := range drift.Orphaned {
				delete(t.Store, k)
			}
		}
	}
	return report
}

func (s Stats) String() string {
	keys := make([]string, 0, len(s))
	for k := range s {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := ""
	for _, k := range keys {
		out += fmt.Sprintf("%s=%d ", k, s[k])
	}
	return out
}
