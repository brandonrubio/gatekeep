// Package audit implements a tamper-evident log: each row's hash covers the previous row's hash.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/yourname/zt-ciam/internal/clock"
	"github.com/yourname/zt-ciam/internal/store"
)

type Log struct {
	st  *store.Store
	clk clock.Clock
}

func New(st *store.Store, clk clock.Clock) *Log { return &Log{st: st, clk: clk} }

func (l *Log) Append(actor, action, resource, decision string, detail map[string]any) {
	prev := "genesis"
	if n := len(l.st.Audit); n > 0 {
		prev = l.st.Audit[n-1].Hash
	}
	db, _ := json.Marshal(detail) // map keys are sorted by encoding/json, so this is deterministic
	row := store.AuditRow{Seq: len(l.st.Audit) + 1, TS: l.clk.Now(), Actor: actor, Action: action,
		Resource: resource, Decision: decision, Detail: string(db), PrevHash: prev}
	row.Hash = hashRow(row)
	l.st.Audit = append(l.st.Audit, row)
}

func hashRow(r store.AuditRow) string {
	b, _ := json.Marshal([]any{r.PrevHash, r.TS.UnixNano(), r.Actor, r.Action, r.Resource, r.Decision, r.Detail})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Verify returns (true, 0) or (false, firstBadSeq).
func (l *Log) Verify() (bool, int) {
	prev := "genesis"
	for _, r := range l.st.Audit {
		if r.PrevHash != prev || r.Hash != hashRow(r) {
			return false, r.Seq
		}
		prev = r.Hash
	}
	return true, 0
}
