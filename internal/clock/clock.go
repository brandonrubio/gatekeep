// Package clock abstracts time so security logic (token expiry, lockouts, backoff) is deterministic in tests.
package clock

import "time"

type Clock interface{ Now() time.Time }

type Real struct{}

func (Real) Now() time.Time { return time.Now() }

// Fake is a manually advanced clock for tests and demos.
type Fake struct{ T time.Time }

func NewFake() *Fake { return &Fake{T: time.Unix(1_700_000_000, 0)} }

func (f *Fake) Now() time.Time          { return f.T }
func (f *Fake) Advance(d time.Duration) { f.T = f.T.Add(d) }
