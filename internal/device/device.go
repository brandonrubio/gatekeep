// Package device is the device registry with signed posture reports (stand-in for MDM / TPM attestation).
package device

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/brandonrubio/gatekeep/internal/clock"
	"github.com/brandonrubio/gatekeep/internal/cryptoutil"
	"github.com/brandonrubio/gatekeep/internal/store"
)

type Registry struct {
	st  *store.Store
	clk clock.Clock
}

func New(st *store.Store, clk clock.Clock) *Registry { return &Registry{st: st, clk: clk} }

// PostureView is a posture report plus how old it is.
type PostureView struct {
	store.Posture
	Age time.Duration
}

func SignPosture(key []byte, p store.Posture) string {
	b, _ := json.Marshal(p) // struct field order is fixed, so this is canonical
	m := hmac.New(sha256.New, key)
	m.Write(b)
	return hex.EncodeToString(m.Sum(nil))
}

func (r *Registry) Enroll(userID, label string) (deviceID string, key []byte) {
	deviceID, key = cryptoutil.NewID(), cryptoutil.RandomBytes(32)
	r.st.Devices[deviceID] = &store.Device{ID: deviceID, UserID: userID, Label: label, Key: key}
	return deviceID, key
}

func (r *Registry) IsEnrolled(userID, deviceID string) bool {
	d, ok := r.st.Devices[deviceID]
	return deviceID != "" && ok && d.UserID == userID
}

// ReportPosture ignores unsigned or forged reports: client claims are never trusted on their own.
func (r *Registry) ReportPosture(deviceID string, p store.Posture, signature string) bool {
	d, ok := r.st.Devices[deviceID]
	if !ok || !hmac.Equal([]byte(SignPosture(d.Key, p)), []byte(signature)) {
		return false
	}
	d.Posture, d.ReportedAt = &p, r.clk.Now()
	return true
}

func (r *Registry) GetPosture(userID, deviceID string) *PostureView {
	d, ok := r.st.Devices[deviceID]
	if deviceID == "" || !ok || d.UserID != userID || d.Posture == nil {
		return nil
	}
	return &PostureView{Posture: *d.Posture, Age: r.clk.Now().Sub(d.ReportedAt)}
}
