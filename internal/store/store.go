// Package store is the in-memory system of record shared by the services.
//
// It stands in for a relational database. Services are NOT goroutine-safe on their own: the HTTP edge
// serialises requests with one mutex, which plays the role of a DB transaction boundary (so a state change
// and its outbox event are always committed together). Production would use Postgres transactions.
package store

import "time"

type User struct {
	ID, Email, Name, PWHash, Role, Status, Region string
	Version                                       int
	CreatedAt                                     time.Time
	MFASecret                                     string
	MFAEnabled                                    bool
	MFALastCounter                                int64
	FailedAttempts                                int
	LockedUntil                                   time.Time
	LastIPPrefix                                  string
}

type Session struct {
	SID, UserID, DeviceID string
	ACR                   int
	AMR                   []string
	AuthTime              time.Time
	IPPrefix              string
	Risk                  int
	Revoked               bool
}

type RefreshToken struct {
	Hash, SID, UserID, Scope string
	ExpiresAt                time.Time
	Used                     bool
}

type Posture struct {
	Managed       bool `json:"managed"`
	DiskEncrypted bool `json:"disk_encrypted"`
	OSPatched     bool `json:"os_patched"`
	ScreenLock    bool `json:"screen_lock"`
}

type Device struct {
	ID, UserID, Label string
	Key               []byte
	Posture           *Posture
	ReportedAt        time.Time
}

type Grant struct {
	Grantee, Subject, Resource, Reason string
	ExpiresAt                          time.Time
}

type OutboxEvent struct {
	ID                int
	AggregateID, Type string
	Version           int
	CreatedAt         time.Time
}

type DeliveryKey struct {
	EventID int
	Target  string
}

type Delivery struct {
	EventID       int
	Target        string
	Status        string // pending | done | dead
	Attempts      int
	NextAttemptAt time.Time
	LastError     string
}

type AuditRow struct {
	Seq                                             int
	TS                                              time.Time
	Actor, Action, Resource, Decision, Detail       string
	PrevHash, Hash                                  string
}

type OIDCClient struct {
	ID, Name     string
	RedirectURIs []string
}

type AuthCode struct {
	Hash, ClientID, UserID, SID, RedirectURI, Challenge, Nonce, Scope string
	AuthTime                                                          time.Time
	ACR                                                               int
	AMR                                                               []string
	ExpiresAt                                                         time.Time
	Used                                                              bool
}

type Store struct {
	Users      map[string]*User
	EmailIndex map[string]string          // normalised email -> user id
	UserOrder  []string                   // creation order, for stable iteration
	Consents   map[string]map[string]bool // user -> purpose -> granted
	Sessions   map[string]*Session
	Refresh    map[string]*RefreshToken // by token hash
	Devices    map[string]*Device
	Grants     []Grant
	Outbox     []OutboxEvent
	Deliveries map[DeliveryKey]*Delivery
	Audit      []AuditRow
	Clients    map[string]*OIDCClient
	Codes      map[string]*AuthCode // by code hash
}

func New() *Store {
	return &Store{
		Users: map[string]*User{}, EmailIndex: map[string]string{}, Consents: map[string]map[string]bool{},
		Sessions: map[string]*Session{}, Refresh: map[string]*RefreshToken{}, Devices: map[string]*Device{},
		Deliveries: map[DeliveryKey]*Delivery{}, Clients: map[string]*OIDCClient{}, Codes: map[string]*AuthCode{},
	}
}
