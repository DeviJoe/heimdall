package application

import (
	"Heimdall/internal/authorization"
	"Heimdall/internal/identity"
	"errors"
	"time"
)

var ErrForbidden = errors.New("access denied")
var ErrConflict = errors.New("resource changed; reload before saving")
var ErrNotFound = errors.New("resource not found")

type AuthRecord struct {
	User         identity.User
	PasswordHash string
	TOTPSecret   string
	LastTOTPStep int64
}
type Token struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	Name      string     `json:"name"`
	Audiences []string   `json:"audiences"`
	Scopes    []string   `json:"scopes"`
	Groups    []string   `json:"groups"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at"`
	LastUsed  *time.Time `json:"last_used"`
}
type NotificationJob struct {
	ID, UserID, Provider, ChatID, Subject, Kind, Severity, GroupID, IncidentUserID, Message, Status string
	Attempts                                                                                        int
}
type DirectoryUser struct{ Subject, Login, DisplayName string }
type MetricState struct {
	CertificatesPending int
	CertificatesOldest  float64
	Connectivity        map[string]int
	Directories         map[string]DirectoryStatus
	Nodes               map[string]int
	Pending             int
	Revocations         int
	Oldest              float64
	OutboxOldest        float64
	NotificationOldest  float64
	Incidents           int
}
type DirectoryStatus struct {
	Phase                    string
	LastAttempt, LastSuccess *time.Time
}

type LabelPolicy struct {
	ResourceType string                      `json:"resource_type"`
	ResourceID   string                      `json:"resource_id"`
	Label        authorization.SecurityLabel `json:"label"`
}

type Passkey struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	CreatedAt *time.Time `json:"created_at"`
	LastUsed  *time.Time `json:"last_used"`
}
