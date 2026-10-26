package synchronization

import (
	"Heimdall/internal/authorization"
	"Heimdall/internal/credentials"
	"Heimdall/internal/identity"
	"time"
)

type Account struct {
	AllowPassword bool                        `json:"allow_password"`
	AllowSSHKeys  bool                        `json:"allow_ssh_keys"`
	Clearance     authorization.SecurityLabel `json:"clearance"`
	User          identity.User               `json:"user"`
	Enabled       bool                        `json:"enabled"`
	PasswordHash  string                      `json:"password_hash,omitempty"`
	Keys          []credentials.Key           `json:"keys"`
	Sudo          []authorization.SudoRule    `json:"sudo"`
	Sudoers       []string                    `json:"sudoers,omitempty"`
	Groups        []string                    `json:"groups,omitempty"`
}
type Snapshot struct {
	CertificatePolicy  CertificatePolicy           `json:"certificate_policy,omitempty"`
	Label              authorization.SecurityLabel `json:"label"`
	BootstrapNonce     string                      `json:"bootstrap_nonce,omitempty"`
	BootstrapTokenHash string                      `json:"bootstrap_token_hash,omitempty"`
	Full               bool                        `json:"full"`
	BaseRevision       int64                       `json:"base_revision"`
	Schema             int                         `json:"schema"`
	Epoch              string                      `json:"epoch"`
	NodeID             string                      `json:"node_id"`
	Revision           int64                       `json:"revision"`
	IssuedAt           time.Time                   `json:"issued_at"`
	Accounts           []Account                   `json:"accounts"`
	Groups             []UnixGroup                 `json:"groups,omitempty"`
}
type SignedState struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
	Digest    string `json:"digest"`
}
type ResourceResult struct {
	UserID string `json:"user_id"`
	Login  string `json:"login"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}
type ApplyResult struct {
	Revision int64            `json:"revision"`
	Digest   string           `json:"digest"`
	Results  []ResourceResult `json:"results"`
	Error    string           `json:"error,omitempty"`
	Duration float64          `json:"duration"`
}
type AgentHealth struct {
	Hostname  string    `json:"hostname"`
	Addresses []string  `json:"addresses"`
	Platform  string    `json:"platform"`
	NodeID    string    `json:"node_id"`
	Error     string    `json:"error"`
	CheckedAt time.Time `json:"checked_at"`
}
type ConnectionIdentity struct {
	Generation int64
	Serial     string
	Expires    time.Time
}
type Operation struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"`
	ResourceID string    `json:"resource_id"`
	Revision   int64     `json:"revision"`
	Status     string    `json:"status"`
	Total      int       `json:"total"`
	Applied    int       `json:"applied"`
	Failed     int       `json:"failed"`
	CreatedAt  time.Time `json:"created_at"`
}
type Incident struct {
	Occurrences int64     `json:"occurrences"`
	LastSeen    time.Time `json:"last_seen"`
	ID          string    `json:"id"`
	Kind        string    `json:"kind"`
	Severity    string    `json:"severity"`
	NodeID      string    `json:"node_id,omitempty"`
	GroupID     string    `json:"group_id,omitempty"`
	UserID      string    `json:"user_id,omitempty"`
	Message     string    `json:"message"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}

type UnixGroup struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	GID  int    `json:"gid"`
}
