package fleet

import "time"

type Group struct {
	Nodes       int    `json:"nodes"`
	ActiveNodes int    `json:"active_nodes"`
	ID          string `json:"id"`
	Name        string `json:"name"`
	ParentID    string `json:"parent_id"`
}
type Node struct {
	CertificateStatus string     `json:"certificate_status"`
	Health            string     `json:"health"`
	Hostname          string     `json:"hostname"`
	Addresses         []string   `json:"addresses"`
	Platform          string     `json:"platform"`
	MetadataSeen      *time.Time `json:"metadata_seen"`
	ID                string     `json:"id"`
	Name              string     `json:"name"`
	GroupID           string     `json:"group_id"`
	GroupName         string     `json:"group_name"`
	DesiredRevision   int64      `json:"desired_revision"`
	AppliedRevision   int64      `json:"applied_revision"`
	Status            string     `json:"status"`
	Connectivity      string     `json:"connectivity"`
	Error             string     `json:"error"`
	LastSeen          *time.Time `json:"last_seen"`
	LastProgress      time.Time  `json:"last_progress"`
	PendingSince      time.Time  `json:"pending_since"`
	CertExpires       *time.Time `json:"cert_expires"`
	Disabled          bool       `json:"disabled"`
	SSHHost           string     `json:"ssh_host"`
	SSHPort           int        `json:"ssh_port"`
}
