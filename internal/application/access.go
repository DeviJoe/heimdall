package application

import "Heimdall/internal/authorization"

// AccessibleNode contains native connection details, independent of fleet
// administration permissions and internal synchronization counters.
type AccessibleNode struct {
	Health       string       `json:"health"`
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	Hostname     string       `json:"hostname"`
	Addresses    []string     `json:"addresses"`
	Platform     string       `json:"platform"`
	GroupName    string       `json:"group_name"`
	Host         string       `json:"host"`
	Port         int          `json:"port"`
	Login        string       `json:"login"`
	AccessStatus string       `json:"access_status"`
	Roles        []AccessRole `json:"roles"`
}

type AccessRole struct {
	AllowPassword bool                     `json:"allow_password"`
	AllowSSHKeys  bool                     `json:"allow_ssh_keys"`
	Name          string                   `json:"name"`
	Sudoers       string                   `json:"sudoers"`
	Sudo          []authorization.SudoRule `json:"sudo"`
}

// NativeAccessPolicy is the union of explicitly assigned native roles.
type NativeAccessPolicy struct {
	SyncToNodes   bool `json:"sync_to_nodes"`
	AllowPassword bool `json:"allow_password"`
	AllowSSHKeys  bool `json:"allow_ssh_keys"`
}
