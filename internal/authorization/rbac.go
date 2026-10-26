package authorization

import (
	"errors"
	"regexp"
	"slices"
	"strings"
)

var Permissions = []string{"users.read", "users.manage", "roles.read", "roles.manage", "nodes.read", "nodes.manage", "sync.read", "sync.retry", "sudo.manage", "tokens.manage", "integrations.manage", "incidents.read", "incidents.manage", "audit.read", "api_docs.read", "inventory.read", "settings.manage", "security.read", "announcements.manage", "security.manage", "documentation.manage", "documentation.read"}
var commandPattern = regexp.MustCompile(`^/[a-zA-Z0-9_./-]+$`)
var argumentPattern = regexp.MustCompile(`^[a-zA-Z0-9_./:@=-]+$`)

type SudoRule struct {
	Command    string   `json:"command"`
	Arguments  []string `json:"arguments"`
	RunAs      string   `json:"run_as"`
	NoPassword bool     `json:"no_password"`
}
type Role struct {
	AllowPassword bool       `json:"allow_password"`
	AllowSSHKeys  bool       `json:"allow_ssh_keys"`
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Permissions   []string   `json:"permissions"`
	LinuxAccess   bool       `json:"linux_access"`
	Sudo          []SudoRule `json:"sudo"`
	Sudoers       string     `json:"sudoers"`
}

// Normalize keeps collection fields non-null at API and persistence boundaries.
func (r *Role) Normalize() {
	if r.Permissions == nil {
		r.Permissions = []string{}
	}
	if r.Sudo == nil {
		r.Sudo = []SudoRule{}
	}
	for i := range r.Sudo {
		if r.Sudo[i].Arguments == nil {
			r.Sudo[i].Arguments = []string{}
		}
	}
}

type Binding struct {
	ID      string `json:"id"`
	UserID  string `json:"user_id"`
	RoleID  string `json:"role_id"`
	GroupID string `json:"group_id"`
	Role    Role   `json:"role"`
}
type Principal struct {
	UserID      string    `json:"user_id"`
	Login       string    `json:"login"`
	TokenID     string    `json:"token_id,omitempty"`
	Bindings    []Binding `json:"bindings"`
	TokenScopes []string  `json:"-"`
	TokenGroups []string  `json:"-"`
	Restricted  bool      `json:"restricted"`
	AuthVersion int64     `json:"-"`
	Audience    string    `json:"-"`
	index       map[string]map[string]struct{}
	scopes      map[string]struct{}
	groups      map[string]struct{}
}

func (p *Principal) Prepare() {
	p.index = map[string]map[string]struct{}{}
	p.scopes = map[string]struct{}{}
	p.groups = map[string]struct{}{}
	for _, v := range p.TokenScopes {
		p.scopes[v] = struct{}{}
	}
	for _, v := range p.TokenGroups {
		p.groups[v] = struct{}{}
	}
	for _, b := range p.Bindings {
		for _, permission := range b.Role.Permissions {
			if p.index[permission] == nil {
				p.index[permission] = map[string]struct{}{}
			}
			p.index[permission][b.GroupID] = struct{}{}
		}
	}
}
func (p Principal) indexed(permission, group string) bool {
	for _, action := range []string{permission, "*"} {
		for _, scope := range []string{group, "*"} {
			if _, ok := p.index[action][scope]; ok {
				return true
			}
		}
	}
	return false
}

func (p Principal) Allowed(permission, group string) bool {
	if p.Restricted {
		return false
	}
	if p.index != nil {
		if p.TokenID != "" {
			_, scope := p.scopes[permission]
			_, all := p.scopes["*"]
			if !scope && !all {
				return false
			}
			if len(p.TokenGroups) > 0 {
				_, scope = p.groups[group]
				_, all = p.groups["*"]
				if !scope && !all {
					return false
				}
			}
		}
		return p.indexed(permission, group)
	}
	if p.TokenID != "" && !slices.Contains(p.TokenScopes, permission) && !slices.Contains(p.TokenScopes, "*") {
		return false
	}
	if p.TokenID != "" && len(p.TokenGroups) > 0 && !slices.Contains(p.TokenGroups, "*") && !slices.Contains(p.TokenGroups, group) {
		return false
	}
	for _, b := range p.Bindings {
		if b.GroupID != "*" && b.GroupID != group {
			continue
		}
		if slices.Contains(b.Role.Permissions, permission) || slices.Contains(b.Role.Permissions, "*") {
			return true
		}
	}
	return false
}
func (p Principal) Self(userID string) bool {
	return p.UserID == userID && !p.Restricted && (p.TokenID == "" || slices.Contains(p.TokenScopes, "self") || slices.Contains(p.TokenScopes, "*"))
}
func (r Role) Validate() error {
	if strings.TrimSpace(r.Name) == "" || len(r.Name) > 100 {
		return errors.New("invalid role name")
	}
	for _, permission := range r.Permissions {
		if permission != "*" && !slices.Contains(Permissions, permission) {
			return errors.New("unknown permission")
		}
	}
	if (r.AllowPassword || r.AllowSSHKeys) && !r.LinuxAccess {
		return errors.New("node login methods require UNIX access")
	}
	if (len(r.Sudo) > 0 || r.Sudoers != "") && !r.LinuxAccess {
		return errors.New("sudo requires Linux access")
	}
	if err := ValidateSudoers(r.Sudoers); err != nil {
		return err
	}
	for _, rule := range r.Sudo {
		if !commandPattern.MatchString(rule.Command) || strings.Contains(rule.Command, "..") {
			return errors.New("sudo requires an absolute command without patterns")
		}
		if rule.RunAs != "root" {
			return errors.New("only explicit root RunAs is supported")
		}
		for _, arg := range rule.Arguments {
			if !argumentPattern.MatchString(arg) {
				return errors.New("sudo arguments must be literal safe arguments")
			}
		}
	}
	return nil
}

// Each line is the native sudoers User_Spec right-hand side. The trusted
// account name is supplied by the agent so role scope cannot escape to ALL
// users. Grammar is checked by visudo, not a replacement sudo language.
func ValidateSudoers(text string) error {
	if len(text) > 32768 || strings.ContainsAny(text, "\x00\r") {
		return errors.New("invalid sudoers size or control characters")
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "@") || strings.HasSuffix(line, "\\") {
			return errors.New("use one native sudoers User_Spec per line, after the account name")
		}
	}
	return nil
}
