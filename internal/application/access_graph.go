package application

import (
	"Heimdall/internal/authorization"
	"encoding/json"
	"slices"
	"strings"
)

type AccessConnection struct {
	ID          string             `json:"id"`
	SubjectID   string             `json:"subject_id"`
	SubjectName string             `json:"subject_name"`
	SubjectKind string             `json:"subject_kind"`
	GroupID     string             `json:"group_id"`
	GroupName   string             `json:"group_name"`
	Ancestors   []string           `json:"ancestors"`
	Role        authorization.Role `json:"role"`
}
type AccessRecommendation struct {
	Kind        string   `json:"kind"`
	Connections []string `json:"connections"`
	Message     string   `json:"message"`
	Common      []string `json:"common"`
}
type AccessGraph struct {
	Connections     []AccessConnection     `json:"connections"`
	Recommendations []AccessRecommendation `json:"recommendations"`
}

func sharedRights(a, b authorization.Role) []string {
	common := []string{}
	for _, p := range a.Permissions {
		if p == "*" {
			common = append(common, b.Permissions...)
			continue
		}
		if slices.Contains(b.Permissions, p) || slices.Contains(b.Permissions, "*") {
			common = append(common, p)
		}
	}
	if a.LinuxAccess && b.LinuxAccess {
		if a.AllowSSHKeys && b.AllowSSHKeys {
			common = append(common, "unix.ssh_keys")
		}
		if a.AllowPassword && b.AllowPassword {
			common = append(common, "unix.password")
		}
	}
	slices.Sort(common)
	return slices.Compact(common)
}
func roleSignature(r authorization.Role) string {
	r.Permissions = slices.Clone(r.Permissions)
	r.Sudo = slices.Clone(r.Sudo)
	r.ID = ""
	r.Name = ""
	r.Normalize()
	slices.Sort(r.Permissions)
	r.Permissions = slices.Compact(r.Permissions)
	r.Sudoers = strings.TrimSpace(r.Sudoers)
	data, _ := json.Marshal(r)
	return string(data)
}

// Analysis is bounded to one graph page. It never guesses arbitrary sudoers
// command-pattern intersections or treats a role shared by scopes as a grant.
func AccessRecommendations(connections []AccessConnection) []AccessRecommendation {
	out := []AccessRecommendation{}
	seen := map[string]bool{}
	for i, a := range connections {
		for _, b := range connections[i+1:] {
			if a.Role.ID == b.Role.ID {
				continue
			}
			effectiveA, effectiveB := a.Role, b.Role
			if a.SubjectKind == "unix_group" {
				effectiveA.Permissions = []string{}
			}
			if b.SubjectKind == "unix_group" {
				effectiveB.Permissions = []string{}
			}
			common := sharedRights(effectiveA, effectiveB)
			if len(common) == 0 {
				continue
			}
			sameSubject := a.SubjectKind == b.SubjectKind && a.SubjectID == b.SubjectID
			scopesIntersect := a.GroupID == "*" || b.GroupID == "*" || a.GroupID == b.GroupID || slices.Contains(a.Ancestors, b.GroupID) || slices.Contains(b.Ancestors, a.GroupID)
			kind, message := "overlap", "На пересекающейся области нод один субъект получает общие разрешения через несколько ролей. Проверьте, нужны ли оба назначения."
			if roleSignature(a.Role) == roleSignature(b.Role) {
				kind = "duplicate_role"
				message = "Роли имеют одинаковые разрешения и способы входа. Рассмотрите одну общую роль; назначения и область действия меняйте отдельно."
			} else if !sameSubject || !scopesIntersect {
				continue
			}
			ids := []string{a.Role.ID, b.Role.ID}
			slices.Sort(ids)
			key := kind + strings.Join(ids, ":")
			if kind == "overlap" {
				key += a.SubjectKind + a.SubjectID + a.GroupID + b.GroupID
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, AccessRecommendation{kind, []string{a.ID, b.ID}, message, common})
			if len(out) == 100 {
				return out
			}
		}
	}
	return out
}
