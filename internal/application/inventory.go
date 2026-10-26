package application

import "strings"

type InventoryGroup struct {
	Hosts    []string       `json:"hosts"`
	Children []string       `json:"children"`
	Vars     map[string]any `json:"vars,omitempty"`
}

func inventoryID(prefix, id string) string { return prefix + strings.ReplaceAll(id, "-", "") }
func BuildInventory(hosts []InventoryHost) map[string]any {
	hostvars := map[string]any{}
	groups := map[string]*InventoryGroup{}
	out := map[string]any{"_meta": map[string]any{"hostvars": hostvars}}
	all := InventoryGroup{Hosts: []string{}, Children: []string{}}
	for _, host := range hosts {
		name := inventoryID("n_", host.ID)
		group := inventoryID("g_", host.GroupID)
		hostvars[name] = map[string]any{"ansible_host": host.Host, "ansible_port": host.Port, "ansible_user": host.Login, "heimdall_node_id": host.ID, "heimdall_node_name": host.Name, "heimdall_group_id": host.GroupID}
		if groups[group] == nil {
			groups[group] = &InventoryGroup{Hosts: []string{}, Children: []string{}, Vars: map[string]any{"heimdall_group_name": host.GroupName}}
		}
		groups[group].Hosts = append(groups[group].Hosts, name)
	}
	parents := map[string]string{}
	for _, host := range hosts {
		group := inventoryID("g_", host.GroupID)
		parent := inventoryID("g_", host.ParentID)
		if groups[parent] != nil && parent != group {
			parents[group] = parent
		}
	}
	// Stable ordering follows the ordered input, without exposing inaccessible ancestors.
	seen := map[string]bool{}
	for _, host := range hosts {
		group := inventoryID("g_", host.GroupID)
		if seen[group] {
			continue
		}
		seen[group] = true
		if parent := parents[group]; parent != "" {
			groups[parent].Children = append(groups[parent].Children, group)
		} else {
			all.Children = append(all.Children, group)
		}
		out[group] = groups[group]
	}
	out["all"] = all
	out["ungrouped"] = InventoryGroup{Hosts: []string{}, Children: []string{}}
	return out
}
