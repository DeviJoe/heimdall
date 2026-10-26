package application

import (
	"encoding/json"
	"testing"
)

func TestInventoryGroupsAndHostvars(t *testing.T) {
	hosts := []InventoryHost{{ID: "a-1", GroupID: "b-1", GroupName: "parent", Host: "node1.internal", Port: 22, Login: "automation"}, {ID: "a-2", GroupID: "b-2", GroupName: "child", ParentID: "b-1", Host: "10.0.0.2", Port: 2222, Login: "automation"}}
	inventory := BuildInventory(hosts)
	parent := inventory["g_b1"].(*InventoryGroup)
	if len(parent.Children) != 1 || parent.Children[0] != "g_b2" {
		t.Fatal("group hierarchy lost")
	}
	raw, err := json.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err = json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed["_meta"] == nil || parsed["all"] == nil {
		t.Fatal("Ansible inventory contract missing")
	}
	empty := BuildInventory(nil)
	if len(empty["_meta"].(map[string]any)["hostvars"].(map[string]any)) != 0 {
		t.Fatal("empty inventory exposed hosts")
	}
}
func TestInventoryDoesNotExposeHiddenParent(t *testing.T) {
	inventory := BuildInventory([]InventoryHost{{ID: "a", GroupID: "child", ParentID: "hidden", Host: "node.internal", Port: 22}})
	if _, exists := inventory["g_hidden"]; exists {
		t.Fatal("hidden group leaked")
	}
	if inventory["all"].(InventoryGroup).Children[0] != "g_child" {
		t.Fatal("accessible group not rooted")
	}
}
