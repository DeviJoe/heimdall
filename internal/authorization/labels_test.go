package authorization

import "testing"

func TestMandatoryClearance(t *testing.T) {
	required := SecurityLabel{Level: 2, Categories: []string{"production", "finance"}}
	for _, tc := range []struct {
		label SecurityLabel
		ok    bool
	}{{SecurityLabel{Level: 3, Categories: []string{"finance", "production", "audit"}}, true}, {SecurityLabel{Level: 1, Categories: []string{"finance", "production"}}, false}, {SecurityLabel{Level: 3, Categories: []string{"production"}}, false}, {SecurityLabel{Level: 4, Categories: []string{"finance", "production"}}, false}} {
		if tc.label.Dominates(required) != tc.ok {
			t.Fatalf("unexpected mandatory decision %+v", tc)
		}
	}
}
func TestNativeSudoersSpec(t *testing.T) {
	for _, text := range []string{"ALL=(ALL:ALL) NOPASSWD: /usr/bin/systemctl restart nginx, /usr/bin/journalctl *", "ALL=(operator) SETENV: /usr/bin/env ^[a-z]+$"} {
		if err := ValidateSudoers(text); err != nil {
			t.Fatal(err)
		}
	}
	for _, text := range []string{"@include /tmp/unsafe", "#include /tmp/unsafe", "ALL=(root) /bin/sh\\", "ALL=(root) /usr/bin/id\x00"} {
		if ValidateSudoers(text) == nil {
			t.Fatal("unsafe User_Spec accepted")
		}
	}
}
