package application

import "testing"

func TestFactorRequirementsComposeWithoutWeakeningTheMinimum(t *testing.T) {
	for _, tc := range []struct {
		name     string
		policies []string
		// No factors, TOTP only, passkey only, both.
		allowed [4]bool
	}{
		{"optional", nil, [4]bool{true, true, true, true}},
		{"either factor", []string{"any"}, [4]bool{false, true, true, true}},
		{"TOTP minimum and optional personal", []string{"totp", "none"}, [4]bool{false, true, false, true}},
		{"passkey minimum and weaker personal", []string{"passkey", "any"}, [4]bool{false, false, true, true}},
		{"both minimum and weaker personal", []string{"both", "any"}, [4]bool{false, false, false, true}},
		{"direct TOTP and group passkey", []string{"totp", "passkey"}, [4]bool{false, false, false, true}},
		{"either minimum and personal both", []string{"any", "both"}, [4]bool{false, false, false, true}},
		{"unknown requirement fails closed", []string{"invalid"}, [4]bool{false, false, false, false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := FactorState{Required: tc.policies}
			for i, factors := range [][2]bool{{false, false}, {true, false}, {false, true}, {true, true}} {
				if state.Satisfied(factors[0], factors[1]) != tc.allowed[i] {
					t.Fatalf("TOTP=%v passkey=%v: incorrect minimum", factors[0], factors[1])
				}
			}
		})
	}
}
