// Acceptance-only helper. It is not included in the control plane image and
// exposes no HTTP endpoint. Password input and hash output are piped privately.
package main

import (
	"Heimdall/internal/platform/security"
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	var in struct {
		Password string `json:"password"`
	}
	if json.NewDecoder(os.Stdin).Decode(&in) != nil {
		os.Exit(2)
	}
	hash, err := security.PasswordHash(in.Password)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fixture hash failed")
		os.Exit(1)
	}
	json.NewEncoder(os.Stdout).Encode(map[string]string{"hash": hash})
}
