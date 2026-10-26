package identity

import (
	"errors"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var loginPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,30}$`)

type User struct {
	SyncToNodes  bool      `json:"sync_to_nodes"`
	UnixMember   bool      `json:"unix_member,omitempty"`
	UnixPrimary  bool      `json:"unix_primary,omitempty"`
	TOTPEnabled  bool      `json:"totp_enabled"`
	PasskeyCount int       `json:"passkey_count"`
	RequireSK    bool      `json:"require_sk"`
	Kind         string    `json:"kind"`
	MFAPolicy    string    `json:"mfa_policy"`
	ID           string    `json:"id"`
	Login        string    `json:"login"`
	DisplayName  string    `json:"display_name"`
	Status       string    `json:"status"`
	UID          int       `json:"uid"`
	GID          int       `json:"gid"`
	Home         string    `json:"home"`
	Shell        string    `json:"shell"`
	GECOS        string    `json:"gecos"`
	RequireMFA   bool      `json:"require_mfa"`
	MFAEnabled   bool      `json:"mfa_enabled"`
	AuthVersion  int64     `json:"auth_version"`
	Source       string    `json:"source"`
	CreatedAt    time.Time `json:"created_at"`
}

func (u User) Validate() error {
	if !loginPattern.MatchString(u.Login) || u.Login == "root" {
		return errors.New("invalid or protected login")
	}
	if u.UID < 10000 || u.UID > 2147483646 || u.GID < 10000 || u.GID > 2147483646 {
		return errors.New("UID and GID must be in the managed range")
	}
	if (filepath.Dir(u.Home) != "/home" && filepath.Dir(u.Home) != "/usr/home") || filepath.Clean(u.Home) != u.Home || strings.ContainsAny(u.Home, "\n\r\x00:") {
		return errors.New("home must be a clean path below /home or /usr/home")
	}
	allowed := map[string]bool{"/bin/bash": true, "/usr/local/bin/bash": true, "/bin/sh": true, "/usr/sbin/nologin": true}
	if !allowed[u.Shell] {
		return errors.New("unsupported shell")
	}
	if strings.ContainsAny(u.GECOS, "\n\r\x00:") || len(u.GECOS) > 256 {
		return errors.New("invalid GECOS")
	}
	if len(u.DisplayName) > 200 {
		return errors.New("display name too long")
	}
	return nil
}

func (u User) Active() bool { return u.Status == "active" }

// ValidateGroup applies the same POSIX namespace and managed range as users.
func ValidateGroup(name string, gid int) error {
	if !loginPattern.MatchString(name) || name == "root" || name == "wheel" || gid < 10000 || gid > 2147483646 {
		return errors.New("invalid or protected UNIX group name/GID")
	}
	return nil
}
