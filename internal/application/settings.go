package application

import (
	"Heimdall/internal/synchronization"
	"errors"
	"time"
)

type Settings struct {
	NodeCertificateTTLSeconds int   `json:"node_certificate_ttl_seconds"`
	CertificatePolicyVersion  int64 `json:"certificate_policy_version"`
	CertificatesTotal         int   `json:"certificates_total"`
	CertificatesPending       int   `json:"certificates_pending"`
	ApplyTimeoutSeconds       int   `json:"apply_timeout_seconds"`
	Version                   int64 `json:"version"`
	KeyWarnSeconds            int   `json:"key_warn_seconds"`
	KeyTTLSeconds             int   `json:"key_ttl_seconds"`
	RequireSK                 bool  `json:"require_sk"`
	StalledSeconds            int   `json:"stalled_seconds"`
	OfflineSeconds            int   `json:"offline_seconds"`
	RevocationAlertSeconds    int   `json:"revocation_alert_seconds"`
	SwaggerEnabled            bool  `json:"swagger_enabled"`
	MCPEnabled                bool  `json:"mcp_enabled"`
}

func (s Settings) Validate() error {
	if s.NodeCertificateTTLSeconds != 0 && (s.NodeCertificateTTLSeconds < 86400 || s.NodeCertificateTTLSeconds > synchronization.DefaultNodeCertificateTTLSeconds) {
		return errors.New("срок жизни сертификатов нод должен быть от 1 дня до 10 лет (3650 дней)")
	}
	if s.ApplyTimeoutSeconds != 0 && (s.ApplyTimeoutSeconds < 60 || s.ApplyTimeoutSeconds > 86400) {
		return errors.New("apply timeout must be 60–86400 seconds")
	}
	if s.KeyWarnSeconds < 0 || s.KeyWarnSeconds > 31536000 {
		return errors.New("key rotation notice window must be 0–31536000 seconds")
	}
	if s.KeyTTLSeconds < 60 || s.KeyTTLSeconds > 31536000 {
		return errors.New("SSH key TTL must be 60–31536000 seconds")
	}
	if s.StalledSeconds < 15 || s.StalledSeconds > 86400 || s.OfflineSeconds < 30 || s.OfflineSeconds > 86400 || s.RevocationAlertSeconds < 5 || s.RevocationAlertSeconds > 3600 {
		return errors.New("invalid synchronization timeout")
	}
	return nil
}

type UserGroup struct {
	MemberCount    int      `json:"member_count"`
	Purpose        string   `json:"purpose"`
	TOTPCount      int      `json:"totp_count"`
	PasskeyCount   int      `json:"passkey_count"`
	MissingFactors int      `json:"missing_factors"`
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	MFAPolicy      string   `json:"mfa_policy"`
	RequireSK      bool     `json:"require_sk"`
	Members        []string `json:"members"`
}
type InventoryHost struct {
	ID, Name, GroupID, GroupName, ParentID, Host, Login string
	Port                                                int
}
type FactorState struct {
	Required              []string `json:"required"`
	AdministratorRequired []string `json:"administrator_required"`
	PersonalPolicy        string   `json:"personal_policy"`
	TOTP                  bool     `json:"totp"`
	Passkey               bool     `json:"passkey"`
}

// Satisfied evaluates the intersection of enrollment requirements. Personal
// requirements add to the administrator's minimum; they never replace it.
func (s FactorState) Satisfied(totp, passkey bool) bool {
	for _, policy := range s.Required {
		switch policy {
		case "none":
		case "any":
			if !totp && !passkey {
				return false
			}
		case "totp":
			if !totp {
				return false
			}
		case "passkey":
			if !passkey {
				return false
			}
		case "both":
			if !totp || !passkey {
				return false
			}
		default:
			return false
		}
	}
	return true
}

type UnixGroup struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	GID            int      `json:"gid"`
	Members        []string `json:"members"`
	PrimaryMembers []string `json:"primary_members"`
}
type UnixAssignment struct {
	ID          string `json:"id"`
	UnixGroupID string `json:"unix_group_id"`
	RoleID      string `json:"role_id"`
	GroupID     string `json:"group_id"`
}
type JoinToken struct {
	Name      string     `json:"name"`
	ID        string     `json:"id"`
	GroupID   string     `json:"group_id"`
	Uses      int        `json:"uses"`
	MaxUses   int        `json:"max_uses"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at"`
}

type Announcement struct {
	ID       string     `json:"id"`
	Title    string     `json:"title"`
	Markdown string     `json:"markdown"`
	Severity string     `json:"severity"`
	Enabled  bool       `json:"enabled"`
	StartsAt time.Time  `json:"starts_at"`
	EndsAt   *time.Time `json:"ends_at"`
	Version  int64      `json:"version"`
}
