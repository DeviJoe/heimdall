package application

import (
	"Heimdall/internal/authorization"
	"Heimdall/internal/credentials"
	"Heimdall/internal/fleet"
	"Heimdall/internal/identity"
	"Heimdall/internal/knowledge"
	"Heimdall/internal/synchronization"
	"context"
	"encoding/json"
	"time"
)

// ControlPlane is the application contract shared by REST and MCP. Transactional
// authorization and synchronization outbox writes are implemented by its adapter.
type ControlPlane interface {
	AccessGraph(context.Context, authorization.Principal, PageQuery) (AccessGraph, string, error)
	CreateNamedJoinToken(context.Context, authorization.Principal, string, string, int, time.Duration) (string, error)
	FilteredNodesPage(context.Context, authorization.Principal, time.Duration, int, string, string, string, string, string) ([]fleet.Node, string, error)
	FilteredUsersPage(context.Context, authorization.Principal, int, string, string, string, string, string, string, string) ([]identity.User, string, error)
	DocumentationPages(context.Context, authorization.Principal, int, string, string) ([]knowledge.Page, string, error)
	DocumentationPage(context.Context, authorization.Principal, string) (knowledge.Page, error)
	SaveDocumentation(context.Context, authorization.Principal, knowledge.Page) (string, error)
	NativeAccessPolicy(context.Context, authorization.Principal, string) (NativeAccessPolicy, error)
	RotateTOTP(context.Context, string, int64, string, []string) error
	AccessibleNodesPage(context.Context, authorization.Principal, string, int, string, string) ([]AccessibleNode, string, error)
	QueryUnixUsersPage(context.Context, authorization.Principal, int, string, string, string, bool) ([]identity.User, string, error)
	UnixGroup(context.Context, authorization.Principal, string) (UnixGroup, error)
	UpdateUnixMembers(context.Context, authorization.Principal, string, []string, []string) (string, error)
	UpdateJoinToken(context.Context, authorization.Principal, string, int, time.Time) error
	RemovePeople(context.Context, authorization.Principal, string, []string) (string, error)
	ReadPage(context.Context, authorization.Principal, string, PageQuery) (Page, error)
	QueryUsersPage(context.Context, authorization.Principal, int, string, string, string, string, string) ([]identity.User, string, error)
	QueryNodesPage(context.Context, authorization.Principal, time.Duration, int, string, string, string) ([]fleet.Node, string, error)
	DeleteGroup(context.Context, authorization.Principal, string) (string, error)
	DeleteUserGroup(context.Context, authorization.Principal, string) (string, error)
	DeleteUnixGroup(context.Context, authorization.Principal, string) (string, error)
	ResolveIncidents(context.Context, authorization.Principal, []string) error

	Passkeys(context.Context, authorization.Principal, string) ([]Passkey, error)
	RenamePasskey(context.Context, authorization.Principal, string, string, string) error
	RemoveFactor(context.Context, authorization.Principal, string, string) (string, error)
	DeleteRole(context.Context, authorization.Principal, string) (string, error)
	MovePeople(context.Context, authorization.Principal, string, string, []string) (string, error)

	LabelPolicies(context.Context, authorization.Principal) ([]LabelPolicy, error)
	SaveLabelPolicy(context.Context, authorization.Principal, LabelPolicy) (string, error)
	Announcements(context.Context, authorization.Principal, bool) ([]Announcement, error)
	SaveAnnouncement(context.Context, authorization.Principal, Announcement) (string, error)
	DeleteAnnouncement(context.Context, authorization.Principal, string, int64) (string, error)
	UnixGroups(context.Context, authorization.Principal) ([]UnixGroup, error)
	SaveUnixGroup(context.Context, authorization.Principal, UnixGroup) (string, error)
	UnixAssignments(context.Context, authorization.Principal) ([]UnixAssignment, error)
	AssignUnixGroup(context.Context, authorization.Principal, UnixAssignment) (string, error)
	UnassignUnixGroup(context.Context, authorization.Principal, string) (string, error)
	JoinTokens(context.Context, authorization.Principal) ([]JoinToken, error)
	RevokeJoinToken(context.Context, authorization.Principal, string) error
	RequireSK(context.Context, string) (bool, error)

	ResolveActivityIncident(context.Context, authorization.Principal, string) error
	UserGroupBindings(context.Context, authorization.Principal, string) ([]authorization.Binding, error)
	UnbindUserGroupRole(context.Context, authorization.Principal, string, string) (string, error)
	FilterUsersPage(context.Context, authorization.Principal, int, string, string, string) ([]identity.User, string, error)
	EnrollBound(context.Context, string, string, string, time.Time, string, string) (string, error)
	FactorState(context.Context, string) (FactorState, error)
	SetPersonalFactorPolicy(context.Context, authorization.Principal, string) (string, error)
	SecurityEvents(context.Context, authorization.Principal) ([]synchronization.ActivityEvent, error)
	NodesInGroupPage(context.Context, authorization.Principal, time.Duration, int, string, string) ([]fleet.Node, string, error)
	SearchUsersPage(context.Context, authorization.Principal, int, string, string) ([]identity.User, string, error)
	Settings(context.Context) (Settings, error)
	SaveSettings(context.Context, authorization.Principal, Settings) (string, error)
	Inventory(context.Context, authorization.Principal) ([]InventoryHost, error)
	SetNodeSSH(context.Context, authorization.Principal, string, string, int) error
	SaveGroup(context.Context, authorization.Principal, fleet.Group) (string, error)
	MoveNodes(context.Context, authorization.Principal, []string, string) (string, error)
	UserGroups(context.Context, authorization.Principal) ([]UserGroup, error)
	SaveUserGroup(context.Context, authorization.Principal, UserGroup) (string, error)
	BindUserGroupRole(context.Context, authorization.Principal, string, authorization.Binding) (string, error)
	SetMFAPolicy(context.Context, authorization.Principal, string, string) (string, error)
	AcceptInvite(ctx context.Context, token, hash string) (identity.User, error)
	Acknowledge(ctx context.Context, p authorization.Principal, id string) error
	AddKey(ctx context.Context, p authorization.Principal, k credentials.Key) (credentials.Key, string, error)
	AuditEvents(ctx context.Context, p authorization.Principal) ([]map[string]any, error)
	Auth(ctx context.Context, login string) (AuthRecord, error)
	Bearer(ctx context.Context, secret, audience string) (authorization.Principal, error)
	BindRole(ctx context.Context, p authorization.Principal, b authorization.Binding) (string, error)
	Bindings(ctx context.Context, p authorization.Principal, userID string) ([]authorization.Binding, error)
	CreateGroup(ctx context.Context, p authorization.Principal, name string) (fleet.Group, error)
	CreateJoinToken(ctx context.Context, p authorization.Principal, groupID string, maxUses int, ttl time.Duration) (string, error)
	CreateRecoveryToken(ctx context.Context, p authorization.Principal, nodeID string) (string, error)
	CreateToken(ctx context.Context, p authorization.Principal, t Token) (Token, string, error)
	CreateUser(ctx context.Context, p authorization.Principal, u identity.User, inviteHash string) (identity.User, string, error)
	EnableTOTP(ctx context.Context, id, secret string, recovery []string) error
	EnableWebAuthn(ctx context.Context, id, keyID string, credential []byte, recovery []string) error
	ConsumeRecoveryCode(ctx context.Context, id, code string) bool
	Enroll(ctx context.Context, token, name, serial string, expires time.Time, nodeID string) (string, error)
	FleetSummary(ctx context.Context, p authorization.Principal, offline time.Duration) (map[string]int, error)
	Groups(ctx context.Context, p authorization.Principal) ([]fleet.Group, error)
	Health(ctx context.Context) error
	IdentityUser(ctx context.Context, provider, subject string) (identity.User, error)
	IntegrationStatuses(ctx context.Context, p authorization.Principal) ([]map[string]any, error)
	Incidents(ctx context.Context, p authorization.Principal) ([]synchronization.Incident, error)
	Keys(ctx context.Context, p authorization.Principal, id string) ([]credentials.Key, error)
	LinkIdentity(ctx context.Context, p authorization.Principal, provider, subject, userID string) error
	LinkNotification(ctx context.Context, userID, provider, subject, chatID string) error
	NodesPage(ctx context.Context, p authorization.Principal, offline time.Duration, limit int, after string) ([]fleet.Node, string, error)
	Notifications(ctx context.Context, p authorization.Principal) ([]map[string]any, error)
	OperationTargetsPage(ctx context.Context, p authorization.Principal, id string, limit int, after string) ([]map[string]any, string, error)
	Operations(ctx context.Context, p authorization.Principal) ([]synchronization.Operation, error)
	Principal(ctx context.Context, userID, tokenID, audience string) (authorization.Principal, error)
	ProvisionOIDC(ctx context.Context, issuer, subject, login, name string, mfa bool) (identity.User, error)
	RecoverNode(ctx context.Context, nodeID, token, serial string, expires time.Time) error
	RetryNode(ctx context.Context, p authorization.Principal, id string) (string, error)
	RevokeKey(ctx context.Context, p authorization.Principal, id string) (string, error)
	RevokeToken(ctx context.Context, p authorization.Principal, id string) error
	Roles(ctx context.Context) ([]authorization.Role, error)
	SaveRole(ctx context.Context, p authorization.Principal, r authorization.Role) (string, error)
	SaveWebAuthnCredential(ctx context.Context, userID, id string, credential []byte) error
	SetLinuxPassword(ctx context.Context, p authorization.Principal, id, hash string) (string, error)
	SetNode(ctx context.Context, p authorization.Principal, id, groupID string, disabled bool) (string, error)
	SetUserStatus(ctx context.Context, p authorization.Principal, id, status string) (string, error)
	TelegramPrincipal(ctx context.Context, subject string) (authorization.Principal, error)
	TelegramUpdate(ctx context.Context, id int64) (bool, error)
	Tokens(ctx context.Context, p authorization.Principal) ([]Token, error)
	UnbindRole(ctx context.Context, p authorization.Principal, id string) (string, error)
	UnlinkNotification(ctx context.Context, p authorization.Principal, id string) error
	UpdateUser(ctx context.Context, p authorization.Principal, u identity.User, maintenance bool) (string, error)
	UseTOTP(ctx context.Context, id string, step int64) bool
	User(ctx context.Context, id string) (identity.User, error)
	UserSyncPage(ctx context.Context, p authorization.Principal, id string, limit int, after string) ([]map[string]any, string, error)
	UsersPage(ctx context.Context, p authorization.Principal, limit int, after string) ([]identity.User, string, error)
	WebAuthnCredentials(ctx context.Context, id string) ([]json.RawMessage, error)
}
