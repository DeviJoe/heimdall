package httpapi

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"Heimdall/internal/identity"
	"Heimdall/internal/platform/security"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/redis/go-redis/v9"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

type factorUserStore struct {
	application.ControlPlane
	user  identity.User
	calls int
}

func (s *factorUserStore) User(_ context.Context, id string) (identity.User, error) {
	s.calls++
	if id != s.user.ID {
		return identity.User{}, application.ErrNotFound
	}
	return s.user, nil
}

// Capture cache commands without a Redis server or a network connection.
type enrollmentCacheHook struct{ writes [][]any }

func (h *enrollmentCacheHook) DialHook(redis.DialHook) redis.DialHook {
	return func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("unit enrollment cache must not dial")
	}
}
func (h *enrollmentCacheHook) ProcessHook(redis.ProcessHook) redis.ProcessHook {
	return func(_ context.Context, cmd redis.Cmder) error {
		status, ok := cmd.(*redis.StatusCmd)
		if cmd.Name() != "set" || !ok {
			return errors.New("unexpected enrollment cache command")
		}
		h.writes = append(h.writes, cmd.Args())
		status.SetVal("OK")
		return nil
	}
}
func (h *enrollmentCacheHook) ProcessPipelineHook(redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(context.Context, []redis.Cmder) error {
		return errors.New("unexpected enrollment pipeline")
	}
}

func TestTOTPBeginChecksTheSpecificFactor(t *testing.T) {
	for _, tc := range []struct {
		name     string
		totp     bool
		passkeys int
		token    string
		status   int
	}{
		{"first factor", false, 0, "", http.StatusOK},
		{"passkey exists and TOTP policy remains required", false, 1, "", http.StatusOK},
		{"TOTP cannot be silently replaced", true, 0, "", http.StatusBadRequest},
		{"both exist and TOTP cannot be replaced", true, 1, "", http.StatusBadRequest},
		{"API token cannot enroll browser factors", false, 1, "api-token", http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &factorUserStore{user: identity.User{ID: "engineer", Login: "engineer", Status: "active", Kind: "human", MFAPolicy: "totp", TOTPEnabled: tc.totp, PasskeyCount: tc.passkeys, MFAEnabled: tc.totp || tc.passkeys > 0}}
			cache := &enrollmentCacheHook{}
			client := redis.NewClient(&redis.Options{Addr: "unused", MaxRetries: -1})
			t.Cleanup(func() { _ = client.Close() })
			client.AddHook(cache)
			cipher, err := security.NewCipher(security.Random(32))
			if err != nil {
				t.Fatal(err)
			}
			s := &Server{Store: store, Redis: client, Cipher: cipher}
			p := authorization.Principal{UserID: store.user.ID, Login: store.user.Login, Restricted: !tc.totp, TokenID: tc.token}
			r := httptest.NewRequest("POST", "/api/v1/me/totp/begin", nil)
			r = r.WithContext(context.WithValue(r.Context(), contextKey{}, p))
			w := httptest.NewRecorder()
			s.totpBegin(w, r)
			if w.Code != tc.status {
				t.Fatalf("HTTP %d, expected %d", w.Code, tc.status)
			}
			if tc.status != http.StatusOK {
				if len(cache.writes) != 0 {
					t.Fatal("rejected enrollment changed pending secret")
				}
				return
			}
			var body map[string]string
			if err = json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if len(cache.writes) != 1 {
				t.Fatal("enrollment secret not cached once")
			}
			args := cache.writes[0]
			if len(args) != 5 || args[1] != "totp-enroll:engineer" || args[3] != "ex" || fmt.Sprint(args[4]) != "300" {
				t.Fatal("pending enrollment must belong to the caller and expire after five minutes")
			}
			sealed, ok := args[2].(string)
			if !ok || sealed == body["secret"] {
				t.Fatal("pending secret was not encrypted")
			}
			plain, err := cipher.Open(sealed)
			if err != nil || plain == "" || plain != body["secret"] {
				t.Fatal("cached enrollment does not match the returned secret")
			}
			uri, err := url.Parse(body["uri"])
			if err != nil || uri.Scheme != "otpauth" || uri.Host != "totp" || uri.Query().Get("secret") != plain {
				t.Fatal("authenticator URI does not match the pending enrollment")
			}
		})
	}
}
