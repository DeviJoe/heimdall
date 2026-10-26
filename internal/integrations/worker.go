package integrations

import (
	"Heimdall/internal/application"
	"Heimdall/internal/platform/config"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Repository interface {
	ImportDirectory(context.Context, string, []application.DirectoryUser) error
	IntegrationResult(context.Context, string, error) error
	IntegrationStarted(context.Context, string) error
	ClaimNotifications(context.Context) ([]application.NotificationJob, error)
	NotificationAllowed(context.Context, application.NotificationJob) bool
	FinishNotification(context.Context, string, string, string, time.Duration) error
}
type Worker struct {
	Store  Repository
	Config config.Config
	Client *http.Client
}

func (w *Worker) Run(ctx context.Context) {
	if w.Client == nil {
		w.Client = &http.Client{Timeout: 15 * time.Second}
	}
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	directory := time.NewTicker(time.Minute)
	defer directory.Stop()
	w.directories(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-directory.C:
			w.directories(ctx)
		case <-tick.C:
			w.notifications(ctx)
		}
	}
}
func (w *Worker) directories(ctx context.Context) {
	for _, p := range w.Config.LDAP {
		if err := w.Store.IntegrationStarted(ctx, p.ID); err != nil {
			slog.Error("directory start status unavailable", "provider", p.ID, "error", err)
			continue
		}
		users, err := ReadLDAP(p)
		if err == nil {
			err = w.Store.ImportDirectory(ctx, "ldap:"+p.ID, users)
		}
		if err != nil {
			slog.Error("directory synchronization failed", "provider", p.ID, "error", err)
		}
		if e := w.Store.IntegrationResult(ctx, p.ID, err); e != nil {
			slog.Error("integration status persistence failed", "error", e)
		}
	}
}
func ReadLDAP(p config.LDAPProvider) ([]application.DirectoryUser, error) {
	u, err := url.Parse(p.URL)
	if err != nil || (u.Scheme != "ldaps" && u.Scheme != "ldap") {
		return nil, errors.New("LDAP requires ldap or ldaps URL")
	}
	connection, err := ldap.DialURL(p.URL, ldap.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}), ldap.DialWithTLSConfig(&tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}))
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	connection.SetTimeout(10 * time.Second)
	if u.Scheme == "ldap" {
		if err = connection.StartTLS(&tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}); err != nil {
			return nil, err
		}
	}
	if err = connection.Bind(p.BindDN, os.Getenv(p.PasswordEnv)); err != nil {
		return nil, err
	}
	filter := p.Filter
	if filter == "" {
		filter = "(objectClass=person)"
	}
	result, err := connection.SearchWithPaging(ldap.NewSearchRequest(p.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 50000, 30, false, filter, []string{p.IDAttribute, p.LoginAttribute, "displayName"}, nil), 1000)
	if err != nil {
		return nil, err
	}
	out := []application.DirectoryUser{}
	seen := map[string]bool{}
	for _, entry := range result.Entries {
		subject := entry.GetAttributeValue(p.IDAttribute)
		login := entry.GetAttributeValue(p.LoginAttribute)
		if subject == "" || login == "" || seen[subject] {
			return nil, errors.New("directory entries must have unique stable IDs and logins")
		}
		seen[subject] = true
		out = append(out, application.DirectoryUser{Subject: subject, Login: login, DisplayName: entry.GetAttributeValue("displayName")})
	}
	return out, nil
}
func (w *Worker) notifications(ctx context.Context) {
	jobs, err := w.Store.ClaimNotifications(ctx)
	if err != nil {
		slog.Error("notification queue unavailable", "error", err)
		return
	}
	for _, j := range jobs {
		if !w.Store.NotificationAllowed(ctx, j) {
			w.Store.FinishNotification(ctx, j.ID, "cancelled", "recipient access removed", 0)
			continue
		}
		if (j.Provider == "telegram" && !w.Config.Telegram.Enabled) || (j.Provider == "mattermost" && !w.Config.Mattermost.Enabled) {
			w.Store.FinishNotification(ctx, j.ID, "retrying", "provider disabled", time.Minute)
			continue
		}
		err = w.deliver(ctx, j)
		state := "accepted_by_provider"
		detail := ""
		delay := time.Duration(0)
		if err != nil {
			state = "retrying"
			detail = err.Error()
			delay = time.Second*time.Duration(1<<min(j.Attempts, 10)) + time.Duration(rand.IntN(30))*time.Second
			if j.Attempts >= 20 {
				state = "failed"
			}
		}
		if e := w.Store.FinishNotification(ctx, j.ID, state, detail, delay); e != nil {
			slog.Error("notification result persistence failed", "job", j.ID, "error", e)
		}
	}
}
func (w *Worker) deliver(ctx context.Context, j application.NotificationJob) error {
	text := fmt.Sprintf("Heimdall · %s · %s\n%s\n%s\n%s", j.Severity, j.Status, j.Kind, j.Message, w.Config.Server.PublicURL)
	if j.Provider == "telegram" {
		_, err := w.request(ctx, "POST", "https://api.telegram.org/bot"+os.Getenv(w.Config.Telegram.BotTokenEnv)+"/sendMessage", map[string]string{"chat_id": j.ChatID, "text": text}, "")
		return err
	}
	if j.Provider != "mattermost" {
		return errors.New("unsupported notification provider")
	}
	base := strings.TrimRight(w.Config.Mattermost.URL, "/") + "/api/v4"
	bearer := os.Getenv(w.Config.Mattermost.TokenEnv)
	me, err := w.request(ctx, "GET", base+"/users/me", nil, bearer)
	if err != nil {
		return err
	}
	id, _ := me["id"].(string)
	if id == "" {
		return errors.New("Mattermost bot identity missing")
	}
	channel, err := w.request(ctx, "POST", base+"/channels/direct", []string{id, j.Subject}, bearer)
	if err != nil {
		return err
	}
	channelID, _ := channel["id"].(string)
	if channelID == "" {
		return errors.New("Mattermost direct channel missing")
	}
	_, err = w.request(ctx, "POST", base+"/posts", map[string]string{"channel_id": channelID, "message": text}, bearer)
	return err
}
func (w *Worker) request(ctx context.Context, method, target string, body any, bearer string) (map[string]any, error) {
	var reader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		reader = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return nil, errors.New("provider request configuration invalid")
	}
	request.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := w.Client.Do(request)
	if err != nil {
		return nil, errors.New("provider network request failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("provider HTTP %d", response.StatusCode)
	}
	var out map[string]any
	if err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&out); err != nil {
		return nil, errors.New("invalid provider response")
	}
	if ok, present := out["ok"].(bool); present && !ok {
		return nil, errors.New("provider rejected notification")
	}
	return out, nil
}
