package config

import (
	"errors"
	"go.yaml.in/yaml/v3"
	"io"
	"net/url"
	"os"
	"time"
)

type Config struct {
	Queue struct {
		URLEnv string `yaml:"url_env"`
	} `yaml:"queue"`
	Server struct {
		PublicURL   string `yaml:"public_url"`
		APIListen   string `yaml:"api_listen"`
		GRPCListen  string `yaml:"grpc_listen"`
		PKIDir      string `yaml:"pki_dir"`
		Development bool   `yaml:"development"`
	} `yaml:"server"`
	Database struct {
		DSNEnv string `yaml:"dsn_env"`
	} `yaml:"database"`
	Redis struct {
		URLEnv string `yaml:"url_env"`
	} `yaml:"redis"`
	Security struct {
		EncryptionKeyEnv string        `yaml:"encryption_key_env"`
		AdminPasswordEnv string        `yaml:"admin_password_env"`
		JoinTokenEnv     string        `yaml:"join_token_env"`
		RequireSK        bool          `yaml:"require_sk"`
		KeyTTL           time.Duration `yaml:"key_ttl"`
	} `yaml:"security"`
	Sync struct {
		ApplyTimeout    time.Duration `yaml:"apply_timeout"`
		Heartbeat       time.Duration `yaml:"heartbeat_interval"`
		Stalled         time.Duration `yaml:"stalled_after"`
		Offline         time.Duration `yaml:"offline_after"`
		RevocationAlert time.Duration `yaml:"revocation_alert_after"`
	} `yaml:"sync"`
	Metrics struct {
		Listen          string `yaml:"listen"`
		UsernameEnv     string `yaml:"username_env"`
		PasswordHashEnv string `yaml:"password_hash_env"`
		TLS             bool   `yaml:"tls"`
		MTLS            bool   `yaml:"mtls"`
		ClientCAFile    string `yaml:"client_ca_file"`
	} `yaml:"metrics"`
	Swagger struct {
		Enabled bool `yaml:"enabled"`
	} `yaml:"swagger"`
	MCP struct {
		Enabled bool `yaml:"enabled"`
	} `yaml:"mcp"`
	Telegram struct {
		Enabled          bool   `yaml:"enabled"`
		BotTokenEnv      string `yaml:"bot_token_env"`
		ClientIDEnv      string `yaml:"client_id_env"`
		ClientSecretEnv  string `yaml:"client_secret_env"`
		WebhookSecretEnv string `yaml:"webhook_secret_env"`
	} `yaml:"telegram"`
	Mattermost struct {
		Enabled         bool   `yaml:"enabled"`
		URL             string `yaml:"url"`
		TokenEnv        string `yaml:"token_env"`
		ChannelID       string `yaml:"channel_id"`
		ClientIDEnv     string `yaml:"client_id_env"`
		ClientSecretEnv string `yaml:"client_secret_env"`
	} `yaml:"mattermost"`
	OIDC []OIDCProvider `yaml:"oidc"`
	LDAP []LDAPProvider `yaml:"ldap"`
}
type OIDCProvider struct {
	AutoProvision   bool   `yaml:"auto_provision"`
	RequireMFA      bool   `yaml:"require_mfa"`
	ID              string `yaml:"id"`
	Issuer          string `yaml:"issuer"`
	ClientIDEnv     string `yaml:"client_id_env"`
	ClientSecretEnv string `yaml:"client_secret_env"`
}
type LDAPProvider struct {
	ID             string `yaml:"id"`
	URL            string `yaml:"url"`
	BindDN         string `yaml:"bind_dn"`
	PasswordEnv    string `yaml:"password_env"`
	BaseDN         string `yaml:"base_dn"`
	Filter         string `yaml:"filter"`
	LoginAttribute string `yaml:"login_attribute"`
	IDAttribute    string `yaml:"id_attribute"`
}

func Load(path string) (Config, error) {
	var c Config
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	d := yaml.NewDecoder(io.LimitReader(f, 1<<20))
	d.KnownFields(true)
	if err = d.Decode(&c); err != nil {
		return c, err
	}
	if c.Server.PublicURL == "" || c.Server.PKIDir == "" || c.Server.APIListen == "" || c.Server.GRPCListen == "" {
		return c, errors.New("server configuration incomplete")
	}
	if !c.Server.Development && (len(c.Server.PublicURL) < 8 || c.Server.PublicURL[:8] != "https://") {
		return c, errors.New("production public URL requires HTTPS")
	}
	public, err := url.Parse(c.Server.PublicURL)
	if err != nil || public.Hostname() == "" || public.User != nil || public.RawQuery != "" || public.Fragment != "" || (public.Path != "" && public.Path != "/") || (public.Scheme != "https" && public.Scheme != "http") {
		return c, errors.New("public_url must be an absolute HTTP origin without credentials or a path")
	}
	if c.Sync.Heartbeat == 0 {
		c.Sync.Heartbeat = 60 * time.Second
	}
	if c.Sync.Stalled == 0 {
		c.Sync.Stalled = 5 * time.Minute
	}
	if c.Sync.ApplyTimeout == 0 {
		c.Sync.ApplyTimeout = 15 * time.Minute
	}
	if c.Sync.ApplyTimeout < time.Minute || c.Sync.ApplyTimeout > 24*time.Hour {
		return c, errors.New("apply_timeout must be between 1m and 24h")
	}
	if c.Sync.Offline == 0 {
		c.Sync.Offline = 3 * time.Minute
	}
	if c.Sync.RevocationAlert == 0 {
		c.Sync.RevocationAlert = time.Minute
	}
	if c.Security.KeyTTL == 0 {
		c.Security.KeyTTL = 30 * 24 * time.Hour
	}
	if c.Sync.Heartbeat <= 0 || c.Sync.Stalled <= 0 || c.Sync.Offline < 2*c.Sync.Heartbeat || c.Sync.RevocationAlert <= 0 || c.Security.KeyTTL <= 0 {
		return c, errors.New("invalid synchronization duration or key TTL")
	}
	for _, env := range []string{c.Database.DSNEnv, c.Redis.URLEnv, c.Security.EncryptionKeyEnv, c.Security.AdminPasswordEnv, c.Security.JoinTokenEnv} {
		if env == "" || os.Getenv(env) == "" {
			return c, errors.New("required secret environment variable missing")
		}
	}
	if c.Metrics.MTLS && !c.Metrics.TLS {
		return c, errors.New("metrics mTLS requires TLS")
	}
	if c.Metrics.PasswordHashEnv != "" && (os.Getenv(c.Metrics.PasswordHashEnv) == "" || os.Getenv(c.Metrics.UsernameEnv) == "") {
		return c, errors.New("metrics credentials incomplete")
	}
	if c.Telegram.Enabled {
		for _, env := range []string{c.Telegram.BotTokenEnv, c.Telegram.ClientIDEnv, c.Telegram.ClientSecretEnv, c.Telegram.WebhookSecretEnv} {
			if os.Getenv(env) == "" {
				return c, errors.New("Telegram credentials incomplete")
			}
		}
	}
	if c.Mattermost.Enabled && (c.Mattermost.URL == "" || os.Getenv(c.Mattermost.TokenEnv) == "" || os.Getenv(c.Mattermost.ClientIDEnv) == "" || os.Getenv(c.Mattermost.ClientSecretEnv) == "") {
		return c, errors.New("Mattermost credentials incomplete")
	}
	providers := map[string]bool{}
	for _, provider := range c.OIDC {
		u, e := url.Parse(provider.Issuer)
		if e != nil || u.Hostname() == "" || (!c.Server.Development && u.Scheme != "https") || provider.ID == "" || providers[provider.ID] || os.Getenv(provider.ClientIDEnv) == "" || os.Getenv(provider.ClientSecretEnv) == "" {
			return c, errors.New("OIDC provider configuration incomplete or duplicate")
		}
		providers[provider.ID] = true
	}
	for _, provider := range c.LDAP {
		u, e := url.Parse(provider.URL)
		if e != nil || u.Hostname() == "" || (u.Scheme != "ldap" && u.Scheme != "ldaps") || provider.ID == "" || providers[provider.ID] || provider.IDAttribute == "" || provider.LoginAttribute == "" || provider.BaseDN == "" || os.Getenv(provider.PasswordEnv) == "" {
			return c, errors.New("LDAP provider configuration incomplete or duplicate")
		}
		providers[provider.ID] = true
	}
	return c, nil
}
