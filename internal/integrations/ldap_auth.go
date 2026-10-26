package integrations

import (
	"Heimdall/internal/platform/config"
	"crypto/tls"
	"errors"
	"github.com/go-ldap/ldap/v3"
	"net"
	"net/url"
	"os"
	"time"
)

func LDAPLogin(p config.LDAPProvider, login, password string) (string, error) {
	if password == "" || len(password) > 1024 {
		return "", errors.New("invalid credentials")
	}
	u, err := url.Parse(p.URL)
	if err != nil || (u.Scheme != "ldap" && u.Scheme != "ldaps") {
		return "", errors.New("invalid LDAP URL")
	}
	connection, err := ldap.DialURL(p.URL, ldap.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}), ldap.DialWithTLSConfig(&tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}))
	if err != nil {
		return "", err
	}
	defer connection.Close()
	connection.SetTimeout(10 * time.Second)
	if u.Scheme == "ldap" {
		if err = connection.StartTLS(&tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}); err != nil {
			return "", err
		}
	}
	if err = connection.Bind(p.BindDN, os.Getenv(p.PasswordEnv)); err != nil {
		return "", err
	}
	baseFilter := p.Filter
	if baseFilter == "" {
		baseFilter = "(objectClass=person)"
	}
	filter := "(&" + baseFilter + "(" + p.LoginAttribute + "=" + ldap.EscapeFilter(login) + "))"
	result, err := connection.Search(ldap.NewSearchRequest(p.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 10, false, filter, []string{p.IDAttribute}, nil))
	if err != nil || len(result.Entries) != 1 {
		return "", errors.New("invalid directory credentials")
	}
	entry := result.Entries[0]
	subject := entry.GetAttributeValue(p.IDAttribute)
	if subject == "" {
		return "", errors.New("stable LDAP subject missing")
	}
	if err = connection.Bind(entry.DN, password); err != nil {
		return "", errors.New("invalid directory credentials")
	}
	return subject, nil
}
