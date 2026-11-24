package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	runnel "github.com/runnelhq/sdk-go"
)

// connection is the connection type "ldap": a file in connections/ of the project.
type connection struct {
	runnel.ConnectionInfo
	URL              string `json:"url" doc:"Address of the server: ldaps://host (TLS, port 636) or ldap://host (port 389), e.g. ldaps://dc1.example.com" schema:"required,example=ldaps://dc1.example.com"`
	BindDN           string `json:"bindDn" doc:"User to sign in with: a DN such as CN=svc-runnel,OU=Service,DC=example,DC=com or, for Active Directory, svc-runnel@example.com; empty: anonymous" schema:"group=Sign-in"`
	Password         string `json:"password" doc:"Password of bindDn" schema:"format=runnel-secret,group=Sign-in"`
	BaseDN           string `json:"baseDn" doc:"Where searches start unless an action names another, e.g. DC=example,DC=com"`
	StartTLS         bool   `json:"startTls" doc:"Switch an ldap:// connection to TLS before signing in (StartTLS)" schema:"group=Security"`
	CAFile           string `json:"caFile" doc:"PEM file with the certificate of the CA that signed the certificate of the server, if the computer does not trust it yet; relative to the project folder" schema:"group=Security"`
	ServerName       string `json:"serverName" doc:"Name in the certificate of the server, if it differs from the host in url" schema:"group=Security"`
	AllowUnencrypted bool   `json:"allowUnencrypted" doc:"Allow signing in with a password over ldap:// without startTls; the password crosses the network readable, so only for tests" schema:"group=Security"`
	Timeout          string `json:"timeout" doc:"Longest time to connect and for each request, e.g. 30s" schema:"format=runnel-duration,default=30s"`
}

const defaultTimeout = 30 * time.Second

// session is an open connection; Close ends it.
type session struct {
	*ldap.Conn
	stop func() bool
	host string
}

func (s *session) Close() {
	s.stop()
	_ = s.Conn.Close()
}

// open connects to the server and signs in with bindDn. The connection is closed when ctx
// ends, which stops a running request.
func (c connection) open(ctx context.Context) (*session, error) {
	s, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	if c.BindDN == "" {
		if c.Password != "" {
			s.Close()
			return nil, errors.New("connection: password without bindDn")
		}
		return s, nil
	}
	if err := s.bind(ctx, c.BindDN, c.Password); err != nil {
		s.Close()
		return nil, fmt.Errorf("sign-in as %s: %w", c.BindDN, err)
	}
	return s, nil
}

// dial connects without signing in; TLS as configured.
func (c connection) dial(ctx context.Context) (*session, error) {
	timeout := defaultTimeout
	if c.Timeout != "" {
		d, err := time.ParseDuration(c.Timeout)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("connection: timeout %q is not a duration such as 30s", c.Timeout)
		}
		timeout = d
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "ldap" && u.Scheme != "ldaps") || u.Hostname() == "" {
		return nil, fmt.Errorf("connection: url %q must be ldap://host or ldaps://host", c.URL)
	}
	if u.Scheme == "ldaps" && c.StartTLS {
		return nil, errors.New("connection: startTls is only for ldap://; ldaps:// uses TLS already")
	}
	encrypted := u.Scheme == "ldaps" || c.StartTLS
	if c.BindDN != "" && !encrypted && !c.AllowUnencrypted {
		return nil, errors.New("connection: signing in over ldap:// would send the password readable; use ldaps://, startTls: true or, only for tests, allowUnencrypted: true")
	}
	tlsConfig, err := c.tlsConfig(u.Hostname())
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := ldap.DialURL(u.String(), ldap.DialWithDialer(dialer), ldap.DialWithTLSConfig(tlsConfig))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("cannot connect to %s: %w", u.Host, unwrapNetwork(err))
	}
	conn.SetTimeout(timeout)
	s := &session{Conn: conn, host: u.Host}
	s.stop = context.AfterFunc(ctx, func() { _ = conn.Close() })
	if c.StartTLS {
		if err := conn.StartTLS(tlsConfig); err != nil {
			s.Close()
			return nil, fmt.Errorf("StartTLS with %s: %w", u.Host, explain(ctx, err))
		}
	}
	return s, nil
}

func (s *session) bind(ctx context.Context, dn, password string) error {
	if password == "" {
		// An empty password would be an unauthenticated bind, which many servers accept.
		return errEmptyPassword
	}
	if err := s.Bind(dn, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) && ctx.Err() == nil {
			return errInvalidCredentials
		}
		return explain(ctx, err)
	}
	return nil
}

var (
	errEmptyPassword      = errors.New("the password is empty")
	errInvalidCredentials = errors.New("invalid user or password (LDAP result 49)")
)

func (c connection) tlsConfig(host string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	if c.ServerName != "" {
		cfg.ServerName = c.ServerName
	}
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("connection: caFile: %w", unwrapPath(err))
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("connection: caFile %s holds no PEM certificate", c.CAFile)
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// explain turns errors of the LDAP library into messages for users: the meaning of the
// result code and the message of the server.
func explain(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if le, ok := errors.AsType[*ldap.Error](err); ok {
		if le.ResultCode == ldap.ErrorNetwork {
			return fmt.Errorf("network error: %w", unwrapNetwork(le.Err))
		}
		text, ok := resultTexts[le.ResultCode]
		if !ok {
			text = strings.ToLower(ldap.LDAPResultCodeMap[le.ResultCode])
		}
		msg := fmt.Sprintf("%s (LDAP result %d)", text, le.ResultCode)
		if detail := strings.TrimSpace(serverMessage(le)); detail != "" {
			msg += ": " + detail
		}
		return errors.New(msg)
	}
	return err
}

func serverMessage(le *ldap.Error) string {
	if le.Err == nil {
		return ""
	}
	return strings.TrimRight(le.Err.Error(), "\x00")
}

var resultTexts = map[uint16]string{
	ldap.LDAPResultInvalidCredentials:          "invalid user or password",
	ldap.LDAPResultNoSuchObject:                "the entry does not exist",
	ldap.LDAPResultInsufficientAccessRights:    "no permission",
	ldap.LDAPResultEntryAlreadyExists:          "the entry exists already",
	ldap.LDAPResultObjectClassViolation:        "the entry does not fit its object classes",
	ldap.LDAPResultNotAllowedOnNonLeaf:         "the entry has entries below it",
	ldap.LDAPResultConstraintViolation:         "a value is not allowed",
	ldap.LDAPResultUndefinedAttributeType:      "unknown attribute",
	ldap.LDAPResultInvalidDNSyntax:             "invalid DN",
	ldap.LDAPResultSizeLimitExceeded:           "too many entries for the server",
	ldap.LDAPResultTimeLimitExceeded:           "the server took too long",
	ldap.LDAPResultUnwillingToPerform:          "the server refuses",
	ldap.LDAPResultConfidentialityRequired:     "the server requires TLS",
	ldap.LDAPResultStrongAuthRequired:          "the server requires a stronger sign-in (TLS or signing)",
	ldap.LDAPResultAttributeOrValueExists:      "the value exists already",
	ldap.LDAPResultNoSuchAttribute:             "the attribute or value does not exist",
	ldap.LDAPResultInappropriateAuthentication: "this sign-in is not allowed",
}

// unwrapNetwork drops the Go operation names from network errors ("dial tcp …: connect: ").
func unwrapNetwork(err error) error {
	if oe, ok := errors.AsType[*net.OpError](err); ok && oe.Err != nil {
		return oe.Err
	}
	return err
}

func unwrapPath(err error) error {
	if pe, ok := errors.AsType[*os.PathError](err); ok {
		return fmt.Errorf("%s: %w", pe.Path, pe.Err)
	}
	return err
}

// testConnection signs in and reads the root DSE for the version of the server.
func testConnection(ctx context.Context, c connection) (runnel.TestResult, error) {
	s, err := c.open(ctx)
	if err != nil {
		return runnel.TestResult{}, err
	}
	defer s.Close()
	who := "anonymously"
	if c.BindDN != "" {
		who = "as " + c.BindDN
	}
	res := runnel.TestResult{OK: true, Message: fmt.Sprintf("signed in %s on %s", who, s.host)}
	root, err := s.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)", []string{"vendorName", "vendorVersion", "supportedCapabilities", "domainControllerFunctionality"}, nil))
	if err == nil && len(root.Entries) == 1 {
		res.Version = serverVersion(root.Entries[0])
	}
	return res, nil
}

// adCapability is the capability of Active Directory in the root DSE.
const adCapability = "1.2.840.113556.1.4.800"

func serverVersion(e *ldap.Entry) string {
	for _, c := range e.GetAttributeValues("supportedCapabilities") {
		if c == adCapability {
			if level := e.GetAttributeValue("domainControllerFunctionality"); level != "" {
				return "Active Directory (functional level " + level + ")"
			}
			return "Active Directory"
		}
	}
	return strings.TrimSpace(e.GetAttributeValue("vendorName") + " " + e.GetAttributeValue("vendorVersion"))
}
