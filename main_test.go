package main

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/runnelhq/sdk-go/runneltest"

	"github.com/runnelhq/plugin-ldap/internal/ldaptest"
)

const alice = "uid=alice,ou=people,dc=example,dc=org"

// conns returns connections to the test server: anonymous over ldaps, admin over ldaps,
// admin with StartTLS.
func conns(s *ldaptest.Server) (anon, admin, startTLS map[string]any) {
	anon = map[string]any{"name": "dir", "type": "ldap", "url": s.TLSURL, "caFile": s.CAFile, "baseDn": ldaptest.Base}
	admin = map[string]any{"name": "dir", "type": "ldap", "url": s.TLSURL, "caFile": s.CAFile, "baseDn": ldaptest.Base,
		"bindDn": ldaptest.Admin, "password": ldaptest.AdminPassword}
	startTLS = map[string]any{"name": "dir", "type": "ldap", "url": s.URL, "startTls": true, "caFile": s.CAFile, "serverName": "localhost",
		"bindDn": ldaptest.Admin, "password": ldaptest.AdminPassword}
	return anon, admin, startTLS
}

func with(m map[string]any, kv ...any) map[string]any {
	out := maps.Clone(m)
	for i := 0; i < len(kv); i += 2 {
		out[kv[i].(string)] = kv[i+1]
	}
	return out
}

func TestDescribe(t *testing.T) {
	c := runneltest.Start(t, newPlugin())
	d, err := c.Describe()
	if err != nil {
		t.Fatal(err)
	}
	var types []string
	for _, a := range d.Actions {
		types = append(types, a.Type)
		if !strings.Contains(string(a.Schema), `"connection":{"type":"string","description":"LDAP connection`) ||
			!strings.Contains(string(a.Schema), `"format":"runnel-connection","x-runnel-connection":["ldap"]`) {
			t.Errorf("%s: schema %s", a.Type, a.Schema)
		}
	}
	if got := strings.Join(types, " "); got != "ldap.search ldap.authenticate ldap.add ldap.modify ldap.delete" {
		t.Errorf("types = %s", got)
	}
	if len(d.ConnectionTypes) != 1 || d.ConnectionTypes[0].Type != "ldap" || !d.ConnectionTypes[0].Test ||
		!strings.Contains(string(d.ConnectionTypes[0].Schema), `"password":{"type":"string","description":"Password of bindDn","format":"runnel-secret"`) {
		t.Errorf("connection types = %+v", d.ConnectionTypes)
	}
}

// The actions have no category, so that Runnel shows them in the group "Plugin: ldap";
// ldap.input keeps the category input.
func TestCategories(t *testing.T) {
	c := runneltest.Start(t, newPlugin())
	d, err := c.Describe()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range d.Actions {
		if a.Category != "" {
			t.Errorf("%s: category %q", a.Type, a.Category)
		}
	}
	raw, err := c.Call("describe", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"type":"ldap.input","kind":"transform","category":"input"`) {
		t.Errorf("ldap.input without category input: %s", raw)
	}
}

func TestConnectionTest(t *testing.T) {
	s := ldaptest.Start(t)
	c := runneltest.Start(t, newPlugin())
	anon, admin, startTLS := conns(s)
	tests := []struct {
		name string
		conn map[string]any
		ok   bool
		msg  string
	}{
		{"anonymous over ldaps", anon, true, "signed in anonymously on 127.0.0.1"},
		{"admin over ldaps", admin, true, "signed in as cn=admin,dc=example,dc=org"},
		{"StartTLS", startTLS, true, "signed in as cn=admin"},
		{"wrong password", with(admin, "password", "nope"), false, "sign-in as cn=admin,dc=example,dc=org: invalid user or password (LDAP result 49)"},
		{"empty password", with(admin, "password", ""), false, "the password is empty"},
		{"password without TLS", with(admin, "url", s.URL), false, "signing in over ldap:// would send the password readable"},
		{"allowUnencrypted", with(admin, "url", s.URL, "allowUnencrypted", true), true, "signed in as cn=admin"},
		{"unknown CA", with(admin, "caFile", ""), false, "cannot connect to 127.0.0.1"},
		{"wrong server name", with(startTLS, "serverName", "other.example.org"), false, "StartTLS with 127.0.0.1"},
		{"bad url", with(admin, "url", "http://x"), false, `url "http://x" must be ldap://host or ldaps://host`},
		{"bad timeout", with(admin, "timeout", "soon"), false, `timeout "soon" is not a duration`},
		{"missing CA file", with(admin, "caFile", "nowhere.pem"), false, "caFile: nowhere.pem: no such file"},
		{"no server", with(anon, "url", "ldap://127.0.0.1:1"), false, "cannot connect to 127.0.0.1:1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := c.TestConnection(tt.conn)
			if err != nil || res.OK != tt.ok || !strings.Contains(res.Message, tt.msg) {
				t.Errorf("test = %+v, %v; want ok %v with %q", res, err, tt.ok, tt.msg)
			}
			if strings.Contains(res.Message, ldaptest.AdminPassword) {
				t.Errorf("message shows the password: %s", res.Message)
			}
		})
	}
}

func TestSearch(t *testing.T) {
	s := ldaptest.Start(t)
	c := runneltest.Start(t, newPlugin())
	anon, _, startTLS := conns(s)

	var out searchOutput
	if err := c.ExecuteInto("ldap.search", map[string]any{
		"connection": anon, "filter": "(&(objectClass=inetOrgPerson)(uid={user}))", "filterValues": map[string]any{"user": "bob"},
		"attributes": []string{"cn", "mail"},
	}, &out); err != nil {
		t.Fatal(err)
	}
	if out.Count != 1 || out.Entries[0].DN != "uid=bob,ou=people,dc=example,dc=org" ||
		!slices.Equal(out.Entries[0].Attributes["mail"], []string{"bob@example.org", "robert@example.org"}) ||
		!slices.Equal(out.Entries[0].Attributes["cn"], []string{"Bob Roe"}) || len(out.Entries[0].Attributes) != 2 {
		t.Errorf("output = %+v", out)
	}

	// Values are escaped: an injected filter finds nothing.
	out = searchOutput{}
	if err := c.ExecuteInto("ldap.search", map[string]any{
		"connection": anon, "filter": "(uid={user})", "filterValues": map[string]any{"user": "*)(uid=*"},
	}, &out); err != nil || out.Count != 0 || out.Entries == nil {
		t.Errorf("injection: %+v, %v", out, err)
	}

	// Binary values as Base64; userPassword is not readable anonymously.
	out = searchOutput{}
	if err := c.ExecuteInto("ldap.search", map[string]any{"connection": anon, "baseDn": alice, "scope": "base"}, &out); err != nil {
		t.Fatal(err)
	}
	if out.Count != 1 || out.Entries[0].Attributes["jpegPhoto"][0] != "/9j/4AAQ" || out.Entries[0].Attributes["userPassword"] != nil {
		t.Errorf("alice = %+v", out)
	}

	// Scope one, with paging (page size 1) and StartTLS.
	out = searchOutput{}
	if err := c.ExecuteInto("ldap.search", map[string]any{
		"connection": startTLS, "baseDn": "ou=people," + ldaptest.Base, "scope": "one", "pageSize": "1", "attributes": []string{"uid"},
	}, &out); err != nil || out.Count != 2 {
		t.Errorf("scope one: %+v, %v", out, err)
	}

	errorsWant := []struct {
		config map[string]any
		msg    string
	}{
		{map[string]any{"connection": anon, "sizeLimit": 3}, "the search finds more than 3 entries (sizeLimit)"},
		{map[string]any{"connection": anon, "sizeLimit": 3, "pageSize": 0}, "the search finds more than 3 entries (sizeLimit)"},
		{map[string]any{"connection": anon, "sizeLimit": 200000}, "sizeLimit must be between 1 and 100000"},
		{map[string]any{"connection": anon, "filter": "(uid={who})"}, "filter uses {who}, which is not in filterValues"},
		{map[string]any{"connection": anon, "filter": "(uid=alice"}, `invalid filter "(uid=alice"`},
		{map[string]any{"connection": anon, "scope": "all"}, `scope "all" must be sub, one or base`},
		{map[string]any{"connection": anon, "baseDn": "ou=nobody," + ldaptest.Base}, `search in "ou=nobody,dc=example,dc=org": the entry does not exist (LDAP result 32)`},
	}
	for _, tt := range errorsWant {
		if _, err := c.Execute("ldap.search", tt.config); err == nil || !strings.Contains(err.Error(), tt.msg) {
			t.Errorf("%v: err = %v, want %q", tt.config, err, tt.msg)
		}
	}
}

func TestAuthenticate(t *testing.T) {
	s := ldaptest.Start(t)
	c := runneltest.Start(t, newPlugin())
	anon, _, _ := conns(s)
	tests := []struct {
		user, password string
		ok             bool
	}{
		{"alice", "alice-pw", true},
		{"alice", "wrong", false},
		{"alice", "", false},
		{"nobody", "alice-pw", false},
		{"*", "alice-pw", false},
	}
	for _, tt := range tests {
		var out authOutput
		err := c.ExecuteInto("ldap.authenticate", map[string]any{"connection": anon, "username": tt.user, "password": tt.password, "attributes": []string{"cn"}}, &out)
		if err != nil || out.Authenticated != tt.ok {
			t.Errorf("%s/%s: %+v, %v", tt.user, tt.password, out, err)
			continue
		}
		if tt.ok && (out.DN != alice || !slices.Equal(out.Attributes["cn"], []string{"Alice Doe"}) || out.Error != "") {
			t.Errorf("%s: %+v", tt.user, out)
		}
		if !tt.ok && out.Error != "invalid user or password" {
			t.Errorf("%s/%s: %+v", tt.user, tt.password, out)
		}
	}
	_, err := c.Execute("ldap.authenticate", map[string]any{"connection": anon, "username": "x", "password": "y", "userFilter": "(objectClass=inetOrgPerson)"})
	if err == nil || !strings.Contains(err.Error(), "userFilter finds several users") {
		t.Errorf("several users: %v", err)
	}
}

func TestAddModifyDelete(t *testing.T) {
	s := ldaptest.Start(t)
	c := runneltest.Start(t, newPlugin())
	anon, admin, _ := conns(s)
	carol := "uid=carol,ou=people," + ldaptest.Base
	var out changeOutput
	if err := c.ExecuteInto("ldap.add", map[string]any{"connection": admin, "dn": carol, "attributes": map[string]any{
		"objectClass": "inetOrgPerson", "cn": "Carol Poe", "sn": "Poe", "mail": []any{"carol@example.org"}, "employeeNumber": 42,
	}}, &out); err != nil || !out.Changed || out.DN != carol {
		t.Fatalf("add: %+v, %v", out, err)
	}
	if _, err := c.Execute("ldap.add", map[string]any{"connection": admin, "dn": carol, "attributes": map[string]any{"objectClass": "inetOrgPerson", "cn": "x", "sn": "y"}}); err == nil ||
		!strings.Contains(err.Error(), "the entry exists already (LDAP result 68)") {
		t.Errorf("add twice: %v", err)
	}
	if _, err := c.Execute("ldap.add", map[string]any{"connection": anon, "dn": "uid=dave,ou=people," + ldaptest.Base, "attributes": map[string]any{"objectClass": "inetOrgPerson", "cn": "x", "sn": "y"}}); err == nil ||
		!strings.Contains(err.Error(), "LDAP result") {
		t.Errorf("add anonymously: %v", err)
	}
	if err := c.ExecuteInto("ldap.modify", map[string]any{"connection": admin, "dn": carol,
		"replace": map[string]any{"cn": "Carol Q. Poe"}, "add": map[string]any{"mail": "cpoe@example.org"}, "delete": map[string]any{"employeeNumber": []any{}},
	}, &out); err != nil || !out.Changed {
		t.Fatalf("modify: %+v, %v", out, err)
	}
	var found searchOutput
	if err := c.ExecuteInto("ldap.search", map[string]any{"connection": anon, "baseDn": carol, "scope": "base"}, &found); err != nil {
		t.Fatal(err)
	}
	a := found.Entries[0].Attributes
	if !slices.Equal(a["cn"], []string{"Carol Q. Poe"}) || !slices.Equal(a["mail"], []string{"carol@example.org", "cpoe@example.org"}) || a["employeeNumber"] != nil {
		t.Errorf("after modify: %v", a)
	}
	if _, err := c.Execute("ldap.modify", map[string]any{"connection": admin, "dn": carol}); err == nil || !strings.Contains(err.Error(), "nothing to change") {
		t.Errorf("modify without changes: %v", err)
	}
	if err := c.ExecuteInto("ldap.delete", map[string]any{"connection": admin, "dn": carol}, &out); err != nil || !out.Changed {
		t.Fatalf("delete: %+v, %v", out, err)
	}
	if err := c.ExecuteInto("ldap.delete", map[string]any{"connection": admin, "dn": carol, "ignoreMissing": true}, &out); err != nil || out.Changed {
		t.Errorf("delete missing: %+v, %v", out, err)
	}
	if _, err := c.Execute("ldap.delete", map[string]any{"connection": admin, "dn": carol}); err == nil || !strings.Contains(err.Error(), "delete uid=carol,ou=people,dc=example,dc=org: the entry does not exist (LDAP result 32)") {
		t.Errorf("delete missing: %v", err)
	}
	if _, err := c.Execute("ldap.delete", map[string]any{"connection": admin, "dn": "ou=people," + ldaptest.Base}); err == nil || !strings.Contains(err.Error(), "the entry has entries below it") {
		t.Errorf("delete non-leaf: %v", err)
	}
}

func TestCancel(t *testing.T) {
	c := runneltest.Start(t, newPlugin())
	// A server that accepts but never answers: the search waits until it is cancelled.
	ctx, cancel := context.WithCancel(context.Background())
	l := silentServer(t)
	go func() {
		<-l.accepted
		cancel()
	}()
	_, err := c.ExecuteContext(ctx, "ldap.search", map[string]any{"connection": map[string]any{"name": "x", "type": "ldap", "url": "ldap://" + l.addr}}, runneltest.Context{})
	var rerr *runneltest.Error
	if !errors.As(err, &rerr) || rerr.Code != -32800 {
		t.Errorf("err = %v, want cancelled", err)
	}
}

func TestVersionMatchesPluginYAML(t *testing.T) {
	data, err := os.ReadFile("plugin.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^version:\s*(\S+)`).FindSubmatch(data)
	if m == nil || string(m[1]) != version {
		t.Errorf("plugin.yaml has version %q, the program %q", m, version)
	}
}

// TestWithRunnel uses the plugin in a workflow of Runnel, with a connection file whose
// password comes from a secret (needs RUNNEL_BIN and slapd).
func TestWithRunnel(t *testing.T) {
	if os.Getenv(runneltest.RunnelEnv) == "" {
		t.Skip("RUNNEL_BIN is not set")
	}
	s := ldaptest.Start(t)
	t.Setenv("LDAP_TEST_ADMIN_PW", ldaptest.AdminPassword)
	p := runneltest.NewProject(t, ".", "plugin.yaml")
	p.WriteFile("connections/dir.yaml", `kind: Connection
apiVersion: runnel/v1
name: dir
type: ldap
with:
  url: `+s.TLSURL+`
  caFile: `+s.CAFile+`
  baseDn: dc=example,dc=org
  bindDn: cn=admin,dc=example,dc=org
  password: ${secret:env/LDAP_TEST_ADMIN_PW}
`)
	p.WriteFile("workflows/check.workflow.yaml", `kind: Workflow
apiVersion: runnel/v1
name: check
parameters:
  - name: USER
  - name: PASSWORD
outputs:
  - name: OK
    value: "{{ results.login.output.authenticated }}"
  - name: MAIL
    value: "{{ results.find.output.entries[0].attributes.mail[0] }}"
actions:
  - id: start
    type: core.start
  - id: login
    type: ldap.authenticate
    with:
      connection: dir
      username: ${USER}
      password: ${PASSWORD}
  - id: find
    type: ldap.search
    with:
      connection: dir
      filter: (uid={user})
      filterValues:
        user: ${USER}
      attributes: [mail]
links:
  - { from: start, to: login }
  - { from: login, to: find }
`)
	if out, code := p.Validate(); code != 0 {
		t.Fatalf("validate: exit %d\n%s", code, out)
	}
	out, code := p.Run("workflows/check.workflow.yaml", "USER=alice", "PASSWORD=alice-pw")
	if code != 0 || !strings.Contains(out, `output OK = "true"`) || !strings.Contains(out, `output MAIL = "alice@example.org"`) {
		t.Fatalf("run: exit %d\n%s", code, out)
	}
	out, code = p.Run("workflows/check.workflow.yaml", "USER=alice", "PASSWORD=wrong")
	if code != 0 || !strings.Contains(out, `output OK = "false"`) {
		t.Fatalf("run with wrong password: exit %d\n%s", code, out)
	}
	if strings.Contains(out, ldaptest.AdminPassword) {
		t.Errorf("log shows the password of the connection:\n%s", out)
	}
}

func TestValues(t *testing.T) {
	var m map[string]Values
	if err := json.Unmarshal([]byte(`{"a":"x","b":["y","z"],"c":42,"d":null,"e":true}`), &m); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(m["a"], Values{"x"}) || !slices.Equal(m["b"], Values{"y", "z"}) || !slices.Equal(m["c"], Values{"42"}) || len(m["d"]) != 0 || !slices.Equal(m["e"], Values{"true"}) {
		t.Errorf("values = %v", m)
	}
	if err := json.Unmarshal([]byte(`{"a":{"x":1}}`), &m); err == nil {
		t.Error("object accepted")
	}
	guid := []byte{0xff, 0x19, 0x96, 0x6f, 0x86, 0x8b, 0x11, 0xd0, 0xb4, 0x2d, 0x00, 0xcf, 0x4f, 0xc9, 0x64, 0xff}
	if got := decodeValue("objectGUID", guid); got != "6f9619ff-8b86-d011-b42d-00cf4fc964ff" {
		t.Errorf("guid = %s", got)
	}
	sid := []byte{1, 2, 0, 0, 0, 0, 0, 5, 0x20, 0, 0, 0, 0x20, 2, 0, 0}
	if got := decodeValue("objectSid", sid); got != "S-1-5-32-544" {
		t.Errorf("sid = %s", got)
	}
	if got := decodeValue("objectSid", []byte{1, 5, 0xff}); got != "AQX/" {
		t.Errorf("short sid = %s", got)
	}
	if got := decodeValue("cn", []byte("Müller")); got != "Müller" {
		t.Errorf("text = %s", got)
	}
}

func FuzzFillFilter(f *testing.F) {
	f.Add("(&(uid={user})(cn=*))", "*)(uid=*")
	f.Add("(uid={x})", "\x00\\()")
	f.Fuzz(func(t *testing.T, filter, value string) {
		out, err := fillFilter(filter, map[string]string{"user": value, "x": value})
		if err != nil {
			return
		}
		if strings.Contains(filter, "{user}") && value != "" && strings.Contains(out, "{user}") {
			t.Fatalf("placeholder left in %q", out)
		}
	})
}
