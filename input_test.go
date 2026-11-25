package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	runnel "github.com/runnelhq/sdk-go"
	"github.com/runnelhq/sdk-go/runneltest"

	"github.com/runnelhq/plugin-ldap/internal/ldaptest"
)

func TestInput(t *testing.T) {
	s := ldaptest.Start(t)
	c := runneltest.Start(t, newPlugin())
	anon, _, _ := conns(s)
	people := map[string]any{"connection": anon, "filter": "(objectClass=inetOrgPerson)", "pageSize": 1, "fields": []any{
		map[string]any{"name": "login", "from": "uid"},
		map[string]any{"name": "dn"},
		map[string]any{"name": "mail", "type": "json"},
		map[string]any{"name": "mails", "from": "mail"},
		map[string]any{"name": "number", "from": "employeeNumber", "type": "int"},
		map[string]any{"name": "created", "from": "createTimestamp", "type": "datetime"},
		map[string]any{"name": "photo", "from": "jpegPhoto", "type": "binary"},
	}}
	res, err := c.RunTransform("ldap.input", people)
	if err != nil || res.Error != "" {
		t.Fatal(err, res.Error)
	}
	recs := res.Records(runnel.ToMain)
	if len(recs) != 2 {
		t.Fatalf("records = %v", recs)
	}
	bob := recs[1]
	if recs[0]["login"] != "alice" || recs[0]["photo"] != "/9j/4AAQ" || bob["dn"] != "uid=bob,ou=people,dc=example,dc=org" || bob["number"] != 1002.0 ||
		bob["mails"] != "bob@example.org; robert@example.org" || len(bob["mail"].([]any)) != 2 || bob["photo"] != nil {
		t.Errorf("records = %v", recs)
	}
	if created, err := time.Parse(time.RFC3339, bob["created"].(string)); err != nil || time.Since(created) > time.Hour {
		t.Errorf("created = %v (%v)", bob["created"], err)
	}
	if f := res.Emits[0].Fields; f.Index("number") != 4 || f[4].Type != runnel.TypeInt || f[5].Type != runnel.TypeDatetime {
		t.Errorf("fields = %v", f)
	}

	// A value that does not fit its type goes to the error link.
	res, err = c.RunTransform("ldap.input", map[string]any{"connection": anon, "filter": "(uid=alice)", "fields": []any{
		map[string]any{"name": "uid"}, map[string]any{"name": "n", "from": "cn", "type": "int"},
	}})
	if err != nil || res.Error != "" {
		t.Fatal(err, res.Error)
	}
	errs := res.Records(runnel.ToError)
	if len(errs) != 1 || errs[0]["_error"] != `"Alice Doe" is not a whole number` || errs[0]["_errorField"] != "n" || errs[0]["uid"] != "alice" {
		t.Errorf("errors = %v", errs)
	}

	// Without fields: dn and all attributes as text; sizeLimit.
	res, err = c.RunTransform("ldap.input", map[string]any{"connection": anon, "baseDn": "ou=people," + ldaptest.Base, "scope": "one", "sizeLimit": 1})
	if err != nil || res.Error != "" {
		t.Fatal(err, res.Error)
	}
	recs = res.Records(runnel.ToMain)
	if len(recs) != 1 || !strings.HasPrefix(recs[0]["dn"].(string), "uid=") || recs[0]["cn"] == nil || recs[0]["mail"] == nil {
		t.Errorf("records = %v", recs)
	}

	res, err = c.RunTransform("ldap.input", map[string]any{"connection": anon, "filter": "(uid={who})"})
	if err != nil || res.Error != "filter uses {who}, which is not in filterValues" {
		t.Errorf("bad filter: %v %q", err, res.Error)
	}
	res, err = c.RunTransform("ldap.input", map[string]any{"connection": with(anon, "url", "ldap://127.0.0.1:1")})
	if err != nil || !strings.Contains(res.Error, "cannot connect to 127.0.0.1:1") {
		t.Errorf("no server: %v %q", err, res.Error)
	}
}

func TestInputInit(t *testing.T) {
	c := runneltest.Start(t, newPlugin())
	res, err := c.Init("ldap.input", map[string]any{"connection": "ad", "fields": []any{
		map[string]any{"name": "login", "from": "sAMAccountName"}, map[string]any{"name": "groups", "from": "memberOf", "type": "json"},
	}}, runnel.InitInput{})
	if err != nil || len(res.Problems) != 0 || res.Output == nil || res.Output.Open ||
		len(res.Output.Fields) != 2 || res.Output.Fields[1] != (runnel.Field{Name: "groups", Type: runnel.TypeJSON}) {
		t.Errorf("init = %+v, %v", res, err)
	}
	res, err = c.Init("ldap.input", map[string]any{"connection": "ad", "filter": "(uid=x", "scope": "all", "pageSize": "${PAGE}", "fields": []any{
		map[string]any{"name": "a"}, map[string]any{"name": "a"}, map[string]any{"name": "b", "type": "date"},
	}}, runnel.InitInput{})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range res.Problems {
		got = append(got, p.Path)
	}
	if strings.Join(got, " ") != "filter scope fields[1].name fields[2].type" || len(res.Output.Fields) != 1 {
		t.Errorf("problems = %+v", res.Problems)
	}
	res, err = c.Init("ldap.input", map[string]any{"connection": "ad"}, runnel.InitInput{})
	if err != nil || !res.Output.Open || res.Output.Fields[0].Name != "dn" {
		t.Errorf("init without fields = %+v, %v", res, err)
	}
}

func TestInputDetectFields(t *testing.T) {
	s := ldaptest.Start(t)
	c := runneltest.Start(t, newPlugin())
	anon, _, _ := conns(s)
	d, err := c.DetectFields("ldap.input", map[string]any{"connection": anon, "filter": "(objectClass=inetOrgPerson)"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	types := map[string]string{}
	for _, f := range d.Fields {
		types[f.Name] = f.Type
	}
	if d.Rows != 2 || !d.Complete || d.Fields[0].Name != "dn" || types["mail"] != "json" || types["employeeNumber"] != "int" ||
		types["jpegPhoto"] != "binary" || types["cn"] != "string" || d.Source[2].Value != "(objectClass=inetOrgPerson)" {
		t.Errorf("detection = %+v", d)
	}
	// With fields, still all attributes are proposed; Runnel marks the new ones.
	d, err = c.DetectFields("ldap.input", map[string]any{"connection": anon, "filter": "(objectClass=inetOrgPerson)", "fields": []any{map[string]any{"name": "uid"}}}, 1)
	if err != nil || d.Rows != 1 || d.Complete || len(d.Fields) < 5 {
		t.Errorf("detection with limit 1 = %+v, %v", d, err)
	}
}

func TestParseTime(t *testing.T) {
	tests := map[string]string{
		"20261124103000Z":    "2026-11-24T10:30:00Z",
		"20261124103000.0Z":  "2026-11-24T10:30:00Z",
		"202611241030+0100":  "2026-11-24T09:30:00Z",
		"2026112410Z":        "2026-11-24T10:00:00Z",
		"133779000000000000": "2024-12-05T19:20:00Z", // 1733426400 s after 1970
	}
	for in, want := range tests {
		got, never, err := parseTime(in)
		if err != nil || never || got.UTC().Format(time.RFC3339) != want {
			t.Errorf("parseTime(%s) = %v, %v, %v; want %s", in, got, never, err, want)
		}
	}
	for _, in := range []string{"0", "9223372036854775807"} {
		if _, never, err := parseTime(in); !never || err != nil {
			t.Errorf("parseTime(%s): never %v, %v", in, never, err)
		}
	}
	for _, in := range []string{"soon", "-5", "20261324103000Z"} {
		if _, _, err := parseTime(in); err == nil {
			t.Errorf("parseTime(%s) accepted", in)
		}
	}
}

// TestPipelineWithRunnel reads the people into a CSV file in a pipeline of Runnel (needs
// RUNNEL_BIN and slapd).
func TestPipelineWithRunnel(t *testing.T) {
	if os.Getenv(runneltest.RunnelEnv) == "" {
		t.Skip("RUNNEL_BIN is not set")
	}
	s := ldaptest.Start(t)
	p := runneltest.NewProject(t, ".", "plugin.yaml")
	p.WriteFile("connections/dir.yaml", "kind: Connection\napiVersion: runnel/v1\nname: dir\ntype: ldap\nwith:\n  url: "+s.TLSURL+"\n  caFile: "+s.CAFile+"\n  baseDn: dc=example,dc=org\n")
	p.WriteFile("pipelines/people.pipeline.yaml", `kind: Pipeline
apiVersion: runnel/v1
name: people
transforms:
  - id: read
    type: ldap.input
    with:
      connection: dir
      filter: (objectClass=inetOrgPerson)
      pageSize: 1
      fields:
        - { name: login, from: uid }
        - { name: number, from: employeeNumber, type: int }
        - { name: mails, from: mail }
  - id: write
    type: csv.output
    with:
      path: people.csv
      encoding: utf-8
      fields: [{ name: login }, { name: number }, { name: mails }]
links:
  - { from: read, to: write }
`)
	if out, code := p.Validate(); code != 0 {
		t.Fatalf("validate: exit %d\n%s", code, out)
	}
	if out, code := p.Run("pipelines/people.pipeline.yaml"); code != 0 {
		t.Fatalf("run: exit %d\n%s", code, out)
	}
	csv, _ := os.ReadFile(filepath.Join(p.Dir, "people.csv"))
	if got := strings.ReplaceAll(string(csv), "\r", ""); got != "login,number,mails\nalice,1001,alice@example.org\nbob,1002,bob@example.org; robert@example.org\n" {
		t.Errorf("people.csv:\n%s", got)
	}
	// init: a field that the next transform names, but ldap.input does not read.
	p.WriteFile("pipelines/people.pipeline.yaml", strings.Replace(readFile(t, filepath.Join(p.Dir, "pipelines", "people.pipeline.yaml")), "{ name: mails }]", "{ name: phone }]", 1))
	if out, code := p.Validate(); code == 0 || !strings.Contains(out, "phone") {
		t.Fatalf("validate with unknown field: exit %d\n%s", code, out)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func FuzzParseTime(f *testing.F) {
	for _, s := range []string{"20261124103000Z", "202611241030+0100", "133779000000000000", "0", "2026112410.5Z"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, never, err := parseTime(s)
		if err == nil && !never && got.IsZero() {
			t.Fatalf("parseTime(%q) gave the zero time", s)
		}
	})
}

// BenchmarkEntryToRow converts LDAP entries with five fields of different types to rows,
// the work of ldap.input per record (without the server).
func BenchmarkEntryToRow(b *testing.B) {
	e := ldap.NewEntry("uid=alice,ou=people,dc=example,dc=org", map[string][]string{
		"uid": {"alice"}, "mail": {"alice@example.org", "a@example.org"}, "employeeNumber": {"1001"},
		"pwdLastSet": {"133779000000000000"}, "isActive": {"TRUE"},
	})
	fields := []inputField{{Name: "uid"}, {Name: "mail", Type: "json"}, {Name: "employeeNumber", Type: "int"}, {Name: "pwdLastSet", Type: "datetime"}, {Name: "isActive", Type: "bool"}}
	b.ReportAllocs()
	for b.Loop() {
		for _, f := range fields {
			if _, err := fieldValue(e, f, "; "); err != nil {
				b.Fatal(err)
			}
		}
	}
}
