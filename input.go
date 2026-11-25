package main

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"
	runnel "github.com/runnelhq/sdk-go"
)

// inputConfig is the configuration of the transform ldap.input.
type inputConfig struct {
	Connection   connection        `json:"connection" doc:"LDAP connection (a file in connections/)" schema:"required,connection=ldap"`
	BaseDN       string            `json:"baseDn" doc:"Where the search starts, e.g. OU=Users,DC=example,DC=com; empty: baseDn of the connection"`
	Filter       string            `json:"filter" doc:"LDAP filter, e.g. (&(objectClass=user)(department={dept})); {name} stands for the escaped value of name in filterValues" schema:"default=(objectClass=*)"`
	FilterValues map[string]string `json:"filterValues" doc:"Values for {name} in filter, escaped for LDAP, e.g. dept: ${DEPARTMENT}"`
	Scope        string            `json:"scope" doc:"sub: baseDn and all entries below it, one: only the entries directly below, base: only baseDn itself" schema:"enum=sub|one|base,default=sub"`
	Fields       []inputField      `json:"fields" doc:"Fields to read, with attribute and type; empty: dn and all attributes as text"`
	Separator    string            `json:"separator" doc:"Text between several values of an attribute in a field of type string" schema:"default=; "`
	PageSize     int               `json:"pageSize" doc:"Entries per page (paged results, so that Active Directory returns more than 1000 entries); 0: no paging" schema:"default=500"`
	SizeLimit    int               `json:"sizeLimit" doc:"Most entries to read; 0: all"`
}

type inputField struct {
	Name string `json:"name" doc:"Name of the field" schema:"required,example=mail"`
	From string `json:"from" doc:"Attribute to read, e.g. sAMAccountName, or dn for the DN of the entry; empty: the name of the field"`
	Type string `json:"type" doc:"Type of the field: string (several values joined with separator), int, bool (TRUE/FALSE), datetime (generalized time or Active Directory file time), binary, json (list of all values)" schema:"enum=string|int|bool|datetime|binary|json,default=string"`
}

func (f inputField) attribute() string {
	if f.From != "" {
		return f.From
	}
	return f.Name
}

func (f inputField) typ() string {
	if f.Type == "" {
		return runnel.TypeString
	}
	return f.Type
}

var inputTypes = []string{runnel.TypeString, runnel.TypeInt, runnel.TypeBool, runnel.TypeDatetime, runnel.TypeBinary, runnel.TypeJSON}

// batchSize is the most records per transform.emit.
const batchSize = 500

func addInput(p *runnel.Plugin) {
	// The category input stays: without it the editor offers a link into the input, whose
	// batches it never reads. The actions have no category and stand in the group of the
	// plugin ("Plugin: ldap").
	runnel.AddTransform(p, runnel.Transform[inputConfig]{
		Type: "ldap.input", Category: runnel.CategoryInput, Label: "LDAP Input",
		Description:  "Reads the entries of an LDAP search (Active Directory, OpenLDAP) as records",
		Example:      "type: ldap.input\nwith:\n  connection: ad\n  baseDn: OU=Users,DC=example,DC=com\n  filter: (&(objectClass=user)(objectCategory=person))\n  fields:\n    - { name: login, from: sAMAccountName }\n    - { name: mail }\n    - { name: groups, from: memberOf, type: json }\n    - { name: lastLogon, from: lastLogonTimestamp, type: datetime }\n",
		RecordErrors: true,
		Run:          readEntries,
		Init:         initInput,
		DetectFields: detectInput,
	})
}

func (c inputConfig) base() string {
	if c.BaseDN != "" {
		return c.BaseDN
	}
	return c.Connection.BaseDN
}

func (c inputConfig) attributes() []string {
	var out []string
	for _, f := range c.Fields {
		if a := f.attribute(); !strings.EqualFold(a, "dn") && !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	if len(c.Fields) > 0 && len(out) == 0 {
		return []string{"1.1"} // only the DN
	}
	return out
}

func (c inputConfig) check() (string, int, error) {
	if c.Filter == "" {
		c.Filter = "(objectClass=*)"
	}
	filter, err := fillFilter(c.Filter, c.FilterValues)
	if err != nil {
		return "", 0, err
	}
	scope, err := scopeOf(c.Scope)
	if err != nil {
		return "", 0, err
	}
	if c.PageSize < 0 || c.SizeLimit < 0 {
		return "", 0, fmt.Errorf("pageSize and sizeLimit must not be negative")
	}
	for i, f := range c.Fields {
		if !slices.Contains(inputTypes, f.typ()) {
			return "", 0, fmt.Errorf("fields[%d]: type %q must be one of %s", i, f.Type, strings.Join(inputTypes, ", "))
		}
	}
	return filter, scope, nil
}

// readEntries searches page by page and emits the entries as records; Emit waits while the
// pipeline behind is busy, so only a page is held at a time.
func readEntries(ctx context.Context, st *runnel.Stream, c inputConfig) error {
	filter, scope, err := c.check()
	if err != nil {
		return err
	}
	if c.Separator == "" {
		c.Separator = "; "
	}
	s, err := c.Connection.open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	st.Log.Debug("reading %s (%s) with %s", c.base(), c.Scope, filter)
	fields := runnel.Fields{}
	for _, f := range c.Fields {
		fields = append(fields, runnel.Field{Name: f.Name, Type: f.typ()})
	}
	read, serverLimit := 0, 0
	if c.SizeLimit > 0 && c.PageSize == 0 {
		serverLimit = c.SizeLimit
	}
	return s.searchPages(ctx, c.base(), scope, filter, c.attributes(), c.PageSize, serverLimit, func(page []*ldap.Entry) (bool, error) {
		if c.SizeLimit > 0 && read+len(page) > c.SizeLimit {
			page = page[:c.SizeLimit-read]
		}
		read += len(page)
		var err error
		if len(c.Fields) == 0 {
			err = emitAll(ctx, st, page, c.Separator)
		} else {
			err = emitFields(ctx, st, page, c, fields)
		}
		return c.SizeLimit > 0 && read >= c.SizeLimit, err
	})
}

// emitFields emits entries with the configured fields; a value that does not fit its type
// sends the record to the error link.
func emitFields(ctx context.Context, st *runnel.Stream, page []*ldap.Entry, c inputConfig, fields runnel.Fields) error {
	var rows, errs [][]any
	flush := func() error {
		if err := st.Emit(ctx, runnel.ToMain, fields, rows); err != nil {
			return err
		}
		rows = nil
		if err := st.Emit(ctx, runnel.ToError, runnel.ErrorFields(fields), errs); err != nil {
			return err
		}
		errs = nil
		return nil
	}
	for _, e := range page {
		row := make([]any, len(c.Fields))
		var bad, badField string
		for i, f := range c.Fields {
			v, err := fieldValue(e, f, c.Separator)
			if err != nil && bad == "" {
				bad, badField = err.Error(), f.Name
			}
			row[i] = v
		}
		if bad != "" {
			errs = append(errs, runnel.ErrorRow(row, bad, badField))
		} else {
			rows = append(rows, row)
		}
		if len(rows)+len(errs) >= batchSize {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	return flush()
}

// emitAll emits entries with dn and all their attributes as text; consecutive entries
// with the same attributes share a header.
func emitAll(ctx context.Context, st *runnel.Stream, page []*ldap.Entry, sep string) error {
	var fields runnel.Fields
	var rows [][]any
	for _, e := range page {
		fs := runnel.Fields{{Name: "dn", Type: runnel.TypeString}}
		row := []any{e.DN}
		for _, a := range e.Attributes {
			fs = append(fs, runnel.Field{Name: a.Name, Type: runnel.TypeString})
			row = append(row, strings.Join(decodeValues(a.Name, a.ByteValues), sep))
		}
		if !slices.Equal(fs, fields) || len(rows) >= batchSize {
			if err := st.Emit(ctx, runnel.ToMain, fields, rows); err != nil {
				return err
			}
			fields, rows = fs, nil
		}
		rows = append(rows, row)
	}
	return st.Emit(ctx, runnel.ToMain, fields, rows)
}

// fieldValue converts the values of an attribute to the type of the field; a missing
// attribute is null.
func fieldValue(e *ldap.Entry, f inputField, sep string) (any, error) {
	attr := f.attribute()
	if strings.EqualFold(attr, "dn") {
		return e.DN, nil
	}
	var raw [][]byte
	for _, a := range e.Attributes {
		if strings.EqualFold(a.Name, attr) {
			raw = a.ByteValues
		}
	}
	if len(raw) == 0 {
		return nil, nil
	}
	switch f.typ() {
	case runnel.TypeJSON:
		return decodeValues(attr, raw), nil
	case runnel.TypeBinary:
		return raw[0], nil
	case runnel.TypeString:
		return strings.Join(decodeValues(attr, raw), sep), nil
	}
	text := strings.TrimSpace(string(raw[0]))
	switch f.typ() {
	case runnel.TypeInt:
		n, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%q is not a whole number", text)
		}
		return n, nil
	case runnel.TypeBool:
		switch strings.ToUpper(text) {
		case "TRUE":
			return true, nil
		case "FALSE":
			return false, nil
		}
		return nil, fmt.Errorf("%q is not TRUE or FALSE", text)
	default: // datetime
		t, never, err := parseTime(text)
		if err != nil || never {
			return nil, err
		}
		return t.UTC().Format(time.RFC3339), nil
	}
}

var generalizedTime = regexp.MustCompile(`^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})?(\d{2})?(?:[.,]\d+)?(Z|[+-]\d{4})?$`)

// fileTimeEpoch is the start of Windows file times (100 ns since 1601-01-01).
var fileTimeEpoch = time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)

// parseTime reads an LDAP generalized time (20261124103000Z) or an Active Directory file
// time (lastLogonTimestamp, pwdLastSet, accountExpires); never is set for 0 and the
// largest value, which mean "never".
func parseTime(text string) (t time.Time, never bool, err error) {
	// A file time has 18 digits and no zone, which the pattern of generalized time does
	// not match.
	if m := generalizedTime.FindStringSubmatch(text); m != nil {
		layout := "2006010215"
		value := m[1] + m[2] + m[3] + m[4]
		if m[5] != "" {
			layout += "04"
			value += m[5]
		}
		if m[6] != "" {
			layout += "05"
			value += m[6]
		}
		zone := m[7]
		switch zone {
		case "", "Z":
			t, err = time.ParseInLocation(layout, value, time.UTC)
		default:
			t, err = time.Parse(layout+"-0700", value+zone)
		}
		if err != nil {
			return time.Time{}, false, fmt.Errorf("%q is not a date and time", text)
		}
		return t, false, nil
	}
	n, err := strconv.ParseInt(text, 10, 64)
	if err != nil || n < 0 {
		return time.Time{}, false, fmt.Errorf("%q is not a date and time", text)
	}
	if n == 0 || n == 1<<63-1 {
		return time.Time{}, true, nil
	}
	// Split, so that the multiplication does not overflow time.Duration.
	days := n / (864e9)
	return fileTimeEpoch.AddDate(0, 0, int(days)).Add(time.Duration(n%864e9) * 100), false, nil
}

// initInput checks the configuration and names the fields of the output; it does not
// connect.
func initInput(_ context.Context, _ runnel.InitInput, c inputConfig) runnel.InitResult {
	var res runnel.InitResult
	problem := func(path, msg string) { res.Problems = append(res.Problems, runnel.Problem{Path: path, Message: msg}) }
	if c.Filter != "" && !strings.Contains(c.Filter, "${") {
		if _, err := fillFilter(c.Filter, c.FilterValues); err != nil {
			problem("filter", err.Error())
		}
	}
	if c.Scope != "" && !strings.Contains(c.Scope, "${") {
		if _, err := scopeOf(c.Scope); err != nil {
			problem("scope", err.Error())
		}
	}
	if len(c.Fields) == 0 {
		res.Output = &runnel.RecordSchema{Fields: runnel.Fields{{Name: "dn", Type: runnel.TypeString}}, Open: true}
		return res
	}
	out := runnel.Fields{}
	for i, f := range c.Fields {
		switch {
		case f.Name == "":
			problem(fmt.Sprintf("fields[%d].name", i), "the field has no name")
			continue
		case out.Index(f.Name) >= 0:
			problem(fmt.Sprintf("fields[%d].name", i), fmt.Sprintf("field %q is listed twice", f.Name))
			continue
		case !slices.Contains(inputTypes, f.typ()):
			problem(fmt.Sprintf("fields[%d].type", i), fmt.Sprintf("type %q must be one of %s", f.Type, strings.Join(inputTypes, ", ")))
			continue
		}
		out = append(out, runnel.Field{Name: f.Name, Type: f.typ()})
	}
	res.Output = &runnel.RecordSchema{Fields: out}
	return res
}

// fileTimeAttributes hold Active Directory file times as numbers.
var fileTimeAttributes = []string{"accountexpires", "badpasswordtime", "lastlogoff", "lastlogon", "lastlogontimestamp", "pwdlastset", "lockouttime"}

// maxSamples is the number of first values shown per proposed field.
const maxSamples = 20

// detectInput reads the first entries and proposes a field per attribute.
func detectInput(ctx context.Context, c inputConfig, limit int) (runnel.Detection, error) {
	filter, scope, err := c.check()
	if err != nil {
		return runnel.Detection{}, err
	}
	s, err := c.Connection.open(ctx)
	if err != nil {
		return runnel.Detection{}, err
	}
	defer s.Close()
	var entries []*ldap.Entry
	pageSize := c.PageSize
	if pageSize > 0 {
		pageSize = min(pageSize, limit+1)
	}
	// All attributes, not only those in fields: Runnel compares them with fields and marks
	// the new ones.
	err = s.searchPages(ctx, c.base(), scope, filter, nil, pageSize, limit+1, func(page []*ldap.Entry) (bool, error) {
		entries = append(entries, page...)
		return len(entries) > limit, nil
	})
	if err != nil {
		return runnel.Detection{}, err
	}
	complete := len(entries) <= limit
	entries = entries[:min(len(entries), limit)]
	d := runnel.Detection{
		Source: []runnel.Fact{{Name: "Server", Value: c.Connection.URL}, {Name: "Base", Value: c.base()}, {Name: "Filter", Value: filter}},
		Rows:   len(entries), Complete: complete,
	}
	dn := runnel.DetectedField{Name: "dn", Type: runnel.TypeString}
	for _, e := range entries[:min(len(entries), maxSamples)] {
		dn.Values = append(dn.Values, e.DN)
	}
	d.Fields = append(d.Fields, dn)
	var order []string
	values := map[string][][][]byte{}
	for _, e := range entries {
		for _, a := range e.Attributes {
			if _, ok := values[a.Name]; !ok {
				order = append(order, a.Name)
			}
			values[a.Name] = append(values[a.Name], a.ByteValues)
		}
	}
	for _, name := range order {
		d.Fields = append(d.Fields, propose(name, values[name]))
	}
	return d, nil
}

// propose chooses the type of an attribute from its values.
func propose(name string, vals [][][]byte) runnel.DetectedField {
	f := runnel.DetectedField{Name: name, Type: runnel.TypeString}
	for _, v := range vals[:min(len(vals), maxSamples)] {
		f.Values = append(f.Values, strings.Join(decodeValues(name, v), "; "))
	}
	multi, ints, bools, times, binaryValues := false, true, true, true, false
	for _, v := range vals {
		multi = multi || len(v) > 1
		for _, b := range v {
			text := string(b)
			if !utf8.Valid(b) {
				binaryValues = true
			}
			if _, err := strconv.ParseInt(text, 10, 64); err != nil || (len(text) > 1 && text[0] == '0') {
				ints = false
			}
			if up := strings.ToUpper(text); up != "TRUE" && up != "FALSE" {
				bools = false
			}
			if m := generalizedTime.FindStringSubmatch(text); m == nil || m[7] == "" {
				times = false
			}
		}
	}
	lower := strings.ToLower(name)
	switch {
	case multi:
		f.Type, f.Note = runnel.TypeJSON, "several values per entry: a list (type string joins them with separator)"
	case slices.Contains(fileTimeAttributes, lower):
		f.Type, f.Note = runnel.TypeDatetime, "Active Directory file time"
	case binaryValues && lower != "objectguid" && lower != "objectsid":
		f.Type, f.Note = runnel.TypeBinary, "binary values"
	case times:
		f.Type = runnel.TypeDatetime
	case bools:
		f.Type = runnel.TypeBool
	case ints:
		f.Type = runnel.TypeInt
	}
	return f
}
