package main

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/go-ldap/ldap/v3"
	runnel "github.com/runnelhq/sdk-go"
)

// maxEntries is the largest sizeLimit: the output of an action must fit into one message of
// the protocol (16 MiB).
const maxEntries = 100000

type searchConfig struct {
	Connection   connection        `json:"connection" doc:"LDAP connection (a file in connections/)" schema:"required,connection=ldap"`
	BaseDN       string            `json:"baseDn" doc:"Where the search starts, e.g. OU=Users,DC=example,DC=com; empty: baseDn of the connection"`
	Filter       string            `json:"filter" doc:"LDAP filter, e.g. (&(objectClass=user)(sAMAccountName={user})); {name} stands for the escaped value of name in filterValues" schema:"default=(objectClass=*)"`
	FilterValues map[string]string `json:"filterValues" doc:"Values for {name} in filter, escaped for LDAP, e.g. user: ${USER}; never write values from outside directly into filter"`
	Scope        string            `json:"scope" doc:"sub: baseDn and all entries below it, one: only the entries directly below, base: only baseDn itself" schema:"enum=sub|one|base,default=sub"`
	Attributes   []string          `json:"attributes" doc:"Attributes to read, e.g. [cn, mail, memberOf]; empty: all attributes of the entries"`
	SizeLimit    int               `json:"sizeLimit" doc:"Most entries the search may find; more fail the action (largest 100000)" schema:"default=1000"`
	PageSize     int               `json:"pageSize" doc:"Entries per page (paged results, so that Active Directory returns more than 1000 entries); 0: no paging" schema:"default=500"`
}

type entry struct {
	DN         string              `json:"dn"`
	Attributes map[string][]string `json:"attributes"`
}

type searchOutput struct {
	Entries []entry `json:"entries"`
	Count   int     `json:"count"`
}

type authConfig struct {
	Connection connection `json:"connection" doc:"LDAP connection whose user may search for users" schema:"required,connection=ldap"`
	Username   string     `json:"username" doc:"Name the user signs in with, e.g. jdoe or jdoe@example.com" schema:"required"`
	Password   string     `json:"password" doc:"Password of the user" schema:"required,format=runnel-secret"`
	BaseDN     string     `json:"baseDn" doc:"Where to search for the user; empty: baseDn of the connection"`
	UserFilter string     `json:"userFilter" doc:"Filter that finds exactly one user; {username} stands for the escaped user name" schema:"default=(|(uid={username})(sAMAccountName={username})(userPrincipalName={username}))"`
	Attributes []string   `json:"attributes" doc:"Attributes of the user to return after a successful sign-in, e.g. [displayName, mail, memberOf]"`
}

type authOutput struct {
	Authenticated bool                `json:"authenticated"`
	DN            string              `json:"dn"`
	Attributes    map[string][]string `json:"attributes"`
	Error         string              `json:"error"`
}

type addConfig struct {
	Connection connection        `json:"connection" doc:"LDAP connection with permission to add entries" schema:"required,connection=ldap"`
	DN         string            `json:"dn" doc:"DN of the new entry, e.g. uid=jdoe,ou=people,dc=example,dc=org" schema:"required"`
	Attributes map[string]Values `json:"attributes" doc:"Attributes of the new entry with their values, including objectClass" schema:"required"`
}

type modifyConfig struct {
	Connection connection        `json:"connection" doc:"LDAP connection with permission to change entries" schema:"required,connection=ldap"`
	DN         string            `json:"dn" doc:"DN of the entry to change" schema:"required"`
	Replace    map[string]Values `json:"replace" doc:"Attributes to set to the given values; an empty list removes the attribute"`
	Add        map[string]Values `json:"add" doc:"Values to add to attributes"`
	Delete     map[string]Values `json:"delete" doc:"Values to remove from attributes; an empty list removes all values of the attribute"`
}

type deleteConfig struct {
	Connection    connection `json:"connection" doc:"LDAP connection with permission to delete entries" schema:"required,connection=ldap"`
	DN            string     `json:"dn" doc:"DN of the entry to delete; entries below it must be deleted first" schema:"required"`
	IgnoreMissing bool       `json:"ignoreMissing" doc:"Succeed if the entry does not exist (deleted is then false)"`
}

type changeOutput struct {
	DN      string `json:"dn"`
	Changed bool   `json:"changed"`
}

func addActions(p *runnel.Plugin) {
	runnel.AddAction(p, runnel.Action[searchConfig]{
		Type: "ldap.search", Category: runnel.CategoryNetwork, Label: "Search LDAP",
		Description: "Searches a directory (LDAP, Active Directory) and returns the entries with their attributes",
		Example:     "type: ldap.search\nwith:\n  connection: ad\n  filter: (&(objectClass=user)(sAMAccountName={user}))\n  filterValues:\n    user: ${USER}\n  attributes: [displayName, mail, memberOf]\n",
		Run:         search,
	})
	runnel.AddAction(p, runnel.Action[authConfig]{
		Type: "ldap.authenticate", Category: runnel.CategoryNetwork, Label: "Check LDAP sign-in",
		Description: "Checks user name and password against the directory: finds the user and signs in as it",
		Example:     "type: ldap.authenticate\nwith:\n  connection: ad\n  username: ${USER}\n  password: ${PASSWORD}\n  attributes: [memberOf]\n",
		Run:         authenticate,
	})
	runnel.AddAction(p, runnel.Action[addConfig]{
		Type: "ldap.add", Category: runnel.CategoryNetwork, Label: "Add LDAP entry",
		Description: "Adds an entry to the directory",
		Example:     "type: ldap.add\nwith:\n  connection: ldap\n  dn: uid=jdoe,ou=people,dc=example,dc=org\n  attributes:\n    objectClass: [inetOrgPerson]\n    cn: Jane Doe\n    sn: Doe\n",
		Run:         add,
	})
	runnel.AddAction(p, runnel.Action[modifyConfig]{
		Type: "ldap.modify", Category: runnel.CategoryNetwork, Label: "Change LDAP entry",
		Description: "Changes attributes of an entry: replaces, adds or removes values",
		Example:     "type: ldap.modify\nwith:\n  connection: ad\n  dn: ${USER_DN}\n  replace:\n    telephoneNumber: ${PHONE}\n",
		Run:         modify,
	})
	runnel.AddAction(p, runnel.Action[deleteConfig]{
		Type: "ldap.delete", Category: runnel.CategoryNetwork, Label: "Delete LDAP entry",
		Description: "Deletes an entry of the directory",
		Example:     "type: ldap.delete\nwith:\n  connection: ldap\n  dn: uid=jdoe,ou=people,dc=example,dc=org\n  ignoreMissing: true\n",
		Run:         remove,
	})
}

var placeholder = regexp.MustCompile(`\{([A-Za-z_][A-Za-z0-9_-]*)\}`)

// fillFilter replaces {name} by the escaped value; an unknown name is an error, so that a
// typo does not search for the literal text.
func fillFilter(filter string, values map[string]string) (string, error) {
	var missing string
	out := placeholder.ReplaceAllStringFunc(filter, func(m string) string {
		name := m[1 : len(m)-1]
		v, ok := values[name]
		if !ok {
			if missing == "" {
				missing = name
			}
			return m
		}
		return ldap.EscapeFilter(v)
	})
	if missing != "" {
		return "", fmt.Errorf("filter uses {%s}, which is not in filterValues", missing)
	}
	if _, err := ldap.CompileFilter(out); err != nil {
		return "", fmt.Errorf("invalid filter %q: %s", out, strings.TrimPrefix(err.Error(), "LDAP Result Code 201 \"Filter Compile Error\": "))
	}
	return out, nil
}

func scopeOf(s string) (int, error) {
	switch s {
	case "", "sub":
		return ldap.ScopeWholeSubtree, nil
	case "one":
		return ldap.ScopeSingleLevel, nil
	case "base":
		return ldap.ScopeBaseObject, nil
	}
	return 0, fmt.Errorf("scope %q must be sub, one or base", s)
}

func search(ctx context.Context, call *runnel.Call, c searchConfig) (any, error) {
	if c.Filter == "" {
		c.Filter = "(objectClass=*)"
	}
	filter, err := fillFilter(c.Filter, c.FilterValues)
	if err != nil {
		return nil, err
	}
	scope, err := scopeOf(c.Scope)
	if err != nil {
		return nil, err
	}
	switch {
	case c.SizeLimit == 0:
		c.SizeLimit = 1000
	case c.SizeLimit < 0 || c.SizeLimit > maxEntries:
		return nil, fmt.Errorf("sizeLimit must be between 1 and %d", maxEntries)
	}
	if c.PageSize < 0 {
		return nil, errors.New("pageSize must not be negative")
	}
	base := c.BaseDN
	if base == "" {
		base = c.Connection.BaseDN
	}
	s, err := c.Connection.open(ctx)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	call.Log.Debug("searching %s (%s) with %s", base, c.Scope, filter)
	entries, err := s.searchAll(ctx, base, scope, filter, c.Attributes, c.SizeLimit, c.PageSize)
	if err != nil {
		return nil, err
	}
	return searchOutput{Entries: entries, Count: len(entries)}, nil
}

// searchAll reads all entries, page by page, and fails once there are more than limit.
func (s *session) searchAll(ctx context.Context, base string, scope int, filter string, attrs []string, limit, pageSize int) ([]entry, error) {
	entries := []entry{}
	tooMany := &tooManyError{limit}
	serverLimit := 0
	if pageSize == 0 {
		serverLimit = limit + 1
	}
	err := s.searchPages(ctx, base, scope, filter, attrs, pageSize, serverLimit, func(page []*ldap.Entry) (bool, error) {
		for _, e := range page {
			if len(entries) == limit {
				return true, tooMany
			}
			entries = append(entries, entryOf(e))
		}
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	return entries, nil
}

// searchPages searches with paged results (pageSize > 0) and passes each page to fn until
// fn stops or the search ends. serverLimit is the size limit sent to the server (0: none);
// reaching it ends the search without error, after the entries the server sent.
func (s *session) searchPages(ctx context.Context, base string, scope int, filter string, attrs []string, pageSize, serverLimit int, fn func([]*ldap.Entry) (bool, error)) error {
	req := ldap.NewSearchRequest(base, scope, ldap.NeverDerefAliases, serverLimit, 0, false, filter, attrs, nil)
	var paging *ldap.ControlPaging
	if pageSize > 0 {
		paging = ldap.NewControlPaging(uint32(min(pageSize, maxEntries))) //nolint:gosec // bounded above
		req.Controls = []ldap.Control{paging}
	}
	for {
		res, err := s.Search(req)
		if res != nil {
			if stop, ferr := fn(res.Entries); ferr != nil || stop {
				return ferr
			}
		}
		if err != nil {
			if serverLimit > 0 && ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
				return nil
			}
			return fmt.Errorf("search in %q: %w", base, explain(ctx, err))
		}
		if paging == nil {
			return nil
		}
		ctrl, _ := ldap.FindControl(res.Controls, ldap.ControlTypePaging).(*ldap.ControlPaging)
		if ctrl == nil || len(ctrl.Cookie) == 0 {
			return nil
		}
		paging.SetCookie(ctrl.Cookie)
	}
}

type tooManyError struct{ limit int }

func (e *tooManyError) Error() string {
	return fmt.Sprintf("the search finds more than %d entries (sizeLimit); narrow the filter or raise sizeLimit", e.limit)
}

func entryOf(e *ldap.Entry) entry {
	out := entry{DN: e.DN, Attributes: make(map[string][]string, len(e.Attributes))}
	for _, a := range e.Attributes {
		out.Attributes[a.Name] = decodeValues(a.Name, a.ByteValues)
	}
	return out
}

const invalidLogin = "invalid user or password"

func authenticate(ctx context.Context, call *runnel.Call, c authConfig) (any, error) {
	if strings.TrimSpace(c.Username) == "" {
		return nil, errors.New("username is empty")
	}
	if c.UserFilter == "" {
		c.UserFilter = "(|(uid={username})(sAMAccountName={username})(userPrincipalName={username}))"
	}
	filter, err := fillFilter(c.UserFilter, map[string]string{"username": c.Username})
	if err != nil {
		return nil, fmt.Errorf("userFilter: %w", err)
	}
	base := c.BaseDN
	if base == "" {
		base = c.Connection.BaseDN
	}
	s, err := c.Connection.open(ctx)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	attrs := c.Attributes
	if len(attrs) == 0 {
		attrs = []string{"1.1"} // no attributes, only the DN
	}
	found, err := s.searchAll(ctx, base, ldap.ScopeWholeSubtree, filter, attrs, 1, 0)
	if _, ok := errors.AsType[*tooManyError](err); ok {
		return nil, errors.New("userFilter finds several users; make it unique")
	}
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		call.Log.Debug("no user %q found under %s", c.Username, base)
		return authOutput{Error: invalidLogin}, nil
	}
	user := found[0]
	// A connection of its own, so the sign-in of the user does not replace the one of the
	// connection.
	us, err := c.Connection.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer us.Close()
	if err := us.bind(ctx, user.DN, c.Password); err != nil {
		if errors.Is(err, errEmptyPassword) || errors.Is(err, errInvalidCredentials) {
			call.Log.Debug("sign-in of %s refused", user.DN)
			return authOutput{DN: user.DN, Error: invalidLogin}, nil
		}
		return nil, fmt.Errorf("sign-in as %s: %w", user.DN, err)
	}
	return authOutput{Authenticated: true, DN: user.DN, Attributes: user.Attributes}, nil
}

func add(ctx context.Context, call *runnel.Call, c addConfig) (any, error) {
	if len(c.Attributes) == 0 {
		return nil, errors.New("attributes is empty; a new entry needs at least objectClass")
	}
	s, err := c.Connection.open(ctx)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	req := ldap.NewAddRequest(c.DN, nil)
	for _, name := range sortedKeys(c.Attributes) {
		req.Attribute(name, c.Attributes[name])
	}
	if err := s.Add(req); err != nil {
		return nil, fmt.Errorf("add %s: %w", c.DN, explain(ctx, err))
	}
	call.Log.Info("added %s", c.DN)
	return changeOutput{DN: c.DN, Changed: true}, nil
}

func modify(ctx context.Context, call *runnel.Call, c modifyConfig) (any, error) {
	if len(c.Replace)+len(c.Add)+len(c.Delete) == 0 {
		return nil, errors.New("nothing to change: give replace, add or delete")
	}
	s, err := c.Connection.open(ctx)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	req := ldap.NewModifyRequest(c.DN, nil)
	for _, name := range sortedKeys(c.Delete) {
		req.Delete(name, c.Delete[name])
	}
	for _, name := range sortedKeys(c.Add) {
		req.Add(name, c.Add[name])
	}
	for _, name := range sortedKeys(c.Replace) {
		req.Replace(name, c.Replace[name])
	}
	if err := s.Modify(req); err != nil {
		return nil, fmt.Errorf("change %s: %w", c.DN, explain(ctx, err))
	}
	call.Log.Info("changed %s", c.DN)
	return changeOutput{DN: c.DN, Changed: true}, nil
}

func remove(ctx context.Context, call *runnel.Call, c deleteConfig) (any, error) {
	s, err := c.Connection.open(ctx)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if err := s.Del(ldap.NewDelRequest(c.DN, nil)); err != nil {
		if c.IgnoreMissing && ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			call.Log.Debug("%s does not exist", c.DN)
			return changeOutput{DN: c.DN}, nil
		}
		return nil, fmt.Errorf("delete %s: %w", c.DN, explain(ctx, err))
	}
	call.Log.Info("deleted %s", c.DN)
	return changeOutput{DN: c.DN, Changed: true}, nil
}
