package main

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/runnelhq/sdk-go/runneltest"
)

// TestReference checks the reference of every type with the rules of Runnel.
func TestReference(t *testing.T) {
	runneltest.CheckReference(t, newPlugin())
}

// TestReferenceOutputs checks that the reference of each action names exactly the fields
// of its result struct (one level of lists below), so that both change together.
func TestReferenceOutputs(t *testing.T) {
	results := map[string]any{
		"ldap.search": searchOutput{}, "ldap.authenticate": authOutput{},
		"ldap.add": changeOutput{}, "ldap.modify": changeOutput{}, "ldap.delete": changeOutput{},
	}
	raw, err := runneltest.Start(t, newPlugin()).Call("describe", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Actions []struct {
			Type    string `json:"type"`
			Outputs []struct {
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"outputs"`
		} `json:"actions"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	if len(d.Actions) != len(results) {
		t.Fatalf("%d actions, %d result structs", len(d.Actions), len(results))
	}
	for _, a := range d.Actions {
		var got []string
		for _, o := range a.Outputs {
			got = append(got, o.Name+" "+o.Type)
		}
		want := outputsOf("output", reflect.TypeOf(results[a.Type]))
		if !slices.Equal(got, want) {
			t.Errorf("%s: outputs\n%v\nwant (from the result struct)\n%v", a.Type, got, want)
		}
	}
}

// outputsOf lists the paths and types of the fields of a result struct as expressions see
// them, with the fields of structs in lists after the list.
func outputsOf(prefix string, rt reflect.Type) []string {
	var out []string
	for f := range rt.Fields() {
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		path := prefix + "." + name
		switch f.Type.Kind() {
		case reflect.Bool:
			out = append(out, path+" boolean")
		case reflect.Int:
			out = append(out, path+" integer")
		case reflect.String:
			out = append(out, path+" string")
		case reflect.Map:
			out = append(out, path+" object")
		case reflect.Slice:
			out = append(out, path+" list")
			if f.Type.Elem().Kind() == reflect.Struct {
				out = append(out, outputsOf(path+"[]", f.Type.Elem())...)
			}
		default:
			out = append(out, path+" ?")
		}
	}
	return out
}
