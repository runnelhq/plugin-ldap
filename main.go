// Command ldap is the Runnel plugin "ldap": it searches, checks sign-ins and changes
// entries in LDAP directories such as Active Directory or OpenLDAP, and reads entries as
// records in pipelines (ldap.input). Runnel starts it; see
// README.md.
package main

import runnel "github.com/runnelhq/sdk-go"

// version must match version in plugin.yaml (checked by a test).
const version = "0.1.0"

func newPlugin() *runnel.Plugin {
	p := runnel.New("ldap", version)
	runnel.AddConnectionType(p, runnel.ConnectionType[connection]{
		Type:        "ldap",
		Label:       "LDAP",
		Description: "LDAP directory such as Active Directory or OpenLDAP",
		Test:        testConnection,
	})
	addActions(p)
	addInput(p)
	return p
}

func main() { newPlugin().Main() }
