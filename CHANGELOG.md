# Änderungen

## Unveröffentlicht (v0.1.0)

- Erste Version: Connection-Typ `ldap` (ldaps, StartTLS, eigene CA, Test im Editor), Actions `ldap.search` (Paged
  Results, maskierte Filterwerte, GUID/SID), `ldap.authenticate`, `ldap.add`, `ldap.modify`, `ldap.delete`.
- Transform `ldap.input`: Einträge seitenweise als Datensätze, Typen `string`, `int`, `bool`, `datetime` (auch
  Datei-Zeiten von Active Directory), `binary`, `json`, Fehler-Link; `transform.init` und „Detect fields“.
